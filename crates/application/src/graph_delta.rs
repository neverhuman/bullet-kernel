//! Atomic, content-addressed graph mutations.

use crate::commands::CommandRequest;
use crate::store::{Ledger, LedgerError, StoredGraph};
use bullet_domain::{Digest, DomainError, MissionId, VariantId, WorkPackageId, WorkPackageState};
use serde::{Deserialize, Serialize};

/// One graph mutation. Applied all-or-nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GraphOp {
    /// Legal work-package transition.
    SetPackageState {
        /// Package.
        id: WorkPackageId,
        /// Expected current state.
        from: WorkPackageState,
        /// Requested next state.
        to: WorkPackageState,
    },
    /// Permanent fence increment. `to` must be `from + 1`.
    BumpFence {
        /// Variant.
        variant_id: VariantId,
        /// Expected current fence.
        from: u64,
        /// Next fence.
        to: u64,
    },
}

/// Content-addressed delta against a stored graph parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphDelta {
    /// Digest of the graph this delta was computed against.
    pub parent: Digest,
    /// Ordered ops.
    pub ops: Vec<GraphOp>,
}

impl GraphDelta {
    /// Canonical digest of this delta.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let body = serde_json::to_vec(self).unwrap_or_default();
        Digest::of(&body)
    }
}

/// Stable digest of a stored graph (ids, states, fences).
#[must_use]
pub fn graph_digest(graph: &StoredGraph) -> Digest {
    let mut buf = String::new();
    buf.push_str(&graph.mission.id.to_string());
    buf.push('\n');
    buf.push_str(&graph.plan.canonical_hash.to_hex());
    buf.push('\n');
    for pkg in &graph.packages {
        buf.push_str(&format!("{}:{:?}\n", pkg.id, pkg.state));
    }
    for variant in &graph.variants {
        buf.push_str(&format!("{}:{}\n", variant.id, variant.fence_counter));
    }
    Digest::of(buf.as_bytes())
}

/// Apply `delta` atomically. Replay of an already-applied delta is a no-op.
///
/// # Errors
///
/// Returns conflict when the parent digest does not match and the ops are not
/// already present.
pub fn apply_graph_delta<L: Ledger>(
    ledger: &mut L,
    mission: &MissionId,
    delta: &GraphDelta,
) -> Result<StoredGraph, LedgerError> {
    let request = CommandRequest::new(
        format!("delta:{}", delta.digest().to_hex()),
        "apply_graph_delta",
        delta,
    );
    ledger.record_command(&request)?;
    let graph = ledger
        .get_graph(mission)?
        .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
    if already_applied(&graph, delta) {
        return Ok(graph);
    }
    if graph_digest(&graph) != delta.parent {
        return Err(DomainError::Conflict("parent digest mismatch".into()).into());
    }
    let mut next = graph;
    for op in &delta.ops {
        apply_op(&mut next, op)?;
    }
    ledger.put_graph(&next)?;
    ledger.append_event("graph_delta", &delta.digest().to_hex())?;
    Ok(next)
}

fn apply_op(graph: &mut StoredGraph, op: &GraphOp) -> Result<(), LedgerError> {
    match op {
        GraphOp::SetPackageState { id, from, to } => {
            let pkg = graph
                .packages
                .iter_mut()
                .find(|pkg| pkg.id == *id)
                .ok_or_else(|| LedgerError::Store("package missing".into()))?;
            if pkg.state != *from {
                return Err(DomainError::Conflict(format!(
                    "package {} is {:?} not {:?}",
                    id, pkg.state, from
                ))
                .into());
            }
            pkg.state = pkg.state.transition(*to)?;
        }
        GraphOp::BumpFence {
            variant_id,
            from,
            to,
        } => {
            if *to != from.saturating_add(1) {
                return Err(DomainError::Fence(format!("{from} -> {to}")).into());
            }
            let variant = graph
                .variants
                .iter_mut()
                .find(|variant| variant.id == *variant_id)
                .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
            if variant.fence_counter != *from {
                return Err(DomainError::Fence(format!(
                    "variant fence is {} not {from}",
                    variant.fence_counter
                ))
                .into());
            }
            variant.fence_counter = *to;
        }
    }
    Ok(())
}

fn already_applied(graph: &StoredGraph, delta: &GraphDelta) -> bool {
    delta.ops.iter().all(|op| match op {
        GraphOp::SetPackageState { id, to, .. } => graph
            .packages
            .iter()
            .any(|pkg| pkg.id == *id && pkg.state == *to),
        GraphOp::BumpFence { variant_id, to, .. } => graph
            .variants
            .iter()
            .any(|variant| variant.id == *variant_id && variant.fence_counter == *to),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::{materialize_plan, PlanInput};
    use crate::memory::MemoryLedger;
    use bullet_domain::TaskClass;

    #[test]
    fn delta_is_atomic_and_idempotent() {
        let mut ledger = MemoryLedger::new();
        let graph = materialize_plan(
            &mut ledger,
            "delta-seed",
            &PlanInput {
                title: "d".into(),
                objective: "o".into(),
                packages: vec![("p".into(), TaskClass::BoundedBugFix)],
            },
        )
        .expect("plan");
        let pkg = graph.packages[0].clone();
        let delta = GraphDelta {
            parent: graph_digest(&graph),
            ops: vec![GraphOp::SetPackageState {
                id: pkg.id.clone(),
                from: WorkPackageState::Ready,
                to: WorkPackageState::Running,
            }],
        };
        let first = apply_graph_delta(&mut ledger, &graph.mission.id, &delta).expect("apply");
        assert_eq!(first.packages[0].state, WorkPackageState::Running);
        let second = apply_graph_delta(&mut ledger, &graph.mission.id, &delta).expect("replay");
        assert_eq!(second.packages[0].state, WorkPackageState::Running);
        let stale = GraphDelta {
            parent: graph_digest(&graph),
            ops: vec![GraphOp::SetPackageState {
                id: pkg.id,
                from: WorkPackageState::Ready,
                to: WorkPackageState::Rejected,
            }],
        };
        let err = apply_graph_delta(&mut ledger, &graph.mission.id, &stale).expect_err("conflict");
        assert!(matches!(err, LedgerError::Domain(DomainError::Conflict(_))));
    }
}
