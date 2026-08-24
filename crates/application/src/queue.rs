//! Ready queue. A package is ready only when its machine says so.

use crate::commands::CommandRequest;
use crate::graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
use crate::leases::LeaseService;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Attempt, AuthorityToken, MissionId, WorkPackage, WorkPackageState};
use serde::{Deserialize, Serialize};

/// One dispatchable package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyItem {
    /// Mission.
    pub mission_id: MissionId,
    /// Package.
    pub package: WorkPackage,
}

/// Packages in `Ready` with no live writer.
///
/// # Errors
///
/// Returns a store error when a graph cannot be loaded.
pub fn ready_queue<L: Ledger>(ledger: &L) -> Result<Vec<ReadyItem>, LedgerError> {
    let mut out = Vec::new();
    for mission in ledger.list_missions()? {
        let Some(graph) = ledger.get_graph(&mission.id)? else {
            continue;
        };
        for package in graph.packages {
            if package.state != WorkPackageState::Ready {
                continue;
            }
            if ledger.active_attempt(&package.id)?.is_some() {
                continue;
            }
            out.push(ReadyItem {
                mission_id: mission.id.clone(),
                package,
            });
        }
    }
    Ok(out)
}

/// Claim the first ready package. Same seed is idempotent.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn claim_ready<L: Ledger>(
    ledger: &mut L,
    seed: &str,
) -> Result<Option<(Attempt, AuthorityToken)>, LedgerError> {
    let request = CommandRequest::new(format!("claim:{seed}"), "claim_ready", &seed);
    ledger.record_command(&request)?;
    let attempt_id = bullet_domain::AttemptId::from_seed(seed);
    if let Some(existing) = ledger.get_attempt(&attempt_id)? {
        return Ok(Some((
            existing.clone(),
            reconstruct_token(ledger, &existing, seed)?,
        )));
    }
    let Some(item) = ready_queue(ledger)?.into_iter().next() else {
        return Ok(None);
    };
    let graph = ledger
        .get_graph(&item.mission_id)?
        .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
    let variant_index = graph
        .variants
        .iter()
        .position(|variant| variant.work_package_id == item.package.id)
        .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
    let (attempt, token) = LeaseService::open_attempt(ledger, &graph, variant_index, seed)?;
    let delta = GraphDelta {
        parent: graph_digest(&graph),
        ops: vec![GraphOp::SetPackageState {
            id: item.package.id,
            from: WorkPackageState::Ready,
            to: WorkPackageState::Running,
        }],
    };
    apply_graph_delta(ledger, &item.mission_id, &delta)?;
    Ok(Some((attempt, token)))
}

fn reconstruct_token<L: Ledger>(
    ledger: &L,
    attempt: &Attempt,
    seed: &str,
) -> Result<AuthorityToken, LedgerError> {
    for mission in ledger.list_missions()? {
        if let Some(graph) = ledger.get_graph(&mission.id)? {
            if let Some(index) = graph
                .variants
                .iter()
                .position(|variant| variant.id == attempt.variant_id)
            {
                return Ok(LeaseService::token_for(&graph, index, attempt, seed));
            }
        }
    }
    Err(LedgerError::Store("attempt graph missing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::{materialize_plan, PlanInput};
    use crate::memory::MemoryLedger;
    use bullet_domain::TaskClass;

    #[test]
    fn ready_then_claim_is_idempotent() {
        let mut ledger = MemoryLedger::new();
        materialize_plan(
            &mut ledger,
            "q",
            &PlanInput {
                title: "t".into(),
                objective: "o".into(),
                packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
            },
        )
        .expect("plan");
        assert_eq!(ready_queue(&ledger).expect("q").len(), 1);
        let first = claim_ready(&mut ledger, "claim-1")
            .expect("claim")
            .expect("item");
        assert!(ready_queue(&ledger).expect("q").is_empty());
        let second = claim_ready(&mut ledger, "claim-1")
            .expect("replay")
            .expect("item");
        assert_eq!(first.0.id, second.0.id);
    }
}
