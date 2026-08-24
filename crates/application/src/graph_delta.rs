//! Atomic, content-addressed graph mutations.

use crate::commands::CommandRequest;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Digest, DomainError, MissionId, VariantId, WorkPackageId, WorkPackageState};
use serde::{Deserialize, Serialize};

/// Durable result stored with an applied or refused graph-delta command.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphDeltaCommandResult {
    /// The graph transition and its audit event committed.
    Applied {
        /// Exact graph immediately after this delta.
        graph: Box<StoredGraph>,
    },
    /// The request was validly admitted but its graph transition was refused.
    Failed {
        /// Exact typed failure returned on replay.
        error: GraphDeltaFailure,
    },
}

/// Serializable form of every current ledger/domain error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphDeltaFailure {
    /// Durable store or logical lookup failure.
    Store { message: String },
    /// Persisted pre-1.0 schema is not supported by this binary.
    UnsupportedSchema { detail: String },
    /// Invalid identifier.
    InvalidId { message: String },
    /// Invalid state transition.
    InvalidTransition { from: String, to: String },
    /// Lease TTL outside the admitted interval.
    InvalidLeaseTtl { ttl_seconds: i64 },
    /// Stale authority.
    StaleAuthority { message: String },
    /// Fence invariant failure.
    Fence { message: String },
    /// Idempotency conflict.
    Idempotency { message: String },
    /// Encoding failure.
    Encoding { message: String },
    /// Graph conflict.
    Conflict { message: String },
    /// Unknown persisted state.
    UnknownState { message: String },
}

impl GraphDeltaFailure {
    /// Preserve an error for durable replay.
    #[must_use]
    pub fn from_error(error: &LedgerError) -> Self {
        match error {
            LedgerError::Store(message) => Self::Store {
                message: message.clone(),
            },
            LedgerError::UnsupportedSchema { detail } => Self::UnsupportedSchema {
                detail: detail.clone(),
            },
            LedgerError::Domain(error) => match error {
                DomainError::InvalidId(message) => Self::InvalidId {
                    message: message.clone(),
                },
                DomainError::InvalidTransition { from, to } => Self::InvalidTransition {
                    from: from.clone(),
                    to: to.clone(),
                },
                DomainError::InvalidLeaseTtl(ttl_seconds) => Self::InvalidLeaseTtl {
                    ttl_seconds: *ttl_seconds,
                },
                DomainError::StaleAuthority(message) => Self::StaleAuthority {
                    message: message.clone(),
                },
                DomainError::Fence(message) => Self::Fence {
                    message: message.clone(),
                },
                DomainError::Idempotency(message) => Self::Idempotency {
                    message: message.clone(),
                },
                DomainError::Encoding(message) => Self::Encoding {
                    message: message.clone(),
                },
                DomainError::Conflict(message) => Self::Conflict {
                    message: message.clone(),
                },
                DomainError::UnknownState(message) => Self::UnknownState {
                    message: message.clone(),
                },
            },
        }
    }

    /// Recreate the exact typed error for an idempotent replay.
    #[must_use]
    pub fn into_error(self) -> LedgerError {
        match self {
            Self::Store { message } => LedgerError::Store(message),
            Self::UnsupportedSchema { detail } => LedgerError::UnsupportedSchema { detail },
            Self::InvalidId { message } => DomainError::InvalidId(message).into(),
            Self::InvalidTransition { from, to } => {
                DomainError::InvalidTransition { from, to }.into()
            }
            Self::InvalidLeaseTtl { ttl_seconds } => {
                DomainError::InvalidLeaseTtl(ttl_seconds).into()
            }
            Self::StaleAuthority { message } => DomainError::StaleAuthority(message).into(),
            Self::Fence { message } => DomainError::Fence(message).into(),
            Self::Idempotency { message } => DomainError::Idempotency(message).into(),
            Self::Encoding { message } => DomainError::Encoding(message).into(),
            Self::Conflict { message } => DomainError::Conflict(message).into(),
            Self::UnknownState { message } => DomainError::UnknownState(message).into(),
        }
    }
}

impl GraphDeltaCommandResult {
    /// Serialize an applied receipt.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn applied(graph: &StoredGraph) -> Result<String, LedgerError> {
        serde_json::to_string(&Self::Applied {
            graph: Box::new(graph.clone()),
        })
        .map_err(|error| LedgerError::Store(error.to_string()))
    }

    /// Serialize a failed receipt.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn failed(error: &LedgerError) -> Result<String, LedgerError> {
        serde_json::to_string(&Self::Failed {
            error: GraphDeltaFailure::from_error(error),
        })
        .map_err(|error| LedgerError::Store(error.to_string()))
    }

    /// Decode a stored result, failing closed on corrupt data.
    ///
    /// # Errors
    /// Invalid stored JSON.
    pub fn decode(value: &str) -> Result<Self, LedgerError> {
        serde_json::from_str(value).map_err(|error| LedgerError::Store(error.to_string()))
    }
}

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
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when the delta cannot be serialized.
    pub fn digest(&self) -> Result<Digest, DomainError> {
        Digest::of_json(self)
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
    let key = format!("delta:{}", delta.digest()?.to_hex());
    let request = CommandRequest::new(&key, "apply_graph_delta", delta)?;
    ledger.apply_graph_delta_command(&request, mission, delta)
}

/// Evaluate a delta against one transactionally loaded graph snapshot.
/// Ledger adapters call this inside their transaction boundary.
///
/// # Errors
/// A stale parent, missing subject, illegal transition, or fence violation.
pub fn evaluate_graph_delta(
    graph: &StoredGraph,
    delta: &GraphDelta,
) -> Result<StoredGraph, LedgerError> {
    if already_applied(graph, delta) {
        return Ok(graph.clone());
    }
    if graph_digest(graph) != delta.parent {
        return Err(DomainError::Conflict("parent digest mismatch".into()).into());
    }
    let mut next = graph.clone();
    for op in &delta.ops {
        apply_op(&mut next, op)?;
    }
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
