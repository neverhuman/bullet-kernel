//! Application services: commands, materializer, leases, queue, demo.

pub mod authority;
pub mod commands;
pub mod conformance;
pub mod conformance_effects;
pub mod demo;
pub mod effect_state;
pub mod effects;
pub mod graph_delta;
pub mod leases;
pub mod materializer;
pub mod memory;
pub mod queue;
pub mod records;
pub mod simulators;
pub mod store;

pub use authority::{check_active_lease_snapshot, ActiveLeaseSubject};
pub use commands::{CommandRecord, CommandRequest};
pub use demo::{derive_receipt, run_demo, DemoReceipt};
pub use effect_state::EffectState;
pub use effects::{receipt_id, EffectIntentRecord, EffectReceiptRecord, ReceiptVerdict, ZERO_OID};
pub use graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
pub use leases::LeaseService;
pub use materializer::{materialize_plan, PlanInput};
pub use memory::MemoryLedger;
pub use queue::{claim_ready, ready_queue, ReadyItem};
pub use records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReadyRow, ReleaseRequest, StoredGraph,
};
pub use simulators::{ProviderSimulator, ScmSimulator, SimulatedInvocation};
pub use store::{Ledger, LedgerError};
