//! Application services: commands, materializer, leases, demo.

pub mod commands;
pub mod demo;
pub mod graph_delta;
pub mod leases;
pub mod materializer;
pub mod memory;
pub mod queue;
pub mod store;

pub use commands::{CommandRecord, CommandRequest};
pub use demo::{run_demo, DemoReceipt};
pub use graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
pub use leases::LeaseService;
pub use materializer::{materialize_plan, PlanInput};
pub use memory::MemoryLedger;
pub use queue::{claim_ready, ready_queue, ReadyItem};
pub use store::{Ledger, LedgerError, LedgerEvent, StoredGraph};
