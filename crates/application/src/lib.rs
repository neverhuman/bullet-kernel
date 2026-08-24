//! Application services: commands, materializer, leases, demo.

pub mod commands;
pub mod demo;
pub mod leases;
pub mod materializer;
pub mod memory;
pub mod store;

pub use commands::{CommandRecord, CommandRequest};
pub use demo::{run_demo, DemoReceipt};
pub use leases::LeaseService;
pub use materializer::{materialize_plan, PlanInput};
pub use memory::MemoryLedger;
pub use store::{Ledger, LedgerError, StoredGraph};
