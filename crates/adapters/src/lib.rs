//! Durable adapters. Domain rules do not live here.

pub mod simulators;
pub mod sqlite;

pub use simulators::{ProviderSimulator, ScmSimulator};
pub use sqlite::SqliteLedger;
