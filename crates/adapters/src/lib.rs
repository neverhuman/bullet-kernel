//! Durable adapters. Domain rules do not live here.

pub mod authority_high_water;
pub mod simulators;
pub mod sqlite;

#[cfg(test)]
mod test_support;

pub use authority_high_water::{
    AuthorityHighWaterError, AuthorityHighWaterStore, AuthorityHighWaterV1,
    AUTHORITY_HIGH_WATER_SCHEMA_VERSION,
};
pub use simulators::{ProviderSimulator, ScmSimulator};
pub use sqlite::{
    create_backup, restore_backup, BackupReceipt, RestoreReceipt, SqliteLedger,
    SqliteMaintenanceError,
};
