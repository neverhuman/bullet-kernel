//! Versioned runner journal records. Structured checkpoints are
//! authoritative; log lines are not.

use serde::{Deserialize, Serialize};

/// Wire version. Bump only when the schema changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Durable runner checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Protocol version that wrote this file.
    pub protocol: u32,
    /// Session id.
    pub session: String,
    /// Monotonic journal sequence.
    pub seq: u64,
    /// Last accepted command.
    pub last_command: String,
    /// Attempt bound to this session, if any.
    pub attempt_id: Option<String>,
}
