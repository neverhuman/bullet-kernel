//! Versioned runner protocol. Structured events are authoritative.

use serde::{Deserialize, Serialize};

/// Wire version. Bump only when the schema changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Dispatch a session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchRequest {
    /// Session id.
    pub session: String,
}

/// Heartbeat from a live session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Session id.
    pub session: String,
}

/// Resume from the last checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SalvageRequest {
    /// Session id.
    pub session: String,
}

/// Stop a session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminateRequest {
    /// Session id.
    pub session: String,
}

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
