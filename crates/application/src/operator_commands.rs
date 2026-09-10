//! Authenticated operator ownership and bounded command recovery.
use crate::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::CommandId;
use std::fmt;

mod projection;
pub use projection::validate_projection;

/// A validated command and watermark from the same committed snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorCommandSnapshot {
    /// Current durable command phase and exact result.
    pub command: CommandRecord,
    /// Latest event covered by the same snapshot.
    pub as_of_sequence: u64,
}

/// One bounded discovery page; historical commands without ownership are absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorCommandPage {
    /// Current records in ascending immutable submission sequence.
    pub commands: Vec<CommandRecord>,
    /// Last returned submission sequence when another row exists.
    pub next_after: Option<u64>,
    /// Latest event covered by all rows in this page.
    pub as_of_sequence: u64,
}

/// Ownership and query refusals, without revealing another operator's command.
#[derive(Debug)]
pub enum OperatorCommandError {
    /// Owner is malformed or not admitted, or cursor/limit is invalid.
    InvalidRequest,
    /// A globally existing key has no owner or belongs to another operator.
    OwnershipConflict,
    /// Invalid request or corrupt durable state; original reason is retained.
    Store(LedgerError),
}
impl OperatorCommandError {
    /// Stable public refusal reason.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "OPERATOR_COMMAND_REQUEST_INVALID",
            Self::OwnershipConflict => "COMMAND_OWNERSHIP_CONFLICT",
            Self::Store(error) => error.reason_code(),
        }
    }
}
impl fmt::Display for OperatorCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}
impl std::error::Error for OperatorCommandError {}
impl From<LedgerError> for OperatorCommandError {
    fn from(error: LedgerError) -> Self {
        Self::Store(error)
    }
}

/// Every method reads current persisted ownership; no client cache is authority.
pub trait OperatorCommandStore {
    /// Atomically admit a new command with owner/outbox/audit/admission effects.
    /// Exact retry returns its current validated phase without fresh admission.
    /// # Errors
    /// Invalid owner/request, changed key subject, ownership conflict or store failure.
    fn submit_operator_command(
        &mut self,
        operator: &str,
        request: &CommandRequest,
    ) -> Result<OperatorCommandSnapshot, OperatorCommandError>;

    /// Read one owned command and its complete correlated projection atomically.
    /// Unowned or foreign records return no subject and are never adopted.
    /// # Errors
    /// Invalid owner or inconsistent persisted command/projection.
    fn get_operator_command(
        &self,
        operator: &str,
        command: &CommandId,
    ) -> Result<Option<OperatorCommandSnapshot>, OperatorCommandError>;

    /// Read an ascending submission-sequence page with limit in 1..=100.
    /// All phase/outbox/audit/claim rows and the watermark share one snapshot.
    /// # Errors
    /// Invalid owner/cursor/limit or inconsistent persisted projection.
    fn list_operator_commands(
        &self,
        operator: &str,
        after: u64,
        limit: u32,
    ) -> Result<OperatorCommandPage, OperatorCommandError>;
}
