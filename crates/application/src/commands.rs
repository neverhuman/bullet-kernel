//! Durable, idempotent commands. Success is not printed before the postcondition.

use bullet_domain::{CommandId, CommandPhase, Digest, DomainError};
use serde::{Deserialize, Serialize};

/// Inbound command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Command kind.
    pub kind: String,
    /// Canonical JSON payload.
    pub payload: String,
}

/// Recorded command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// Durable id.
    pub id: CommandId,
    /// Idempotency key.
    pub idempotency_key: String,
    /// Kind.
    pub kind: String,
    /// Payload.
    pub payload: String,
    /// Payload digest.
    pub payload_digest: Digest,
    /// Phase. UI must show pending until verified.
    pub phase: CommandPhase,
    /// Stored result for idempotent replay.
    pub response: Option<String>,
}

impl CommandRequest {
    /// Build a request from a serializable payload.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when the payload cannot be serialized.
    pub fn new(
        key: impl Into<String>,
        kind: impl Into<String>,
        payload: &impl Serialize,
    ) -> Result<Self, DomainError> {
        let payload =
            serde_json::to_string(payload).map_err(|err| DomainError::Encoding(err.to_string()))?;
        Ok(Self {
            idempotency_key: key.into(),
            kind: kind.into(),
            payload,
        })
    }

    /// Digest of the payload bytes.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::of(self.payload.as_bytes())
    }
}
