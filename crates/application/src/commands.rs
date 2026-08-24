//! Durable, idempotent commands. Success is not printed before the postcondition.

use bullet_domain::{CommandId, CommandPhase, Digest, DomainError};
use serde::{Deserialize, Serialize};

const COMMAND_DIGEST_DOMAIN: &[u8] = b"bullet-kernel.command-request.v1";
const MAX_COMMAND_KEY_BYTES: usize = 256;
const MAX_COMMAND_KIND_BYTES: usize = 64;
const MAX_COMMAND_JSON_BYTES: usize = 1024 * 1024;

/// Inbound command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Command kind.
    pub kind: String,
    /// Exact JSON payload bytes.
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
        Self::from_json(key, kind, payload)
    }

    /// Build a request from already encoded compact JSON.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when identity text or JSON is not admitted.
    pub fn from_json(
        key: impl Into<String>,
        kind: impl Into<String>,
        payload: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let request = Self {
            idempotency_key: key.into(),
            kind: kind.into(),
            payload: payload.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Domain-separated digest of the command kind and exact payload bytes.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut framed = Vec::with_capacity(
            COMMAND_DIGEST_DOMAIN.len() + self.kind.len() + self.payload.len() + 24,
        );
        frame(&mut framed, COMMAND_DIGEST_DOMAIN);
        frame(&mut framed, self.kind.as_bytes());
        frame(&mut framed, self.payload.as_bytes());
        Digest::of(&framed)
    }

    /// Deterministic local command identity used until the immutable wire
    /// contract is published and consumed.
    #[must_use]
    pub fn id(&self) -> CommandId {
        CommandId::from_seed(&self.idempotency_key)
    }

    /// Validate bounded identifiers and exact JSON syntax.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` for empty, oversized, control-bearing, or malformed
    /// command input.
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_text(
            "idempotency key",
            &self.idempotency_key,
            MAX_COMMAND_KEY_BYTES,
            false,
        )?;
        validate_text("command kind", &self.kind, MAX_COMMAND_KIND_BYTES, true)?;
        validate_json("command payload", &self.payload)?;
        Ok(())
    }

    /// Require an existing record to be the exact same request.
    ///
    /// # Errors
    ///
    /// Returns `Idempotency` when any request-bound field differs.
    pub fn matches(&self, record: &CommandRecord) -> Result<(), DomainError> {
        self.validate()?;
        record.validate()?;
        if record.id != self.id()
            || record.idempotency_key != self.idempotency_key
            || record.kind != self.kind
            || record.payload != self.payload
            || record.payload_digest != self.digest()
        {
            return Err(DomainError::Idempotency(self.idempotency_key.clone()));
        }
        Ok(())
    }
}

impl CommandRecord {
    /// Validate persisted identity, request digest, JSON, and result shape.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when durable command truth is malformed.
    pub fn validate(&self) -> Result<(), DomainError> {
        let request = CommandRequest {
            idempotency_key: self.idempotency_key.clone(),
            kind: self.kind.clone(),
            payload: self.payload.clone(),
        };
        request.validate()?;
        if self.id != request.id() {
            return Err(DomainError::Encoding(
                "command id does not match its idempotency key".into(),
            ));
        }
        if self.payload_digest != request.digest() {
            return Err(DomainError::Encoding(
                "command request digest does not match its kind and payload".into(),
            ));
        }
        match (self.phase, self.response.as_deref()) {
            (CommandPhase::Pending, Some(_)) => {
                return Err(DomainError::Encoding(
                    "pending command has a stored result".into(),
                ));
            }
            (CommandPhase::Applied | CommandPhase::Verified | CommandPhase::Failed, None) => {
                return Err(DomainError::Encoding(format!(
                    "{} command has no stored result",
                    self.phase.as_str()
                )));
            }
            (_, Some(response)) => validate_json("command result", response)?,
            (_, None) => {}
        }
        Ok(())
    }
}

fn frame(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}

fn validate_text(field: &str, value: &str, maximum: usize, token: bool) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(DomainError::Encoding(format!(
            "{field} must contain 1..={maximum} non-control bytes"
        )));
    }
    if token
        && !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(DomainError::Encoding(format!(
            "{field} must be a lowercase ASCII token"
        )));
    }
    Ok(())
}

fn validate_json(field: &str, value: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > MAX_COMMAND_JSON_BYTES {
        return Err(DomainError::Encoding(format!(
            "{field} must contain 1..={MAX_COMMAND_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_str::<serde_json::Value>(value)
        .map(|_| ())
        .map_err(|error| DomainError::Encoding(format!("{field}: {error}")))
}
