//! Durable nonce issue/consume. Verification never registers a nonce.
//! This in-memory store is the port. SQLite persistence waits on the
//! adapters/migration claim (0012 is already lease-transport).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Issued but not yet consumed nonce.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuedNonce {
    /// Caller-chosen idempotency key.
    pub key: String,
    /// Domain-separated request digest.
    pub digest: String,
}

/// Fail-closed nonce errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum NonceError {
    /// Key already issued and not consumed.
    #[error("nonce already issued: {0}")]
    AlreadyIssued(String),
    /// Consume of an unknown key.
    #[error("nonce not found: {0}")]
    NotFound(String),
    /// Replay or second consume.
    #[error("nonce already consumed: {0}")]
    Consumed(String),
    /// Digest mismatch.
    #[error("nonce subject mismatch: {0}")]
    SubjectMismatch(String),
}

impl NonceError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::AlreadyIssued(_) => "NONCE_ALREADY_ISSUED",
            Self::NotFound(_) => "NONCE_NOT_FOUND",
            Self::Consumed(_) => "NONCE_CONSUMED",
            Self::SubjectMismatch(_) => "NONCE_SUBJECT_MISMATCH",
        }
    }
}

/// Issue and consume as separate operations.
pub trait NonceLedger {
    /// Record a nonce. Does not consume it.
    ///
    /// # Errors
    ///
    /// Already issued, or subject reuse.
    fn issue(&mut self, key: &str, digest: &str) -> Result<IssuedNonce, NonceError>;

    /// Consume a previously issued nonce. Replay is refused.
    ///
    /// # Errors
    ///
    /// Missing, consumed, or mismatched digest.
    fn consume(&mut self, key: &str, digest: &str) -> Result<(), NonceError>;

    /// Read-only check. Must not mutate.
    fn is_consumed(&self, key: &str) -> bool;
}

/// Process-local nonce ledger.
#[derive(Default)]
pub struct MemoryNonceLedger {
    issued: BTreeMap<String, IssuedNonce>,
    consumed: BTreeSet<String>,
}

impl MemoryNonceLedger {
    /// Empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceLedger for MemoryNonceLedger {
    fn issue(&mut self, key: &str, digest: &str) -> Result<IssuedNonce, NonceError> {
        if self.consumed.contains(key) {
            return Err(NonceError::Consumed(key.into()));
        }
        if let Some(existing) = self.issued.get(key) {
            if existing.digest == digest {
                return Err(NonceError::AlreadyIssued(key.into()));
            }
            return Err(NonceError::SubjectMismatch(key.into()));
        }
        let issued = IssuedNonce {
            key: key.into(),
            digest: digest.into(),
        };
        self.issued.insert(key.into(), issued.clone());
        Ok(issued)
    }

    fn consume(&mut self, key: &str, digest: &str) -> Result<(), NonceError> {
        if self.consumed.contains(key) {
            return Err(NonceError::Consumed(key.into()));
        }
        let issued = self
            .issued
            .get(key)
            .ok_or_else(|| NonceError::NotFound(key.into()))?;
        if issued.digest != digest {
            return Err(NonceError::SubjectMismatch(key.into()));
        }
        self.consumed.insert(key.into());
        Ok(())
    }

    fn is_consumed(&self, key: &str) -> bool {
        self.consumed.contains(key)
    }
}
