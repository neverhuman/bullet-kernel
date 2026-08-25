//! Generic durable nonce issue/consume port.
//!
//! Issuance and consumption are deliberately separate. A read or verification
//! path can observe a nonce, but it can never register one implicitly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// One issued nonce and its domain-separated request digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuedNonce {
    /// Full 256-bit lowercase nonce key.
    pub key: String,
    /// Full 256-bit domain-separated request digest.
    pub digest: String,
}

impl IssuedNonce {
    /// Validate and construct one nonce record.
    ///
    /// # Errors
    ///
    /// `NONCE_INVALID` when either field is not exactly 64 lowercase hex
    /// characters.
    pub fn validated(key: &str, digest: &str) -> Result<Self, NonceError> {
        validate_hex_64(key, "nonce key")?;
        validate_hex_64(digest, "nonce digest")?;
        Ok(Self {
            key: key.to_owned(),
            digest: digest.to_owned(),
        })
    }

    /// Validate a lookup key without inventing a record.
    ///
    /// # Errors
    ///
    /// `NONCE_INVALID` when `key` is not exactly 64 lowercase hex characters.
    pub fn validate_key(key: &str) -> Result<(), NonceError> {
        validate_hex_64(key, "nonce key")
    }
}

/// Explicit durable state of a known nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NonceState {
    /// Issued and available for exactly one matching consume.
    Issued,
    /// Already consumed; it can never authorize again.
    Consumed,
}

/// Fail-closed nonce errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum NonceError {
    /// Caller input is not the exact admitted shape.
    #[error("invalid nonce: {0}")]
    Invalid(String),
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
    /// Persisted nonce truth is malformed or internally inconsistent.
    #[error("corrupt persisted nonce: {0}")]
    Corrupt(String),
    /// Durable store is unavailable or refused the operation.
    #[error("nonce store failed: {0}")]
    StoreFailure(String),
}

impl NonceError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "NONCE_INVALID",
            Self::AlreadyIssued(_) => "NONCE_ALREADY_ISSUED",
            Self::NotFound(_) => "NONCE_NOT_FOUND",
            Self::Consumed(_) => "NONCE_CONSUMED",
            Self::SubjectMismatch(_) => "NONCE_SUBJECT_MISMATCH",
            Self::Corrupt(_) => "NONCE_CORRUPT",
            Self::StoreFailure(_) => "NONCE_STORE_FAILURE",
        }
    }
}

/// Issue and consume as separate operations.
pub trait NonceLedger {
    /// Record a nonce without consuming it.
    ///
    /// # Errors
    ///
    /// Invalid input, prior issuance, subject reuse, corruption, or store
    /// failure.
    fn issue(&mut self, key: &str, digest: &str) -> Result<IssuedNonce, NonceError>;

    /// Consume a previously issued nonce exactly once.
    ///
    /// # Errors
    ///
    /// Invalid input, missing/consumed nonce, subject mismatch, corruption, or
    /// store failure.
    fn consume(&mut self, key: &str, digest: &str) -> Result<(), NonceError>;

    /// Observe a nonce without mutating or registering it. `None` is an
    /// explicit unknown nonce, distinct from both states and from store error.
    ///
    /// # Errors
    ///
    /// Invalid input, corrupt persisted truth, or store failure.
    fn state(&self, key: &str) -> Result<Option<NonceState>, NonceError>;
}

/// Process-local reference implementation for unit tests and simulators.
#[derive(Default)]
pub struct MemoryNonceLedger {
    rows: BTreeMap<String, (IssuedNonce, NonceState)>,
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
        let issued = IssuedNonce::validated(key, digest)?;
        if let Some((existing, state)) = self.rows.get(key) {
            if *state == NonceState::Consumed {
                return Err(NonceError::Consumed(key.into()));
            }
            if existing.digest == digest {
                return Err(NonceError::AlreadyIssued(key.into()));
            }
            return Err(NonceError::SubjectMismatch(key.into()));
        }
        self.rows
            .insert(key.to_owned(), (issued.clone(), NonceState::Issued));
        Ok(issued)
    }

    fn consume(&mut self, key: &str, digest: &str) -> Result<(), NonceError> {
        let requested = IssuedNonce::validated(key, digest)?;
        let (issued, state) = self
            .rows
            .get_mut(key)
            .ok_or_else(|| NonceError::NotFound(key.into()))?;
        if *state == NonceState::Consumed {
            return Err(NonceError::Consumed(key.into()));
        }
        if issued.digest != requested.digest {
            return Err(NonceError::SubjectMismatch(key.into()));
        }
        *state = NonceState::Consumed;
        Ok(())
    }

    fn state(&self, key: &str) -> Result<Option<NonceState>, NonceError> {
        IssuedNonce::validate_key(key)?;
        Ok(self.rows.get(key).map(|(_, state)| *state))
    }
}

fn validate_hex_64(value: &str, name: &str) -> Result<(), NonceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(NonceError::Invalid(format!(
        "{name} must contain 64 lowercase hexadecimal characters"
    )))
}
