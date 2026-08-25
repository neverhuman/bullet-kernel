//! Durable single-use nonce port. Every ledger persists the nonces it mints
//! and consumes each one exactly once with its own authoritative clock.

use crate::store::LedgerError;
use bullet_domain::AttemptId;
use bullet_harness_core::launch_grant::{is_lower_hex_64, LaunchGrantNonceLedger};
use bullet_harness_core::HarnessError;
use serde::{Deserialize, Serialize};

pub use bullet_harness_core::launch_grant::NonceConsumption;

/// One minted nonce as persisted by the issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchGrantNonceRecord {
    /// Single-use 64-hex nonce.
    pub grant_nonce: String,
    /// Grant identifier the nonce belongs to.
    pub grant_id: String,
    /// Attempt the grant binds.
    pub attempt_id: AttemptId,
    /// Fence of that Attempt at mint time.
    pub attempt_fence: u64,
    /// Exclusive expiry of the grant window.
    pub expires_at_unix_ms: u64,
    /// Mint time (RFC 3339 UTC, caller clock; informational only).
    pub issued_at: String,
}

impl LaunchGrantNonceRecord {
    /// Validate the persisted shape.
    ///
    /// # Errors
    ///
    /// Store error for a malformed record.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if !is_lower_hex_64(&self.grant_nonce)
            || !is_lower_hex_64(&self.grant_id)
            || self.attempt_fence == 0
            || self.expires_at_unix_ms == 0
            || self.issued_at.is_empty()
        {
            return Err(LedgerError::Store(
                "launch grant nonce record is malformed".into(),
            ));
        }
        Ok(())
    }
}

/// A persisted nonce plus its consumption state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredLaunchGrantNonce {
    /// The minted record.
    pub record: LaunchGrantNonceRecord,
    /// Store time at which the nonce was spent, if ever.
    pub consumed_at: Option<String>,
}

/// Ledger-side nonce persistence. Each store uses its own clock for expiry.
pub trait LaunchGrantNonceStore {
    /// Persist a freshly minted nonce. A duplicate nonce or grant id is a
    /// typed `Conflict`.
    ///
    /// # Errors
    /// Conflict or store failure.
    fn record_launch_grant_nonce(
        &mut self,
        record: &LaunchGrantNonceRecord,
    ) -> Result<(), LedgerError>;

    /// Spend one nonce for `attempt_id` exactly once at the store's current
    /// time. Never errors for replay, expiry, or unknown nonces; those are
    /// typed outcomes.
    ///
    /// # Errors
    /// Store failure only.
    fn consume_launch_grant_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &AttemptId,
    ) -> Result<NonceConsumption, LedgerError>;

    /// Inspect one persisted nonce without changing it.
    ///
    /// # Errors
    /// Store failure.
    fn get_launch_grant_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<StoredLaunchGrantNonce>, LedgerError>;
}

/// Adapt a ledger nonce store to the harness-core verification callback.
pub struct StoreNonceLedger<'a, S: LaunchGrantNonceStore>(pub &'a mut S);

impl<S: LaunchGrantNonceStore> LaunchGrantNonceLedger for StoreNonceLedger<'_, S> {
    fn consume_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        _now_unix_ms: u64,
    ) -> Result<NonceConsumption, HarnessError> {
        let attempt_id = AttemptId::parse(attempt_id).map_err(|error| HarnessError::Io {
            context: "launch grant nonce attempt id".into(),
            reason: error.to_string(),
        })?;
        self.0
            .consume_launch_grant_nonce(nonce, &attempt_id)
            .map_err(|error| HarnessError::Io {
                context: "launch grant nonce store".into(),
                reason: error.to_string(),
            })
    }
}

/// Classify a stored nonce against the store's current time without mutating.
#[must_use]
pub fn classify_stored_nonce(
    stored: Option<&StoredLaunchGrantNonce>,
    attempt_id: &AttemptId,
    now_unix_ms: u64,
) -> NonceConsumption {
    match stored {
        None => NonceConsumption::Unknown,
        Some(stored) if stored.record.attempt_id != *attempt_id => NonceConsumption::Unknown,
        Some(stored) if stored.consumed_at.is_some() => NonceConsumption::Replayed,
        Some(stored) if now_unix_ms >= stored.record.expires_at_unix_ms => {
            NonceConsumption::Expired
        }
        Some(_) => NonceConsumption::Consumed,
    }
}
