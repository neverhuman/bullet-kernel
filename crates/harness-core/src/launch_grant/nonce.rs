//! Single-use nonce port consumed at admission. The issuer persists every
//! minted nonce with its Attempt and expiry; verification consumes it exactly
//! once. Replay is refused even when every other check passes.

use crate::error::HarnessError;
use std::collections::BTreeMap;

/// Outcome of one nonce consumption attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceConsumption {
    /// The nonce existed, matched the Attempt, was unexpired, and is now spent.
    Consumed,
    /// The nonce was already spent.
    Replayed,
    /// The nonce was never persisted by this issuer or names another Attempt.
    Unknown,
    /// The nonce existed but its persisted expiry has passed.
    Expired,
}

/// Durable single-use nonce store seen from the verifier.
pub trait LaunchGrantNonceLedger {
    /// Consume `nonce` for `attempt_id` at `now_unix_ms`, exactly once.
    ///
    /// # Errors
    ///
    /// Store failure; the verifier treats any error as refusal.
    fn consume_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, HarnessError>;
}

#[derive(Clone, Debug)]
struct MemoryNonceRecord {
    attempt_id: String,
    expires_at_unix_ms: u64,
    consumed: bool,
}

/// In-process nonce ledger for tests and offline tooling. Not durable.
#[derive(Clone, Debug, Default)]
pub struct MemoryNonceLedger {
    records: BTreeMap<String, MemoryNonceRecord>,
}

impl MemoryNonceLedger {
    /// Empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly minted nonce. Returns `false` when it already exists.
    pub fn register(&mut self, nonce: &str, attempt_id: &str, expires_at_unix_ms: u64) -> bool {
        if self.records.contains_key(nonce) {
            return false;
        }
        self.records.insert(
            nonce.to_string(),
            MemoryNonceRecord {
                attempt_id: attempt_id.to_string(),
                expires_at_unix_ms,
                consumed: false,
            },
        );
        true
    }

    /// Whether `nonce` has been spent.
    #[must_use]
    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.records
            .get(nonce)
            .is_some_and(|record| record.consumed)
    }
}

impl LaunchGrantNonceLedger for MemoryNonceLedger {
    fn consume_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, HarnessError> {
        let Some(record) = self.records.get_mut(nonce) else {
            return Ok(NonceConsumption::Unknown);
        };
        if record.attempt_id != attempt_id {
            return Ok(NonceConsumption::Unknown);
        }
        if record.consumed {
            return Ok(NonceConsumption::Replayed);
        }
        if now_unix_ms >= record.expires_at_unix_ms {
            return Ok(NonceConsumption::Expired);
        }
        record.consumed = true;
        Ok(NonceConsumption::Consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_ledger_consumes_exactly_once() {
        let mut ledger = MemoryNonceLedger::new();
        assert!(ledger.register("n", "atm", 10));
        assert!(!ledger.register("n", "atm", 10));
        assert_eq!(
            ledger.consume_nonce("n", "other", 1).unwrap(),
            NonceConsumption::Unknown
        );
        assert_eq!(
            ledger.consume_nonce("n", "atm", 1).unwrap(),
            NonceConsumption::Consumed
        );
        assert_eq!(
            ledger.consume_nonce("n", "atm", 1).unwrap(),
            NonceConsumption::Replayed
        );
        assert!(ledger.register("late", "atm", 10));
        assert_eq!(
            ledger.consume_nonce("late", "atm", 10).unwrap(),
            NonceConsumption::Expired
        );
        assert_eq!(
            ledger.consume_nonce("missing", "atm", 1).unwrap(),
            NonceConsumption::Unknown
        );
    }
}
