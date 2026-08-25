//! Memory-ledger launch-grant nonce store with the same single-use semantics
//! as the SQLite adapter, driven by the deterministic simulation clock.

use super::MemoryLedger;
use crate::launch_grant::{
    classify_stored_nonce, LaunchGrantNonceRecord, LaunchGrantNonceStore, NonceConsumption,
    StoredLaunchGrantNonce,
};
use crate::store::LedgerError;
use bullet_domain::{AttemptId, DomainError};

impl LaunchGrantNonceStore for MemoryLedger {
    fn record_launch_grant_nonce(
        &mut self,
        record: &LaunchGrantNonceRecord,
    ) -> Result<(), LedgerError> {
        record.validate()?;
        self.tick()?;
        if self.launch_grant_nonces.contains_key(&record.grant_nonce)
            || self
                .launch_grant_nonces
                .values()
                .any(|stored| stored.record.grant_id == record.grant_id)
        {
            return Err(DomainError::Conflict(format!(
                "launch grant {} nonce already persisted",
                record.grant_id
            ))
            .into());
        }
        self.launch_grant_nonces.insert(
            record.grant_nonce.clone(),
            StoredLaunchGrantNonce {
                record: record.clone(),
                consumed_at: None,
            },
        );
        Ok(())
    }

    fn consume_launch_grant_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &AttemptId,
    ) -> Result<NonceConsumption, LedgerError> {
        self.tick()?;
        let now_unix_ms = u64::try_from(self.simulation_clock_millis)
            .map_err(|_| LedgerError::Store("simulation clock precedes the epoch".into()))?;
        let outcome =
            classify_stored_nonce(self.launch_grant_nonces.get(nonce), attempt_id, now_unix_ms);
        if outcome == NonceConsumption::Consumed {
            let consumed_at = self.simulation_time();
            if let Some(stored) = self.launch_grant_nonces.get_mut(nonce) {
                stored.consumed_at = Some(consumed_at);
            }
        }
        Ok(outcome)
    }

    fn get_launch_grant_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<StoredLaunchGrantNonce>, LedgerError> {
        Ok(self.launch_grant_nonces.get(nonce).cloned())
    }
}
