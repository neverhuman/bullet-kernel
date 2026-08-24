//! Deterministic monotonic authority clock for the memory ledger.

use super::MemoryLedger;
use crate::store::LedgerError;

impl MemoryLedger {
    /// Current deterministic simulation time in fixed-width RFC 3339 UTC.
    #[must_use]
    pub fn simulation_time(&self) -> String {
        Self::format_simulation_time(self.simulation_clock_millis)
    }

    /// Advance the deterministic clock monotonically without sleeping.
    ///
    /// # Errors
    ///
    /// Store failure when the requested advance exceeds the clock range.
    pub fn advance_simulation_time(&mut self, seconds: u64) -> Result<(), LedgerError> {
        let millis = i64::try_from(seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .and_then(|millis| self.simulation_clock_millis.checked_add(millis))
            .ok_or_else(|| LedgerError::Store("simulation clock overflow".into()))?;
        if chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis).is_none() {
            return Err(LedgerError::Store("simulation clock out of range".into()));
        }
        self.simulation_clock_millis = millis;
        Ok(())
    }

    pub(super) fn lease_window(&self, ttl_seconds: i64) -> Result<(String, String), LedgerError> {
        let expiry = ttl_seconds
            .checked_mul(1_000)
            .and_then(|millis| self.simulation_clock_millis.checked_add(millis))
            .ok_or_else(|| LedgerError::Store("lease expiry overflow".into()))?;
        Ok((self.simulation_time(), Self::format_simulation_time(expiry)))
    }

    fn format_simulation_time(millis: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
            .expect("validated simulation clock")
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}
