//! Expiry reclamation for the memory ledger. Semantics mirror
//! `crates/adapters/src/sqlite/leases.rs`: a lease whose expiry has passed is
//! reclaimed exactly once, the dead Attempt reaches its typed terminal state,
//! the work package returns to the ready queue, and the permanent fence counter
//! is never rewound, so the successor is granted N+1.

use super::super::{json, MemoryLedger};
use crate::records::{ActiveLease, ExpiredLease, OutboxItem};
use crate::store::LedgerError;
use bullet_domain::{AttemptState, CommandPhase, VariantId};

/// Outbox kind for one lease reclaimed by expiry, identical to the SQLite
/// adapter's `RECLAIM_OUTBOX_KIND`.
pub(super) const RECLAIM_OUTBOX_KIND: &str = "lease_reclaimed";

impl MemoryLedger {
    /// Every lease whose expiry has already passed, in variant order.
    pub(super) fn due_leases(&self, now: &str) -> Vec<ActiveLease> {
        let mut due: Vec<ActiveLease> = self
            .leases
            .values()
            .filter(|lease| lease.expires_at.as_str() <= now)
            .cloned()
            .collect();
        due.sort_by_key(|lease| lease.variant_id.to_string());
        due
    }

    /// Reclaim one already-expired lease. Every fallible step runs before the
    /// first map mutation, so a refusal leaves the ledger untouched.
    pub(super) fn reclaim(
        &mut self,
        lease: &ActiveLease,
        now: &str,
    ) -> Result<ExpiredLease, LedgerError> {
        let attempt_key = lease.attempt_id.to_string();
        let attempt = self
            .attempts
            .get(&attempt_key)
            .cloned()
            .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
        if !attempt.state.permits_expiry_reclaim() {
            return Err(LedgerError::Store(format!(
                "active lease Attempt {} cannot expire from {:?}",
                attempt.id, attempt.state
            )));
        }
        let next_state = attempt.state.transition(AttemptState::Crashed)?;
        let expired = ExpiredLease {
            variant_id: lease.variant_id.clone(),
            attempt_id: lease.attempt_id.clone(),
            work_package_id: attempt.work_package_id.clone(),
            fence: lease.fence,
        };
        let payload = json(&expired)?;
        let seq = u64::try_from(self.outbox.len())
            .map_err(|error| LedgerError::Store(error.to_string()))?
            .checked_add(1)
            .ok_or_else(|| LedgerError::Store("outbox sequence overflow".into()))?;
        if let Some(stored) = self.attempts.get_mut(&attempt_key) {
            stored.state = next_state;
        }
        self.leases.remove(&lease.variant_id.to_string());
        self.requeue_package(&attempt.work_package_id, now)?;
        self.push_event(
            "lease_expired",
            lease.attempt_id.as_str(),
            Some(lease.variant_id.to_string()),
            None,
            None,
        );
        self.outbox.push(OutboxItem {
            seq,
            command_id: None,
            kind: RECLAIM_OUTBOX_KIND.into(),
            payload,
            phase: CommandPhase::Pending,
            delivered_at: None,
            acked_at: None,
        });
        Ok(expired)
    }

    /// Reclaim exactly this variant's lease when its expiry has already passed.
    /// A live lease is never reclaimed; a variant with no lease is not an error.
    pub(super) fn reclaim_expired_variant(
        &mut self,
        variant: &VariantId,
        now: &str,
    ) -> Result<Option<ExpiredLease>, LedgerError> {
        let Some(lease) = self.leases.get(&variant.to_string()).cloned() else {
            return Ok(None);
        };
        if now < lease.expires_at.as_str() {
            return Ok(None);
        }
        self.reclaim(&lease, now).map(Some)
    }
}
