//! Read-only projection reads for the memory ledger. Row ordering mirrors
//! the SQLite adapter exactly so both readers project the same sequence.

use super::MemoryLedger;
use crate::effects::{EffectIntentRecord, EffectReceiptRecord};
use crate::records::ActiveLease;
use crate::store::{LedgerError, ProjectionReader};
use crate::ContextCapsule;
use bullet_domain::{Attempt, Candidate, Effect, Evidence};

impl ProjectionReader for MemoryLedger {
    fn list_context_capsules(&self) -> Result<Vec<ContextCapsule>, LedgerError> {
        self.validate_all_initial_contexts()?;
        let mut out: Vec<_> = self.context_capsules.values().cloned().collect();
        out.sort_by(|left, right| {
            left.work_package_id
                .as_str()
                .cmp(right.work_package_id.as_str())
                .then(left.revision.cmp(&right.revision))
        });
        Ok(out)
    }

    fn authority_time(&self) -> Result<String, LedgerError> {
        Ok(self.simulation_time())
    }

    fn list_leases(&self) -> Result<Vec<ActiveLease>, LedgerError> {
        Ok(self.leases.values().cloned().collect())
    }

    fn list_all_attempts(&self) -> Result<Vec<Attempt>, LedgerError> {
        let mut out: Vec<Attempt> = self.attempts.values().cloned().collect();
        out.sort_by(|a, b| {
            a.variant_id
                .as_str()
                .cmp(b.variant_id.as_str())
                .then(a.fence.cmp(&b.fence))
        });
        Ok(out)
    }

    fn list_candidates(&self) -> Result<Vec<Candidate>, LedgerError> {
        Ok(self.candidates.values().cloned().collect())
    }

    fn list_evidence(&self) -> Result<Vec<Evidence>, LedgerError> {
        Ok(self.evidence.values().cloned().collect())
    }

    fn list_effects(&self) -> Result<Vec<Effect>, LedgerError> {
        Ok(self.effects.values().cloned().collect())
    }

    fn list_effect_intents(&self) -> Result<Vec<EffectIntentRecord>, LedgerError> {
        let mut out: Vec<EffectIntentRecord> = self.effect_intents.values().cloned().collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.as_str().cmp(b.id.as_str()))
        });
        Ok(out)
    }

    fn list_effect_receipts(&self) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
        let mut out = self.effect_receipts.clone();
        out.sort_by(|a, b| {
            a.recorded_at
                .cmp(&b.recorded_at)
                .then_with(|| a.id.as_str().cmp(b.id.as_str()))
        });
        Ok(out)
    }
}
