//! Effect intent and receipt persistence for the memory ledger. Semantics
//! mirror the SQLite adapter's transactions exactly; the shared effect
//! conformance suite enforces the parity.

use super::MemoryLedger;
use crate::effect_state::EffectState;
use crate::effects::{EffectIntentRecord, EffectReceiptRecord};
use crate::store::LedgerError;
use bullet_domain::{DomainError, EffectId};

impl MemoryLedger {
    pub(super) fn record_effect_intent_impl(
        &mut self,
        intent: &EffectIntentRecord,
    ) -> Result<(EffectIntentRecord, bool), LedgerError> {
        self.tick()?;
        if intent.state != EffectState::Proposed {
            return Err(DomainError::Conflict(format!(
                "effect intent {} must be recorded as PROPOSED, not {}",
                intent.id,
                intent.state.as_str()
            ))
            .into());
        }
        let mut normalized = intent.clone();
        normalized.payload_hash = intent.payload_digest()?;
        normalized.unknown_retries = 0;
        let key = format!("{}\u{1f}{}", intent.provider, intent.logical_effect_key);
        if let Some(id) = self.effect_keys.get(&key).cloned() {
            let existing = self
                .effect_intents
                .get(&id)
                .cloned()
                .ok_or_else(|| LedgerError::Store(format!("effect key {key} has no row")))?;
            if existing.payload_hash != normalized.payload_hash {
                return Err(DomainError::Idempotency(format!(
                    "effect {}:{} exists with a different identity",
                    intent.provider, intent.logical_effect_key
                ))
                .into());
            }
            return Ok((existing, false));
        }
        if self.effect_intents.contains_key(intent.id.as_str()) {
            return Err(DomainError::Conflict(format!(
                "effect intent id {} already used by another logical key",
                intent.id
            ))
            .into());
        }
        self.effect_keys.insert(key, intent.id.to_string());
        self.effect_intents
            .insert(intent.id.to_string(), normalized.clone());
        self.push_event(
            "effect_intent_recorded",
            normalized.id.as_str(),
            Some(normalized.attempt_id.to_string()),
            None,
            None,
        );
        Ok((normalized, true))
    }

    pub(super) fn get_effect_intent_impl(
        &self,
        provider: &str,
        logical_key: &str,
    ) -> Result<Option<EffectIntentRecord>, LedgerError> {
        let key = format!("{provider}\u{1f}{logical_key}");
        let Some(id) = self.effect_keys.get(&key) else {
            return Ok(None);
        };
        Ok(self.effect_intents.get(id).cloned())
    }

    pub(super) fn transition_effect_impl(
        &mut self,
        id: &EffectId,
        to: EffectState,
    ) -> Result<EffectIntentRecord, LedgerError> {
        self.tick()?;
        let existing = self
            .effect_intents
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| LedgerError::Store(format!("unknown effect intent {id}")))?;
        let next = existing.state.transition(to)?;
        let mut updated = existing.clone();
        updated.state = next;
        if existing.state == EffectState::OutcomeUnknown && next == EffectState::Dispatching {
            updated.unknown_retries += 1;
        }
        self.effect_intents.insert(id.to_string(), updated.clone());
        self.push_event(
            "effect_transition",
            &format!("{id}:{}->{}", existing.state.as_str(), next.as_str()),
            Some(updated.attempt_id.to_string()),
            None,
            None,
        );
        Ok(updated)
    }

    pub(super) fn record_effect_receipt_impl(
        &mut self,
        receipt: &EffectReceiptRecord,
    ) -> Result<bool, LedgerError> {
        self.tick()?;
        if let Some(existing) = self.effect_receipts.iter().find(|row| row.id == receipt.id) {
            if existing == receipt {
                return Ok(false);
            }
            return Err(DomainError::Conflict(format!(
                "effect receipt {} differs from the stored row",
                receipt.id
            ))
            .into());
        }
        self.effect_receipts.push(receipt.clone());
        self.push_event(
            "effect_receipt_recorded",
            receipt.id.as_str(),
            Some(receipt.effect_intent_id.to_string()),
            None,
            None,
        );
        Ok(true)
    }

    pub(super) fn effect_receipts_impl(
        &self,
        intent: &EffectId,
    ) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
        Ok(self
            .effect_receipts
            .iter()
            .filter(|row| row.effect_intent_id == *intent)
            .cloned()
            .collect())
    }

    pub(super) fn unresolved_effects_impl(&self) -> Result<Vec<EffectIntentRecord>, LedgerError> {
        let mut rows: Vec<EffectIntentRecord> = self
            .effect_intents
            .values()
            .filter(|row| row.state.is_unresolved())
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            (a.created_at.as_str(), a.id.as_str()).cmp(&(b.created_at.as_str(), b.id.as_str()))
        });
        Ok(rows)
    }
}
