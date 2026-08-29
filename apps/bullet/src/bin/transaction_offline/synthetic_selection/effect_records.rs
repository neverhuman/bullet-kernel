//! Recursively closed projections of durable effect rows retained in receipts.

use super::fail;
use bullet_application::{EffectIntentRecord, EffectReceiptRecord};
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedEffectIntent {
    pub(super) id: String,
    pub(super) logical_effect_key: String,
    pub(super) provider: String,
    pub(super) target_identity: String,
    pub(super) desired_state_hash: String,
    pub(super) expected_old_oid: String,
    pub(super) attempt_id: String,
    pub(super) fence: u64,
    pub(super) policy_version: String,
    pub(super) payload_hash: String,
    pub(super) provider_idempotency_key: Option<String>,
    pub(super) state: String,
    pub(super) unknown_retries: u32,
    pub(super) created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedEffectReceipt {
    pub(super) id: String,
    pub(super) effect_intent_id: String,
    pub(super) observed_remote_identity: String,
    pub(super) observed_state_hash: Option<String>,
    pub(super) verification_method: String,
    pub(super) verification_result: String,
    pub(super) adopted_after_unknown: bool,
    pub(super) recorded_at: String,
}

impl ClosedEffectIntent {
    pub(super) fn from_record(row: &EffectIntentRecord) -> Result<Self, String> {
        if row
            .payload_digest()
            .map_err(|error| fail(error.to_string()))?
            != row.payload_hash
        {
            return Err(fail("durable effect payload hash differs"));
        }
        Ok(Self {
            id: row.id.to_string(),
            logical_effect_key: row.logical_effect_key.clone(),
            provider: row.provider.clone(),
            target_identity: row.target_identity.clone(),
            desired_state_hash: row.desired_state_hash.clone(),
            expected_old_oid: row.expected_old_oid.clone(),
            attempt_id: row.attempt_id.to_string(),
            fence: row.fence,
            policy_version: row.policy_version.clone(),
            payload_hash: row.payload_hash.clone(),
            provider_idempotency_key: row.provider_idempotency_key.clone(),
            state: row.state.as_str().into(),
            unknown_retries: row.unknown_retries,
            created_at: row.created_at.clone(),
        })
    }

    pub(super) fn validate_payload(&self) -> Result<(), String> {
        let stable = serde_json::json!({
            "logical_effect_key": self.logical_effect_key,
            "provider": self.provider,
            "target_identity": self.target_identity,
            "desired_state_hash": self.desired_state_hash,
            "expected_old_oid": self.expected_old_oid,
            "attempt_id": self.attempt_id,
            "fence": self.fence,
            "policy_version": self.policy_version,
            "provider_idempotency_key": self.provider_idempotency_key,
        });
        let bytes = serde_json::to_string(&stable)
            .map_err(|error| fail(format!("encode closed effect payload: {error}")))?;
        (Digest::of(bytes.as_bytes()).to_hex() == self.payload_hash)
            .then_some(())
            .ok_or_else(|| fail("closed effect payload digest differs"))
    }
}

impl ClosedEffectReceipt {
    pub(super) fn from_record(row: &EffectReceiptRecord) -> Self {
        Self {
            id: row.id.to_string(),
            effect_intent_id: row.effect_intent_id.to_string(),
            observed_remote_identity: row.observed_remote_identity.clone(),
            observed_state_hash: row.observed_state_hash.clone(),
            verification_method: row.verification_method.clone(),
            verification_result: row.verification_result.as_str().into(),
            adopted_after_unknown: row.adopted_after_unknown,
            recorded_at: row.recorded_at.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_effect_projections_reject_unknown_fields() {
        let intent = serde_json::json!({
            "id":"eff_0000000000000000000000000000000000000000000000000000000000000000",
            "logical_effect_key":"key", "provider":"local-bare", "target_identity":"refs/x",
            "desired_state_hash":"head", "expected_old_oid":"old", "attempt_id":"atm_x",
            "fence":2, "policy_version":"policy-v1", "payload_hash":"hash",
            "provider_idempotency_key":null, "state":"COMMITTED", "unknown_retries":0,
            "created_at":"now", "unknown":false
        });
        let receipt = serde_json::json!({
            "id":"efr_0000000000000000000000000000000000000000000000000000000000000000",
            "effect_intent_id":"eff_x", "observed_remote_identity":"refs/x",
            "observed_state_hash":"head", "verification_method":"readback",
            "verification_result":"MATCH", "adopted_after_unknown":true,
            "recorded_at":"now", "unknown":false
        });
        assert!(serde_json::from_value::<ClosedEffectIntent>(intent).is_err());
        assert!(serde_json::from_value::<ClosedEffectReceipt>(receipt).is_err());
    }
}
