//! Durable effect intent and receipt records (spec sections 6.15 and 26.2).
//! An intent is unique on `(provider, logical_effect_key)`; replaying the
//! same identity returns the stored row, and a differing identity under the
//! same key is a typed idempotency conflict.

use crate::effect_state::EffectState;
use bullet_domain::{AttemptId, Digest, DomainError, EffectId, EffectReceiptId};
use serde::{Deserialize, Serialize};

const RECOVERY_RECEIPT_DOMAIN: &str = "bullet.effect-recovery-receipt.v1";

/// The all-zeros git OID: as an expected precondition it means the target
/// ref must not exist (create semantics).
pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// One durable effect intent row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntentRecord {
    /// Identity.
    pub id: EffectId,
    /// Idempotency key: unique per provider.
    pub logical_effect_key: String,
    /// Provider such as `local-bare` or `jeryu`.
    pub provider: String,
    /// Target resource, e.g. a fully qualified ref name.
    pub target_identity: String,
    /// Desired remote value, e.g. the new commit OID.
    pub desired_state_hash: String,
    /// Expected current remote value; [`ZERO_OID`] means create.
    pub expected_old_oid: String,
    /// Attempt whose authority proposed the effect.
    pub attempt_id: AttemptId,
    /// Fence of that attempt at proposal time.
    pub fence: u64,
    /// Policy snapshot label.
    pub policy_version: String,
    /// Digest of the stable identity payload.
    pub payload_hash: String,
    /// Provider-side idempotency key, when the provider supports one.
    pub provider_idempotency_key: Option<String>,
    /// State machine position.
    pub state: EffectState,
    /// Reconcile-proven non-execution retries consumed.
    pub unknown_retries: u32,
    /// Creation time (RFC 3339 UTC).
    pub created_at: String,
}

impl EffectIntentRecord {
    /// Canonical identity payload for idempotency comparison. Excludes the
    /// mutable `state`, `unknown_retries`, and `created_at` fields so a
    /// replayed proposal matches while any change to the requested mutation
    /// conflicts.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when serialization fails.
    pub fn stable_payload(&self) -> Result<String, DomainError> {
        let value = serde_json::json!({
            "logical_effect_key": self.logical_effect_key,
            "provider": self.provider,
            "target_identity": self.target_identity,
            "desired_state_hash": self.desired_state_hash,
            "expected_old_oid": self.expected_old_oid,
            "attempt_id": self.attempt_id.as_str(),
            "fence": self.fence,
            "policy_version": self.policy_version,
            "provider_idempotency_key": self.provider_idempotency_key,
        });
        serde_json::to_string(&value).map_err(|err| DomainError::Encoding(err.to_string()))
    }

    /// Digest of [`Self::stable_payload`], stored as `payload_hash`.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when serialization fails.
    pub fn payload_digest(&self) -> Result<String, DomainError> {
        Ok(self.stable_payload_digest()?.to_hex())
    }

    /// Typed digest of [`Self::stable_payload`].
    pub fn stable_payload_digest(&self) -> Result<Digest, DomainError> {
        Ok(Digest::of(self.stable_payload()?.as_bytes()))
    }
}

/// Read-back verdict of one receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptVerdict {
    /// Observed remote value equals the desired hash.
    Match,
    /// Observed remote value differs from both desired and expected.
    Mismatch,
    /// The remote target does not exist.
    Absent,
}

impl ReceiptVerdict {
    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "MATCH",
            Self::Mismatch => "MISMATCH",
            Self::Absent => "ABSENT",
        }
    }

    /// Parse a stable wire name.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` for any label outside the catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "MATCH" => Ok(Self::Match),
            "MISMATCH" => Ok(Self::Mismatch),
            "ABSENT" => Ok(Self::Absent),
            other => Err(DomainError::UnknownState(format!(
                "receipt verdict {other}"
            ))),
        }
    }
}

/// One durable effect receipt row (append-only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptRecord {
    /// Frozen wire identity (`efr_` + 64 lowercase hex).
    pub id: EffectReceiptId,
    /// Intent the receipt settles or annotates.
    pub effect_intent_id: EffectId,
    /// Remote identity that was read back, e.g. the ref name.
    pub observed_remote_identity: String,
    /// Observed remote value; `None` records authoritative absence.
    pub observed_state_hash: Option<String>,
    /// How the remote truth was observed.
    pub verification_method: String,
    /// Read-back verdict.
    pub verification_result: ReceiptVerdict,
    /// Whether the effect was adopted after `OUTCOME_UNKNOWN`.
    pub adopted_after_unknown: bool,
    /// Recording time (RFC 3339 UTC).
    pub recorded_at: String,
}

/// Deterministic receipt id from a seed.
#[must_use]
pub fn receipt_id(seed: &str) -> EffectReceiptId {
    EffectReceiptId::from_seed(seed)
}

/// Deterministic recovery receipt identity. Mutable intent state, retry count,
/// database timestamps, and caller time are deliberately outside the subject.
pub fn recovery_receipt_id(
    intent: &EffectIntentRecord,
    observed_remote_identity: &str,
    observed_state_hash: Option<&str>,
    verification_method: &str,
    verification_result: ReceiptVerdict,
) -> Result<EffectReceiptId, DomainError> {
    #[derive(Serialize)]
    struct Subject<'a> {
        schema_version: &'static str,
        effect_intent_id: &'a EffectId,
        intent_payload_digest: Digest,
        observed_remote_identity: &'a str,
        observed_state_hash: Option<&'a str>,
        verification_method: &'a str,
        verification_result: ReceiptVerdict,
    }

    let subject = Subject {
        schema_version: RECOVERY_RECEIPT_DOMAIN,
        effect_intent_id: &intent.id,
        intent_payload_digest: intent.stable_payload_digest()?,
        observed_remote_identity,
        observed_state_hash,
        verification_method,
        verification_result,
    };
    let digest = Digest::of_json(&subject)?;
    Ok(EffectReceiptId::from_seed(&format!(
        "{RECOVERY_RECEIPT_DOMAIN}:{}",
        digest.to_hex()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> EffectIntentRecord {
        EffectIntentRecord {
            id: EffectId::from_seed("er-1"),
            logical_effect_key: "push:can_1:refs/heads/bullet/candidate/x".into(),
            provider: "local-bare".into(),
            target_identity: "refs/heads/bullet/candidate/x".into(),
            desired_state_hash: "b".repeat(40),
            expected_old_oid: ZERO_OID.into(),
            attempt_id: AttemptId::from_seed("er-attempt"),
            fence: 3,
            policy_version: "policy-v1".into(),
            payload_hash: String::new(),
            provider_idempotency_key: None,
            state: EffectState::Proposed,
            unknown_retries: 0,
            created_at: "2026-08-24T00:00:00Z".into(),
        }
    }

    #[test]
    fn stable_payload_ignores_state_and_retries() {
        let a = intent();
        let mut b = intent();
        b.state = EffectState::Quarantined;
        b.unknown_retries = 1;
        b.created_at = "2026-08-24T09:00:00Z".into();
        assert_eq!(
            a.stable_payload().expect("payload"),
            b.stable_payload().expect("payload")
        );
        let mut c = intent();
        c.desired_state_hash = "c".repeat(40);
        assert_ne!(
            a.stable_payload().expect("payload"),
            c.stable_payload().expect("payload")
        );
    }

    #[test]
    fn receipt_id_is_prefixed_and_stable() {
        let id = receipt_id("seed-1");
        assert!(id.as_str().starts_with("efr_"));
        assert_eq!(id.as_str().len(), 4 + 64);
        assert_eq!(id, receipt_id("seed-1"));
        assert_ne!(id, receipt_id("seed-2"));
    }
}
