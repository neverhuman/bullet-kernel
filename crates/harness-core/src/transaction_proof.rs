//! Self-signed transaction-component receipt. This exercises the offline
//! fixture saga but is never admissible as a `TRANSACTION_PROOF`.

use crate::error::HarnessError;
use crate::launch_grant::{canonical_json, decode_canonical, validate_label};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::{Deserialize, Serialize};

/// Frozen component-receipt schema.
pub const TRANSACTION_COMPONENT_SCHEMA_VERSION: &str = "v1alpha1";
/// Evidence class bound into the signed document.
pub const TRANSACTION_COMPONENT_CLASS: &str = "COMPONENT_PROOF";
/// Trust class for the in-process key. This is not an external trust root.
pub const TRANSACTION_COMPONENT_TRUST: &str = "EPHEMERAL_SELF_SIGNED";
/// Footer purpose bound into the signature.
pub const TRANSACTION_COMPONENT_KEY_PURPOSE: &str = "transaction-component-signing";
/// PASETO implicit assertion; never transmitted.
pub const TRANSACTION_COMPONENT_IMPLICIT_ASSERTION: &[u8] =
    b"bullet-farm.transaction-component.v1alpha1";

/// Canonical fixture-saga subject. It intentionally cannot clear a gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionComponentSubject {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Always `COMPONENT_PROOF`.
    pub evidence_class: String,
    /// Always `EPHEMERAL_SELF_SIGNED`.
    pub signing_trust: String,
    /// Always false; semantic release admission must reject this receipt.
    pub transaction_gate_eligible: bool,
    /// First writer fence.
    pub fence_first: u64,
    /// Successor fence. Must be `fence_first + 1`.
    pub fence_second: u64,
    /// First attempt id.
    pub attempt_first: String,
    /// Successor attempt id.
    pub attempt_second: String,
    /// Candidate id prepared by fixture gitd.
    pub candidate_id: String,
    /// Independent verifier outcome. Writer overlap cannot be `PASS`.
    pub verifier_outcome: String,
    /// Writer-overlap reason when the author process is refused.
    pub writer_proof_refused: bool,
    /// Lost-response effect phase before reconcile.
    pub effect_unknown: String,
    /// Settled effect phase after identity-exact adopt or orphan.
    pub effect_settled: String,
    /// Whether the stale first fence was refused.
    pub stale_refused: bool,
    /// Whether fixture gitd was the child writer.
    pub gitd_fixture: bool,
    /// Recorded command id. Phase is never painted as empty success.
    pub command_id: String,
    /// Command phase (`pending` or `unknown`, never fabricated `verified`).
    pub command_phase: String,
}

impl TransactionComponentSubject {
    /// Shape check.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for a bad schema or fence pair.
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != TRANSACTION_COMPONENT_SCHEMA_VERSION {
            return Err(invalid("schema_version must be v1alpha1"));
        }
        if self.evidence_class != TRANSACTION_COMPONENT_CLASS {
            return Err(invalid("evidence_class must be COMPONENT_PROOF"));
        }
        if self.signing_trust != TRANSACTION_COMPONENT_TRUST {
            return Err(invalid("signing_trust must be EPHEMERAL_SELF_SIGNED"));
        }
        if self.transaction_gate_eligible {
            return Err(invalid(
                "component receipt cannot be transaction-gate eligible",
            ));
        }
        if self.fence_second != self.fence_first.saturating_add(1) {
            return Err(invalid("successor fence must be first fence + 1"));
        }
        if !self.stale_refused {
            return Err(invalid("stale fence must be refused"));
        }
        if !self.gitd_fixture {
            return Err(invalid("transaction component requires fixture gitd"));
        }
        if self.command_phase == "verified" || self.command_phase == "applied" {
            return Err(invalid("command phase must not be painted as success"));
        }
        if self.effect_unknown.is_empty() {
            return Err(invalid("lost-response UNKNOWN must be recorded"));
        }
        Ok(())
    }
}

/// Signed proof document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransactionComponent {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Always `COMPONENT_PROOF`.
    pub evidence_class: String,
    /// Issuer label.
    pub issuer: String,
    /// Key label.
    pub key_id: String,
    /// 64-hex public half.
    pub public_hex: String,
    /// PASETO v4.public token.
    pub paseto: String,
    /// Canonical subject that was signed.
    pub subject: TransactionComponentSubject,
}

/// Issuing key. Never serialized.
pub struct TransactionComponentSigningKey {
    issuer: String,
    key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public_hex: String,
}

impl std::fmt::Debug for TransactionComponentSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionComponentSigningKey")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("public_hex", &self.public_hex)
            .finish_non_exhaustive()
    }
}

impl TransactionComponentSigningKey {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    ///
    /// Bad label or entropy failure.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, HarnessError> {
        validate_label("issuer", issuer)?;
        validate_label("key_id", key_id)?;
        let pair = AsymmetricKeyPair::<V4>::generate()
            .map_err(|_| invalid("operating-system entropy unavailable"))?;
        Self::from_bytes(issuer, key_id, pair.secret.as_bytes())
    }

    /// Load 64 raw secret bytes.
    ///
    /// # Errors
    ///
    /// Bad label or key.
    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        validate_label("issuer", issuer)?;
        validate_label("key_id", key_id)?;
        if bytes.len() != 64 || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("PASETO v4.public secret keys are 64 nonzero bytes"));
        }
        let secret =
            AsymmetricSecretKey::<V4>::from(bytes).map_err(|_| invalid("invalid signing key"))?;
        let public = AsymmetricPublicKey::<V4>::try_from(&secret)
            .map_err(|_| invalid("signing key has no derivable public half"))?;
        Ok(Self {
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            secret,
            public_hex: hex::encode(public.as_bytes()),
        })
    }

    /// 64-hex public half.
    #[must_use]
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// Sign a validated subject.
    ///
    /// # Errors
    ///
    /// Shape or signing failure.
    pub fn sign(
        &self,
        subject: &TransactionComponentSubject,
    ) -> Result<SignedTransactionComponent, HarnessError> {
        subject.validate()?;
        let payload = canonical_json(subject)?;
        let footer = canonical_json(&Footer {
            purpose: TRANSACTION_COMPONENT_KEY_PURPOSE,
            issuer: self.issuer.as_str(),
            key_id: self.key_id.as_str(),
        })?;
        let paseto = PublicToken::sign(
            &self.secret,
            &payload,
            Some(&footer),
            Some(TRANSACTION_COMPONENT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signing failed"))?;
        Ok(SignedTransactionComponent {
            schema_version: TRANSACTION_COMPONENT_SCHEMA_VERSION.to_string(),
            evidence_class: TRANSACTION_COMPONENT_CLASS.to_string(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            public_hex: self.public_hex.clone(),
            paseto,
            subject: subject.clone(),
        })
    }
}

/// Verify a signed proof against the embedded public half.
///
/// # Errors
///
/// Signature, footer, or subject mismatch.
pub fn verify_transaction_component(
    proof: &SignedTransactionComponent,
) -> Result<TransactionComponentSubject, HarnessError> {
    proof.subject.validate()?;
    if proof.schema_version != TRANSACTION_COMPONENT_SCHEMA_VERSION
        || proof.evidence_class != TRANSACTION_COMPONENT_CLASS
    {
        return Err(invalid("proof envelope is not COMPONENT_PROOF v1alpha1"));
    }
    let public = hex::decode(&proof.public_hex).map_err(|_| invalid("public_hex"))?;
    let public = AsymmetricPublicKey::<V4>::from(&public)
        .map_err(|_| invalid("invalid transaction-proof public key"))?;
    let token = UntrustedToken::<Public, V4>::try_from(proof.paseto.as_str())
        .map_err(|_| invalid("unparseable transaction-proof token"))?;
    let footer = canonical_json(&Footer {
        purpose: TRANSACTION_COMPONENT_KEY_PURPOSE,
        issuer: proof.issuer.as_str(),
        key_id: proof.key_id.as_str(),
    })?;
    let trusted = PublicToken::verify(
        &public,
        &token,
        Some(&footer),
        Some(TRANSACTION_COMPONENT_IMPLICIT_ASSERTION),
    )
    .map_err(|_| invalid("transaction-proof signature is invalid"))?;
    let claimed = decode_canonical::<TransactionComponentSubject>(trusted.payload().as_bytes())?;
    if claimed != proof.subject {
        return Err(invalid("proof subject does not match signed payload"));
    }
    Ok(claimed)
}

#[derive(Serialize)]
struct Footer<'a> {
    purpose: &'static str,
    issuer: &'a str,
    key_id: &'a str,
}

fn invalid(reason: impl Into<String>) -> HarnessError {
    HarnessError::LaunchGrantInvalid {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> TransactionComponentSubject {
        TransactionComponentSubject {
            schema_version: TRANSACTION_COMPONENT_SCHEMA_VERSION.into(),
            evidence_class: TRANSACTION_COMPONENT_CLASS.into(),
            signing_trust: TRANSACTION_COMPONENT_TRUST.into(),
            transaction_gate_eligible: false,
            fence_first: 1,
            fence_second: 2,
            attempt_first: "atm_1".into(),
            attempt_second: "atm_2".into(),
            candidate_id: "can_1".into(),
            verifier_outcome: "FAIL".into(),
            writer_proof_refused: true,
            effect_unknown: "OUTCOME_UNKNOWN".into(),
            effect_settled: "COMMITTED".into(),
            stale_refused: true,
            gitd_fixture: true,
            command_id: "cmd_1".into(),
            command_phase: "pending".into(),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1")
            .expect("key");
        let proof = key.sign(&subject()).expect("sign");
        let verified = verify_transaction_component(&proof).expect("verify");
        assert_eq!(verified, subject());
    }

    #[test]
    fn painted_success_is_refused() {
        let mut bad = subject();
        bad.command_phase = "verified".into();
        let key = TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1")
            .expect("key");
        assert!(key.sign(&bad).is_err());
    }

    #[test]
    fn component_receipt_cannot_be_promoted_or_relabelled() {
        let key = TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1")
            .expect("key");
        let mut promoted = subject();
        promoted.transaction_gate_eligible = true;
        assert!(key.sign(&promoted).is_err());

        let mut relabelled = subject();
        relabelled.evidence_class = "TRANSACTION_PROOF".into();
        assert!(key.sign(&relabelled).is_err());

        let mut trusted = subject();
        trusted.signing_trust = "EXTERNAL_TRUST_ROOT".into();
        assert!(key.sign(&trusted).is_err());
    }
}
