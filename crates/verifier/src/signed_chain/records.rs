use crate::{VerifierEvidence, VerifierRequest};
use bullet_domain::{CandidateId, EvidenceId, GateOutcome};
use serde::{Deserialize, Serialize};

pub const INTENT_SCHEMA: &str = "bullet.verification-intent.v1";
pub const EVIDENCE_SCHEMA: &str = "bullet.evidence.v1";
pub const PROOF_SCHEMA: &str = "bullet.proof-bundle.v1";
pub const CHAIN_SCHEMA: &str = "bullet.verification-chain.v1";
pub const COMPONENT_CLASS: &str = "COMPONENT_PROOF";
pub const FIXTURE_TRUST: &str = "FIXTURE_KEY_ONLY";

/// Inputs accepted by the Kernel-owned fixture intent issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIntentInputV1 {
    /// Stable BulletGit Candidate identity.
    pub candidate_id: CandidateId,
    /// Exact reconstruction and catalog-gate request.
    pub request: VerifierRequest,
    /// Verifier service identity selected by the issuer.
    pub verifier_service_id: String,
    /// Exact verifier public-key identity selected by the issuer.
    pub verifier_key_id: String,
    /// One-use-shaped nonce. This component does not persist consumption.
    pub intent_nonce: String,
    /// Exact policy snapshot digest.
    pub policy_digest: String,
    /// Exact immutable gate-spec digest.
    pub gate_spec_digest: String,
    /// Inclusive issue time.
    pub issued_at_unix_ms: u64,
    /// Exclusive expiry time.
    pub expires_at_unix_ms: u64,
}

/// Kernel-issued, exact-subject verification intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIntentV1 {
    pub schema_version: String,
    pub evidence_class: String,
    pub signing_trust: String,
    pub independent_evidence_eligible: bool,
    pub transaction_gate_eligible: bool,
    pub intent_id: String,
    pub candidate_id: CandidateId,
    pub request: VerifierRequest,
    pub request_digest: String,
    pub verifier_service_id: String,
    pub verifier_key_id: String,
    pub intent_nonce: String,
    pub policy_digest: String,
    pub gate_spec_digest: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Verifier-owned exact-subject evidence. Fixture signing is not independence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceV1 {
    pub schema_version: String,
    pub evidence_class: String,
    pub signing_trust: String,
    pub independent_evidence_eligible: bool,
    pub transaction_gate_eligible: bool,
    pub evidence_id: EvidenceId,
    pub intent_id: String,
    pub intent_envelope_digest: String,
    pub candidate_id: CandidateId,
    pub request_digest: String,
    pub gate_spec_digest: String,
    pub verifier_service_id: String,
    pub verifier_key_id: String,
    pub record: VerifierEvidence,
}

/// Verifier-owned binding from one admitted intent to one exact Evidence record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundleV1 {
    pub schema_version: String,
    pub evidence_class: String,
    pub signing_trust: String,
    pub independent_evidence_eligible: bool,
    pub transaction_gate_eligible: bool,
    pub proof_bundle_id: String,
    pub proof_root: String,
    pub intent_id: String,
    pub intent_envelope_digest: String,
    pub evidence_id: EvidenceId,
    pub evidence_envelope_digest: String,
    pub candidate_id: CandidateId,
    pub request_digest: String,
    pub gate_spec_digest: String,
    pub verifier_service_id: String,
    pub verifier_key_id: String,
    pub outcome: GateOutcome,
}

/// Purpose-signed carrier. Trust comes from the expected external key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecordV1<T> {
    pub schema_version: String,
    pub issuer: String,
    pub key_id: String,
    pub paseto: String,
    pub record: T,
}

pub type SignedVerificationIntentV1 = SignedRecordV1<VerificationIntentV1>;
pub type SignedEvidenceV1 = SignedRecordV1<EvidenceV1>;
pub type SignedProofBundleV1 = SignedRecordV1<ProofBundleV1>;

/// Complete fixture-key-signed chain. The two eligibility flags stay false.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedVerificationChainV1 {
    pub schema_version: String,
    pub intent: SignedVerificationIntentV1,
    pub evidence: SignedEvidenceV1,
    pub proof_bundle: SignedProofBundleV1,
}
