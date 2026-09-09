//! Purpose-separated signed verification records for the offline component
//! path. Fixture key separation is authenticated; OS identity independence is
//! deliberately not claimed.

mod crypto;
mod records;
mod validation;

use crate::{execute, VerifierEvidence, VerifierRequest};
use bullet_domain::{CandidateId, EvidenceId};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical};
use crypto::{
    sign_record, verify_record, EVIDENCE_ASSERTION, EVIDENCE_PURPOSE, INTENT_ASSERTION,
    INTENT_PURPOSE, PROOF_ASSERTION, PROOF_PURPOSE,
};
pub use records::{
    EvidenceV1, ProofBundleV1, SignedEvidenceV1, SignedProofBundleV1, SignedRecordV1,
    SignedVerificationChainV1, SignedVerificationIntentV1, VerificationIntentInputV1,
    VerificationIntentV1,
};
use records::{
    CHAIN_SCHEMA, COMPONENT_CLASS, EVIDENCE_SCHEMA, FIXTURE_TRUST, INTENT_SCHEMA, PROOF_SCHEMA,
};
use thiserror::Error;
use validation::{
    digest, validate_evidence, validate_input, validate_intent, validate_proof,
    validate_verifier_record,
};

const INTENT_ENVELOPE_SCHEMA: &str = "bullet.signed-verification-intent.v1";
const EVIDENCE_ENVELOPE_SCHEMA: &str = "bullet.signed-evidence.v1";
const PROOF_ENVELOPE_SCHEMA: &str = "bullet.signed-proof-bundle.v1";

/// Typed refusal from signed verification-chain construction or admission.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SignedChainError {
    #[error("signed verification record is invalid: {0}")]
    InvalidRecord(String),
    #[error("signed verification record signature is invalid")]
    SignatureInvalid,
    #[error("signed verification record key identity does not match expectation")]
    SigningKeyMismatch,
    #[error("verification intent is outside its admitted time window")]
    IntentTimeInvalid,
    #[error("verification chain does not bind the expected Candidate request")]
    SubjectMismatch,
    #[error("gate outcome cannot produce a proof bundle")]
    OutcomeNotAdmissible,
    #[error("verifier execution refused ({reason_code}): {message}")]
    Execution {
        reason_code: &'static str,
        message: String,
    },
}

impl SignedChainError {
    /// Stable machine refusal code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRecord(_) => "SIGNED_VERIFICATION_RECORD_INVALID",
            Self::SignatureInvalid => "SIGNED_VERIFICATION_SIGNATURE_INVALID",
            Self::SigningKeyMismatch => "SIGNED_VERIFICATION_KEY_MISMATCH",
            Self::IntentTimeInvalid => "VERIFICATION_INTENT_TIME_INVALID",
            Self::SubjectMismatch => "VERIFICATION_SUBJECT_MISMATCH",
            Self::OutcomeNotAdmissible => "VERIFICATION_OUTCOME_NOT_ADMISSIBLE",
            Self::Execution { reason_code, .. } => reason_code,
        }
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> SignedChainError {
    SignedChainError::InvalidRecord(message.into())
}

/// Kernel-owned intent signing key for this component path.
#[derive(Debug)]
pub struct VerificationIntentSigningKey(crypto::RoleSigningKey);

/// Expected Kernel intent verification key.
#[derive(Clone, Debug)]
pub struct VerificationIntentVerificationKey(crypto::RoleVerificationKey);

/// Verifier-owned fixture signing key. It cannot assert OS independence.
#[derive(Debug)]
pub struct FixtureVerifierSigningKey(crypto::RoleSigningKey);

/// Expected fixture verifier verification key.
#[derive(Clone, Debug)]
pub struct FixtureVerifierVerificationKey(crypto::RoleVerificationKey);

macro_rules! verification_key_api {
    ($name:ident) => {
        impl $name {
            /// Reconstruct one externally expected public key from canonical bytes.
            pub fn from_public_hex(
                issuer: &str,
                key_id: &str,
                public_hex: &str,
            ) -> Result<Self, SignedChainError> {
                crypto::RoleVerificationKey::from_public_hex(issuer, key_id, public_hex).map(Self)
            }

            /// Authenticated issuer label.
            #[must_use]
            pub fn issuer(&self) -> &str {
                &self.0.issuer
            }

            /// Authenticated key identity.
            #[must_use]
            pub fn key_id(&self) -> &str {
                &self.0.key_id
            }

            /// Canonical 32-byte public half as 64 lowercase hex.
            #[must_use]
            pub fn public_hex(&self) -> &str {
                &self.0.public_hex
            }
        }
    };
}

verification_key_api!(VerificationIntentVerificationKey);
verification_key_api!(FixtureVerifierVerificationKey);

impl VerificationIntentSigningKey {
    /// Generate a purpose-bound fixture intent key.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, SignedChainError> {
        crypto::RoleSigningKey::generate(issuer, key_id).map(Self)
    }

    /// Matching trusted public half.
    #[must_use]
    pub fn verification_key(&self) -> VerificationIntentVerificationKey {
        VerificationIntentVerificationKey(self.0.verification_key())
    }

    /// Issue an exact-request intent; all identifiers and digests are derived or validated.
    pub fn issue(
        &self,
        input: VerificationIntentInputV1,
    ) -> Result<SignedVerificationIntentV1, SignedChainError> {
        validate_input(&input)?;
        let request_digest = digest("verification.request.v1", "req", &input.request)?;
        let intent_id = digest("verification.intent.id.v1", "vfi", &input)?;
        let record = VerificationIntentV1 {
            schema_version: INTENT_SCHEMA.into(),
            evidence_class: COMPONENT_CLASS.into(),
            signing_trust: FIXTURE_TRUST.into(),
            independent_evidence_eligible: false,
            transaction_gate_eligible: false,
            intent_id,
            candidate_id: input.candidate_id,
            request: input.request,
            request_digest,
            verifier_service_id: input.verifier_service_id,
            verifier_key_id: input.verifier_key_id,
            intent_nonce: input.intent_nonce,
            policy_digest: input.policy_digest,
            gate_spec_digest: input.gate_spec_digest,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        validate_intent(&record, None, record.issued_at_unix_ms)?;
        sign_record(
            &self.0,
            record,
            INTENT_ENVELOPE_SCHEMA,
            INTENT_PURPOSE,
            INTENT_ASSERTION,
        )
    }
}

impl FixtureVerifierSigningKey {
    /// Generate a verifier-owned fixture key.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, SignedChainError> {
        crypto::RoleSigningKey::generate(issuer, key_id).map(Self)
    }

    /// Matching trusted public half.
    #[must_use]
    pub fn verification_key(&self) -> FixtureVerifierVerificationKey {
        FixtureVerifierVerificationKey(self.0.verification_key())
    }

    /// Authenticate the intent, execute the sealed gate, and derive both signed outputs.
    pub async fn execute_chain(
        &self,
        signed_intent: SignedVerificationIntentV1,
        intent_key: &VerificationIntentVerificationKey,
        now_unix_ms: u64,
        author_overlap: bool,
    ) -> Result<SignedVerificationChainV1, SignedChainError> {
        let intent = authenticate_intent(&signed_intent, intent_key, now_unix_ms)?;
        if intent.verifier_service_id != self.0.issuer || intent.verifier_key_id != self.0.key_id {
            return Err(SignedChainError::SigningKeyMismatch);
        }
        let record = execute(&intent.request, author_overlap)
            .await
            .map_err(|error| SignedChainError::Execution {
                reason_code: error.reason_code(),
                message: error.to_string(),
            })?;
        validate_verifier_record(&intent, &record)?;
        let intent_envelope_digest =
            digest("verification.intent.envelope.v1", "vin", &signed_intent)?;
        let evidence = evidence_from(&intent, intent_envelope_digest, record)?;
        let signed_evidence = sign_record(
            &self.0,
            evidence,
            EVIDENCE_ENVELOPE_SCHEMA,
            EVIDENCE_PURPOSE,
            EVIDENCE_ASSERTION,
        )?;
        let proof = proof_from(&intent, &signed_evidence)?;
        let signed_proof = sign_record(
            &self.0,
            proof,
            PROOF_ENVELOPE_SCHEMA,
            PROOF_PURPOSE,
            PROOF_ASSERTION,
        )?;
        Ok(SignedVerificationChainV1 {
            schema_version: CHAIN_SCHEMA.into(),
            intent: signed_intent,
            evidence: signed_evidence,
            proof_bundle: signed_proof,
        })
    }
}

/// Canonically decode and authenticate an exact fixture chain.
pub fn decode_and_verify_fixture_chain(
    bytes: &[u8],
    intent_key: &VerificationIntentVerificationKey,
    verifier_key: &FixtureVerifierVerificationKey,
    expected_candidate: &CandidateId,
    expected_request: &VerifierRequest,
    now_unix_ms: u64,
) -> Result<SignedVerificationChainV1, SignedChainError> {
    let chain = decode_canonical::<SignedVerificationChainV1>(bytes)
        .map_err(|error| invalid(error.to_string()))?;
    verify_chain(
        &chain,
        intent_key,
        verifier_key,
        expected_candidate,
        expected_request,
        now_unix_ms,
    )?;
    Ok(chain)
}

fn authenticate_intent(
    signed: &SignedVerificationIntentV1,
    key: &VerificationIntentVerificationKey,
    now: u64,
) -> Result<VerificationIntentV1, SignedChainError> {
    let intent = verify_record(
        signed,
        &key.0,
        INTENT_ENVELOPE_SCHEMA,
        INTENT_PURPOSE,
        INTENT_ASSERTION,
    )?;
    validate_intent(&intent, None, now)?;
    Ok(intent)
}

fn verify_chain(
    chain: &SignedVerificationChainV1,
    intent_key: &VerificationIntentVerificationKey,
    verifier_key: &FixtureVerifierVerificationKey,
    expected_candidate: &CandidateId,
    expected_request: &VerifierRequest,
    now: u64,
) -> Result<(), SignedChainError> {
    if chain.schema_version != CHAIN_SCHEMA {
        return Err(invalid("verification chain schema mismatch"));
    }
    let intent = authenticate_intent(&chain.intent, intent_key, now)?;
    validate_intent(&intent, Some((expected_candidate, expected_request)), now)?;
    if intent.verifier_service_id != verifier_key.0.issuer
        || intent.verifier_key_id != verifier_key.0.key_id
    {
        return Err(SignedChainError::SigningKeyMismatch);
    }
    let evidence = verify_record(
        &chain.evidence,
        &verifier_key.0,
        EVIDENCE_ENVELOPE_SCHEMA,
        EVIDENCE_PURPOSE,
        EVIDENCE_ASSERTION,
    )?;
    validate_evidence(&intent, &chain.intent, &evidence)?;
    let proof = verify_record(
        &chain.proof_bundle,
        &verifier_key.0,
        PROOF_ENVELOPE_SCHEMA,
        PROOF_PURPOSE,
        PROOF_ASSERTION,
    )?;
    validate_proof(&intent, &chain.intent, &chain.evidence, &proof)
}

fn evidence_from(
    intent: &VerificationIntentV1,
    intent_envelope_digest: String,
    record: VerifierEvidence,
) -> Result<EvidenceV1, SignedChainError> {
    let id = digest(
        "verification.evidence.id.v1",
        "evd",
        &(&intent_envelope_digest, &record),
    )?;
    let evidence_id = EvidenceId::parse(id).map_err(|error| invalid(error.to_string()))?;
    Ok(EvidenceV1 {
        schema_version: EVIDENCE_SCHEMA.into(),
        evidence_class: COMPONENT_CLASS.into(),
        signing_trust: FIXTURE_TRUST.into(),
        independent_evidence_eligible: false,
        transaction_gate_eligible: false,
        evidence_id,
        intent_id: intent.intent_id.clone(),
        intent_envelope_digest,
        candidate_id: intent.candidate_id.clone(),
        request_digest: intent.request_digest.clone(),
        gate_spec_digest: intent.gate_spec_digest.clone(),
        verifier_service_id: intent.verifier_service_id.clone(),
        verifier_key_id: intent.verifier_key_id.clone(),
        record,
    })
}

fn proof_from(
    intent: &VerificationIntentV1,
    evidence: &SignedEvidenceV1,
) -> Result<ProofBundleV1, SignedChainError> {
    let evidence_envelope_digest = digest("verification.evidence.envelope.v1", "ven", evidence)?;
    let proof_root = digest(
        "verification.proof.root.v1",
        "prf",
        &(&intent.request_digest, &evidence_envelope_digest),
    )?;
    let proof_bundle_id = digest("verification.proof.id.v1", "prb", &proof_root)?;
    Ok(ProofBundleV1 {
        schema_version: PROOF_SCHEMA.into(),
        evidence_class: COMPONENT_CLASS.into(),
        signing_trust: FIXTURE_TRUST.into(),
        independent_evidence_eligible: false,
        transaction_gate_eligible: false,
        proof_bundle_id,
        proof_root,
        intent_id: intent.intent_id.clone(),
        intent_envelope_digest: evidence.record.intent_envelope_digest.clone(),
        evidence_id: evidence.record.evidence_id.clone(),
        evidence_envelope_digest,
        candidate_id: intent.candidate_id.clone(),
        request_digest: intent.request_digest.clone(),
        gate_spec_digest: intent.gate_spec_digest.clone(),
        verifier_service_id: intent.verifier_service_id.clone(),
        verifier_key_id: intent.verifier_key_id.clone(),
        outcome: evidence.record.record.outcome,
    })
}

/// Canonical RFC-8785 bytes for storage or transport.
pub fn canonical_chain_bytes(
    chain: &SignedVerificationChainV1,
) -> Result<Vec<u8>, SignedChainError> {
    canonical_json(chain).map_err(|error| invalid(error.to_string()))
}
