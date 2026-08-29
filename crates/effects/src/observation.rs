//! Purpose-signed exact-target observations for the local component path.
//! Fixture keys authenticate negative truth but do not establish OS identity.

mod crypto;
mod validation;

use crate::IntegrationReceipt;
use bullet_domain::CandidateId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validation::validate_subject;

pub use crypto::{
    canonical_observation_bytes, decode_and_verify_fixture_observation, FixtureObserverSigningKey,
    FixtureObserverVerificationKey,
};

pub(super) const OBSERVATION_SCHEMA: &str = "bullet.integration-observation.v1";
pub(super) const ENVELOPE_SCHEMA: &str = "bullet.signed-integration-observation.v1";
pub(super) const SIGNING_PURPOSE: &str = "integration-observation-signing";
pub(super) const IMPLICIT_ASSERTION: &str = "bullet-farm.integration-observation.v1";
pub(super) const COMPONENT_CLASS: &str = "COMPONENT_PROOF";
pub(super) const FIXTURE_TRUST: &str = "FIXTURE_KEY_ONLY";
pub(super) const MAX_WINDOW_MS: u64 = 300_000;

/// Typed refusal from observation construction or admission.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ObservationError {
    /// A field, marker, or canonical encoding is invalid.
    #[error("signed observation record is invalid: {0}")]
    InvalidRecord(String),
    /// The purpose-separated signature or payload binding is invalid.
    #[error("signed observation signature is invalid")]
    SignatureInvalid,
    /// The external expected key identity differs from the envelope.
    #[error("signed observation key identity does not match expectation")]
    SigningKeyMismatch,
    /// The expected exact Candidate/integration/proof subject differs.
    #[error("signed observation does not bind the expected subject")]
    SubjectMismatch,
    /// The observation is future-dated, stale, or outside safe time bounds.
    #[error("signed observation is outside its freshness window")]
    ObservationTimeInvalid,
}

impl ObservationError {
    /// Stable machine refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRecord(_) => "SIGNED_OBSERVATION_RECORD_INVALID",
            Self::SignatureInvalid => "SIGNED_OBSERVATION_SIGNATURE_INVALID",
            Self::SigningKeyMismatch => "SIGNED_OBSERVATION_KEY_MISMATCH",
            Self::SubjectMismatch => "SIGNED_OBSERVATION_SUBJECT_MISMATCH",
            Self::ObservationTimeInvalid => "SIGNED_OBSERVATION_TIME_INVALID",
        }
    }
}

/// Exact immutable subjects an observer must bind before target read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSubjectV1 {
    pub candidate_id: CandidateId,
    pub proof_bundle_id: String,
    pub proof_root: String,
    pub integration_subject_id: String,
    pub target: String,
    pub previous_oid: String,
    pub integrated_oid: String,
    pub check_sha: String,
    pub check_name: String,
    pub check_proof_root: String,
}

impl ObservationSubjectV1 {
    /// Bind one exact protected-integration receipt to its Candidate and proof.
    pub fn from_integration(
        candidate_id: CandidateId,
        proof_bundle_id: impl Into<String>,
        proof_root: impl Into<String>,
        receipt: &IntegrationReceipt,
    ) -> Result<Self, ObservationError> {
        let subject = Self {
            candidate_id,
            proof_bundle_id: proof_bundle_id.into(),
            proof_root: proof_root.into(),
            integration_subject_id: receipt.subject_id.clone(),
            target: receipt.target.clone(),
            previous_oid: receipt.previous_oid.clone(),
            integrated_oid: receipt.integrated_oid.clone(),
            check_sha: receipt.check.sha.clone(),
            check_name: receipt.check.name.clone(),
            check_proof_root: receipt.check.proof_root.clone(),
        };
        validate_subject(&subject)?;
        Ok(subject)
    }
}

/// Caller input. Outcome is deliberately absent and derived from read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationInputV1 {
    pub subject: ObservationSubjectV1,
    pub freshness_window_ms: u64,
}

/// Four-valued exact-target result. No variant is named `PASS`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationOutcomeV1 {
    Matched,
    Mismatched,
    Absent,
    Unknown,
}

/// Fixture-key-signed exact target read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationV1 {
    pub schema_version: String,
    pub evidence_class: String,
    pub signing_trust: String,
    pub independent_evidence_eligible: bool,
    pub transaction_gate_eligible: bool,
    pub release_gate_eligible: bool,
    pub observation_id: String,
    pub subject: ObservationSubjectV1,
    pub outcome: ObservationOutcomeV1,
    pub observed_oid: Option<String>,
    pub readback_reason_code: Option<String>,
    pub integration_survived: bool,
    pub observed_at_unix_ms: u64,
    pub fresh_until_unix_ms: u64,
    pub observer_service_id: String,
    pub observer_key_id: String,
}

/// Purpose-signed observation carrier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedObservationV1 {
    pub schema_version: String,
    pub issuer: String,
    pub key_id: String,
    pub paseto: String,
    pub record: ObservationV1,
}

pub(super) fn invalid(message: impl Into<String>) -> ObservationError {
    ObservationError::InvalidRecord(message.into())
}
