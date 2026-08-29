//! Fixture-key-signed authoritative target observation for the offline bridge.

use super::support::fail;
use bullet_domain::{CandidateId, Digest};
use bullet_effects_core::{
    canonical_observation_bytes, decode_and_verify_fixture_observation, FixtureObserverSigningKey,
    FixtureObserverVerificationKey, ForgeIntegration, IntegrationReceipt, ObservationInputV1,
    ObservationOutcomeV1, ObservationSubjectV1, SignedObservationV1,
};
use serde::{Deserialize, Serialize};

const OBSERVER_ISSUER: &str = "bullet-observer";
const OBSERVER_KEY_ID: &str = "observer-fixture-1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeySubject {
    issuer: String,
    key_id: String,
    public_hex: String,
}

/// Signed, reverified component Observation retained with its public subject.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedObservationClosure {
    signing_trust: String,
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    release_gate_eligible: bool,
    chain_reverified: bool,
    canonical_observation_blake3: String,
    observer_key: PublicKeySubject,
    signed: SignedObservationV1,
}

impl SignedObservationClosure {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_selected(
        &self,
        candidate_id: &str,
        proof_bundle_id: &str,
        proof_root: &str,
        integration_subject_id: &str,
        target: &str,
        previous_oid: &str,
        integrated_oid: &str,
        check_name: &str,
    ) -> Result<(), String> {
        let candidate =
            CandidateId::parse(candidate_id).map_err(|error| fail(error.to_string()))?;
        let record = &self.signed.record;
        let subject = &record.subject;
        let canonical =
            canonical_observation_bytes(&self.signed).map_err(|error| fail(error.to_string()))?;
        let key = FixtureObserverVerificationKey::from_public_hex(
            &self.observer_key.issuer,
            &self.observer_key.key_id,
            &self.observer_key.public_hex,
        )
        .map_err(|error| fail(error.to_string()))?;
        let verified = decode_and_verify_fixture_observation(
            &canonical,
            &key,
            subject,
            record.observed_at_unix_ms,
        )
        .map_err(|error| fail(error.to_string()))?;
        let exact = verified == self.signed
            && self.signing_trust == "FIXTURE_KEY_ONLY"
            && !self.independent_evidence_eligible
            && !self.transaction_gate_eligible
            && !self.release_gate_eligible
            && self.chain_reverified
            && self.canonical_observation_blake3
                == format!("blake3:{}", Digest::of(&canonical).to_hex())
            && self.observer_key.issuer == OBSERVER_ISSUER
            && self.observer_key.key_id == OBSERVER_KEY_ID
            && self.signed.issuer == OBSERVER_ISSUER
            && self.signed.key_id == OBSERVER_KEY_ID
            && subject.candidate_id == candidate
            && subject.proof_bundle_id == proof_bundle_id
            && subject.proof_root == proof_root
            && subject.integration_subject_id == integration_subject_id
            && subject.target == target
            && subject.previous_oid == previous_oid
            && subject.integrated_oid == integrated_oid
            && subject.check_sha == integrated_oid
            && subject.check_name == check_name
            && subject.check_proof_root == proof_root
            && record.outcome == ObservationOutcomeV1::Matched
            && record.observed_oid.as_deref() == Some(integrated_oid)
            && record.readback_reason_code.is_none()
            && record.integration_survived
            && !record.independent_evidence_eligible
            && !record.transaction_gate_eligible
            && !record.release_gate_eligible
            && record.observer_service_id == self.observer_key.issuer
            && record.observer_key_id == self.observer_key.key_id;
        exact
            .then_some(())
            .ok_or_else(|| fail("signed Observation differs from integrated selected Candidate"))
    }
}

/// Read the target through the forge port, sign the derived result, and
/// reconstruct admission from only the retained public subject.
pub(super) fn observe_integration<F: ForgeIntegration>(
    forge: &F,
    candidate_id: &str,
    proof_bundle_id: &str,
    proof_root: &str,
    receipt: &IntegrationReceipt,
) -> Result<SignedObservationClosure, String> {
    let candidate = CandidateId::parse(candidate_id).map_err(|error| fail(error.to_string()))?;
    let subject =
        ObservationSubjectV1::from_integration(candidate, proof_bundle_id, proof_root, receipt)
            .map_err(|error| fail(error.to_string()))?;
    let signer = FixtureObserverSigningKey::generate(OBSERVER_ISSUER, OBSERVER_KEY_ID)
        .map_err(|error| fail(error.to_string()))?;
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| fail("fixture observation time is before the Unix epoch"))?;
    let signed = signer
        .observe(
            forge,
            ObservationInputV1 {
                subject: subject.clone(),
                freshness_window_ms: 60_000,
            },
            now,
        )
        .map_err(|error| fail(error.to_string()))?;
    if signed.record.outcome != ObservationOutcomeV1::Matched || !signed.record.integration_survived
    {
        return Err(fail(format!(
            "signed target observation is non-green: {:?}",
            signed.record.outcome
        )));
    }

    let canonical =
        canonical_observation_bytes(&signed).map_err(|error| fail(error.to_string()))?;
    let public = signer.verification_key();
    let rebuilt = FixtureObserverVerificationKey::from_public_hex(
        OBSERVER_ISSUER,
        OBSERVER_KEY_ID,
        public.public_hex(),
    )
    .map_err(|error| fail(error.to_string()))?;
    let verified = decode_and_verify_fixture_observation(&canonical, &rebuilt, &subject, now)
        .map_err(|error| fail(error.to_string()))?;
    let chain_reverified = verified == signed;
    if !chain_reverified {
        return Err(fail(
            "signed Observation changed after retained-key verification",
        ));
    }

    Ok(SignedObservationClosure {
        signing_trust: "FIXTURE_KEY_ONLY".into(),
        independent_evidence_eligible: false,
        transaction_gate_eligible: false,
        release_gate_eligible: false,
        chain_reverified,
        canonical_observation_blake3: format!("blake3:{}", Digest::of(&canonical).to_hex()),
        observer_key: PublicKeySubject {
            issuer: OBSERVER_ISSUER.into(),
            key_id: OBSERVER_KEY_ID.into(),
            public_hex: public.public_hex().into(),
        },
        signed,
    })
}
