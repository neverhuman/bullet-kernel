use super::records::{
    EvidenceV1, ProofBundleV1, SignedEvidenceV1, SignedVerificationIntentV1,
    VerificationIntentInputV1, VerificationIntentV1, COMPONENT_CLASS, EVIDENCE_SCHEMA,
    FIXTURE_TRUST, INTENT_SCHEMA, PROOF_SCHEMA,
};
use super::{invalid, SignedChainError};
use crate::{CandidateSubject, VerifierEvidence, VerifierRequest};
use bullet_domain::{gate_definition, CandidateId, EvidenceTier, GateOutcome};
use bullet_harness_core::launch_grant::{
    hash_canonical, is_lower_hex_64, validate_label, MAX_SAFE_INTEGER,
};
use serde::Serialize;

const MAX_INTENT_TTL_MS: u64 = 60_000;

pub(super) fn validate_input(input: &VerificationIntentInputV1) -> Result<(), SignedChainError> {
    input
        .request
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    validate_label("verifier_service_id", &input.verifier_service_id)
        .map_err(|error| invalid(error.to_string()))?;
    validate_label("verifier_key_id", &input.verifier_key_id)
        .map_err(|error| invalid(error.to_string()))?;
    if !typed_hex(&input.intent_nonce, "non")
        || !is_lower_hex_64(&input.policy_digest)
        || !is_lower_hex_64(&input.gate_spec_digest)
        || input.issued_at_unix_ms > MAX_SAFE_INTEGER
        || input.expires_at_unix_ms > MAX_SAFE_INTEGER
        || input.expires_at_unix_ms <= input.issued_at_unix_ms
        || input.expires_at_unix_ms - input.issued_at_unix_ms > MAX_INTENT_TTL_MS
    {
        return Err(invalid("intent nonce, digest, or time window is invalid"));
    }
    Ok(())
}

pub(super) fn validate_intent(
    intent: &VerificationIntentV1,
    expected: Option<(&CandidateId, &VerifierRequest)>,
    now: u64,
) -> Result<(), SignedChainError> {
    require_markers(
        &intent.schema_version,
        &intent.evidence_class,
        &intent.signing_trust,
        intent.independent_evidence_eligible,
        intent.transaction_gate_eligible,
        INTENT_SCHEMA,
    )?;
    let input = VerificationIntentInputV1 {
        candidate_id: intent.candidate_id.clone(),
        request: intent.request.clone(),
        verifier_service_id: intent.verifier_service_id.clone(),
        verifier_key_id: intent.verifier_key_id.clone(),
        intent_nonce: intent.intent_nonce.clone(),
        policy_digest: intent.policy_digest.clone(),
        gate_spec_digest: intent.gate_spec_digest.clone(),
        issued_at_unix_ms: intent.issued_at_unix_ms,
        expires_at_unix_ms: intent.expires_at_unix_ms,
    };
    validate_input(&input)?;
    if intent.request_digest != digest("verification.request.v1", "req", &intent.request)?
        || intent.intent_id != digest("verification.intent.id.v1", "vfi", &input)?
    {
        return Err(invalid("intent derived digest mismatch"));
    }
    if now < intent.issued_at_unix_ms || now >= intent.expires_at_unix_ms {
        return Err(SignedChainError::IntentTimeInvalid);
    }
    if expected.is_some_and(|(candidate, request)| {
        candidate != &intent.candidate_id || request != &intent.request
    }) {
        return Err(SignedChainError::SubjectMismatch);
    }
    Ok(())
}

pub(super) fn validate_evidence(
    intent: &VerificationIntentV1,
    signed_intent: &SignedVerificationIntentV1,
    evidence: &EvidenceV1,
) -> Result<(), SignedChainError> {
    require_markers(
        &evidence.schema_version,
        &evidence.evidence_class,
        &evidence.signing_trust,
        evidence.independent_evidence_eligible,
        evidence.transaction_gate_eligible,
        EVIDENCE_SCHEMA,
    )?;
    validate_verifier_record(intent, &evidence.record)?;
    let expected_intent_digest = digest("verification.intent.envelope.v1", "vin", signed_intent)?;
    let expected_id = digest(
        "verification.evidence.id.v1",
        "evd",
        &(&expected_intent_digest, &evidence.record),
    )?;
    if evidence.intent_id != intent.intent_id
        || evidence.intent_envelope_digest != expected_intent_digest
        || evidence.evidence_id.as_str() != expected_id
        || evidence.candidate_id != intent.candidate_id
        || evidence.request_digest != intent.request_digest
        || evidence.gate_spec_digest != intent.gate_spec_digest
        || evidence.verifier_service_id != intent.verifier_service_id
        || evidence.verifier_key_id != intent.verifier_key_id
    {
        return Err(SignedChainError::SubjectMismatch);
    }
    Ok(())
}

pub(super) fn validate_proof(
    intent: &VerificationIntentV1,
    signed_intent: &SignedVerificationIntentV1,
    signed_evidence: &SignedEvidenceV1,
    proof: &ProofBundleV1,
) -> Result<(), SignedChainError> {
    require_markers(
        &proof.schema_version,
        &proof.evidence_class,
        &proof.signing_trust,
        proof.independent_evidence_eligible,
        proof.transaction_gate_eligible,
        PROOF_SCHEMA,
    )?;
    let intent_digest = digest("verification.intent.envelope.v1", "vin", signed_intent)?;
    let evidence_digest = digest("verification.evidence.envelope.v1", "ven", signed_evidence)?;
    let proof_root = digest(
        "verification.proof.root.v1",
        "prf",
        &(&intent.request_digest, &evidence_digest),
    )?;
    let proof_id = digest("verification.proof.id.v1", "prb", &proof_root)?;
    if proof.proof_bundle_id != proof_id
        || proof.proof_root != proof_root
        || proof.intent_id != intent.intent_id
        || proof.intent_envelope_digest != intent_digest
        || proof.evidence_id != signed_evidence.record.evidence_id
        || proof.evidence_envelope_digest != evidence_digest
        || proof.candidate_id != intent.candidate_id
        || proof.request_digest != intent.request_digest
        || proof.gate_spec_digest != intent.gate_spec_digest
        || proof.verifier_service_id != intent.verifier_service_id
        || proof.verifier_key_id != intent.verifier_key_id
        || proof.outcome != signed_evidence.record.record.outcome
    {
        return Err(SignedChainError::SubjectMismatch);
    }
    Ok(())
}

pub(super) fn validate_verifier_record(
    intent: &VerificationIntentV1,
    record: &VerifierEvidence,
) -> Result<(), SignedChainError> {
    let expected_subject = CandidateSubject {
        base_sha: intent.request.base_sha.clone(),
        head_sha: intent.request.head_sha.clone(),
        tree_sha: intent.request.tree_sha.clone(),
    };
    let definition = gate_definition(&intent.request.gate_id)
        .ok_or_else(|| invalid("intent gate is not in the immutable catalog"))?;
    if record.subject != expected_subject
        || record.gate_id != intent.request.gate_id
        || record.author_attempt_id != intent.request.author_attempt_id
        || record.produced_by != intent.verifier_service_id
    {
        return Err(SignedChainError::SubjectMismatch);
    }
    if record.tier != EvidenceTier::E2
        || record.argv != definition.argv()
        || record.timeout_secs != definition.timeout_secs()
    {
        return Err(SignedChainError::OutcomeNotAdmissible);
    }
    if record.outcome == GateOutcome::Pass
        && (record.reason.is_some() || record.exit_code != Some(0))
    {
        return Err(SignedChainError::OutcomeNotAdmissible);
    }
    Ok(())
}

fn require_markers(
    schema: &str,
    class: &str,
    trust: &str,
    independent: bool,
    transaction: bool,
    expected_schema: &str,
) -> Result<(), SignedChainError> {
    if schema != expected_schema
        || class != COMPONENT_CLASS
        || trust != FIXTURE_TRUST
        || independent
        || transaction
    {
        return Err(invalid("component eligibility markers cannot be promoted"));
    }
    Ok(())
}

fn typed_hex(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(is_lower_hex_64)
}

pub(super) fn digest<T: Serialize>(
    domain: &str,
    prefix: &str,
    value: &T,
) -> Result<String, SignedChainError> {
    hash_canonical(domain, value)
        .map(|digest| format!("{prefix}_{digest}"))
        .map_err(|error| invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::GateId;
    use std::collections::BTreeMap;

    fn intent() -> VerificationIntentV1 {
        VerificationIntentV1 {
            schema_version: INTENT_SCHEMA.into(),
            evidence_class: COMPONENT_CLASS.into(),
            signing_trust: FIXTURE_TRUST.into(),
            independent_evidence_eligible: false,
            transaction_gate_eligible: false,
            intent_id: format!("vfi_{}", "1".repeat(64)),
            candidate_id: CandidateId::from_seed("candidate"),
            request: VerifierRequest {
                workspace_repo_path: "/tmp/repo".into(),
                base_sha: "a".repeat(40),
                head_sha: "b".repeat(40),
                tree_sha: "c".repeat(40),
                gate_id: GateId::parse(bullet_domain::REPOSITORY_GATE_ID).unwrap(),
                author_attempt_id: format!("atm_{}", "0".repeat(64)),
            },
            request_digest: format!("req_{}", "2".repeat(64)),
            verifier_service_id: "bullet-verifier".into(),
            verifier_key_id: "verifier-fixture-1".into(),
            intent_nonce: format!("non_{}", "3".repeat(64)),
            policy_digest: "4".repeat(64),
            gate_spec_digest: "5".repeat(64),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        }
    }

    fn record(intent: &VerificationIntentV1) -> VerifierEvidence {
        let definition = gate_definition(&intent.request.gate_id).unwrap();
        VerifierEvidence {
            tier: EvidenceTier::E2,
            gate_id: intent.request.gate_id.clone(),
            outcome: GateOutcome::Pass,
            reason: None,
            detail: None,
            argv: definition.argv(),
            timeout_secs: definition.timeout_secs(),
            exit_code: Some(0),
            duration_ms: 1,
            subject: CandidateSubject {
                base_sha: intent.request.base_sha.clone(),
                head_sha: intent.request.head_sha.clone(),
                tree_sha: intent.request.tree_sha.clone(),
            },
            environment: BTreeMap::new(),
            produced_by: intent.verifier_service_id.clone(),
            author_attempt_id: intent.request.author_attempt_id.clone(),
        }
    }

    #[test]
    fn zero_or_skipped_outcome_is_preserved_non_green_and_cannot_be_painted_pass() {
        let intent = intent();
        let mut zero = record(&intent);
        zero.outcome = GateOutcome::NotRun;
        zero.reason = Some(bullet_domain::REASON_ZERO_TESTS.into());
        zero.exit_code = None;
        validate_verifier_record(&intent, &zero).expect("signed non-green evidence is valid");

        let mut painted = zero;
        painted.outcome = GateOutcome::Pass;
        assert_eq!(
            validate_verifier_record(&intent, &painted)
                .unwrap_err()
                .reason_code(),
            "VERIFICATION_OUTCOME_NOT_ADMISSIBLE"
        );

        let mut skipped = record(&intent);
        skipped.reason = Some("ALL_TESTS_SKIPPED".into());
        assert_eq!(
            validate_verifier_record(&intent, &skipped)
                .unwrap_err()
                .reason_code(),
            "VERIFICATION_OUTCOME_NOT_ADMISSIBLE"
        );
    }

    #[test]
    fn subject_change_cannot_reach_proof_signing() {
        let intent = intent();
        let mut record = record(&intent);
        record.subject.head_sha = "d".repeat(40);
        assert_eq!(
            validate_verifier_record(&intent, &record)
                .unwrap_err()
                .reason_code(),
            "VERIFICATION_SUBJECT_MISMATCH"
        );
    }
}
