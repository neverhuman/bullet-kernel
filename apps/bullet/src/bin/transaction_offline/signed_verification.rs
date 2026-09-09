//! Fixture-key signed verification records consumed by the offline bridge.
//! The external fixture and the in-process signed executor are deliberately
//! separate component observations; neither proves OS-identity independence.

use super::support::{fail, run_verifier};
use bullet_domain::{gate_definition, CandidateId, Digest, GateOutcome, REPOSITORY_GATE_ID};
use bullet_verifier_core::signed_chain::{
    canonical_chain_bytes, decode_and_verify_fixture_chain, FixtureVerifierSigningKey,
    FixtureVerifierVerificationKey, SignedVerificationChainV1, VerificationIntentInputV1,
    VerificationIntentSigningKey, VerificationIntentVerificationKey,
};
use bullet_verifier_core::{GateId, VerifierRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

const INTENT_ISSUER: &str = "bullet-kernel";
const INTENT_KEY_ID: &str = "verification-intent-fixture-1";
const VERIFIER_ISSUER: &str = "bullet-verifier";
const VERIFIER_KEY_ID: &str = "verifier-fixture-1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeySubject {
    issuer: String,
    key_id: String,
    public_hex: String,
}

impl PublicKeySubject {
    fn intent(key: &VerificationIntentVerificationKey) -> Self {
        Self {
            issuer: key.issuer().into(),
            key_id: key.key_id().into(),
            public_hex: key.public_hex().into(),
        }
    }

    fn verifier(key: &FixtureVerifierVerificationKey) -> Self {
        Self {
            issuer: key.issuer().into(),
            key_id: key.key_id().into(),
            public_hex: key.public_hex().into(),
        }
    }
}

/// Signed component truth retained in the outer unsigned receipt.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedVerificationClosure {
    pub(super) verifier_outcome: String,
    pub(super) writer_proof_refused: bool,
    signing_trust: String,
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    chain_reverified: bool,
    canonical_chain_blake3: String,
    intent_key: PublicKeySubject,
    verifier_key: PublicKeySubject,
    chain: SignedVerificationChainV1,
}

impl SignedVerificationClosure {
    pub(super) fn proof_bundle_id(&self) -> &str {
        &self.chain.proof_bundle.record.proof_bundle_id
    }

    pub(super) fn proof_root(&self) -> &str {
        &self.chain.proof_bundle.record.proof_root
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_selected(
        &self,
        candidate_id: &str,
        workspace: &Path,
        base: &str,
        head: &str,
        tree: &str,
        author_attempt_id: &str,
        policy_digest: &str,
    ) -> Result<(), String> {
        let candidate =
            CandidateId::parse(candidate_id).map_err(|error| fail(error.to_string()))?;
        let request = VerifierRequest {
            workspace_repo_path: workspace.display().to_string(),
            base_sha: base.into(),
            head_sha: head.into(),
            tree_sha: tree.into(),
            gate_id: GateId::parse(REPOSITORY_GATE_ID).map_err(|error| fail(error.to_string()))?,
            author_attempt_id: author_attempt_id.into(),
        };
        let intent_key = VerificationIntentVerificationKey::from_public_hex(
            &self.intent_key.issuer,
            &self.intent_key.key_id,
            &self.intent_key.public_hex,
        )
        .map_err(|error| fail(error.to_string()))?;
        let verifier_key = FixtureVerifierVerificationKey::from_public_hex(
            &self.verifier_key.issuer,
            &self.verifier_key.key_id,
            &self.verifier_key.public_hex,
        )
        .map_err(|error| fail(error.to_string()))?;
        let canonical =
            canonical_chain_bytes(&self.chain).map_err(|error| fail(error.to_string()))?;
        let issued = self.chain.intent.record.issued_at_unix_ms;
        let verified = decode_and_verify_fixture_chain(
            &canonical,
            &intent_key,
            &verifier_key,
            &candidate,
            &request,
            issued,
        )
        .map_err(|error| fail(error.to_string()))?;
        let intent = &self.chain.intent.record;
        let evidence = &self.chain.evidence.record;
        let proof = &self.chain.proof_bundle.record;
        let exact = verified == self.chain
            && self.verifier_outcome == "PASS"
            && self.writer_proof_refused
            && self.signing_trust == "FIXTURE_KEY_ONLY"
            && !self.independent_evidence_eligible
            && !self.transaction_gate_eligible
            && self.chain_reverified
            && self.canonical_chain_blake3 == format!("blake3:{}", Digest::of(&canonical).to_hex())
            && self.intent_key.issuer == INTENT_ISSUER
            && self.intent_key.key_id == INTENT_KEY_ID
            && self.verifier_key.issuer == VERIFIER_ISSUER
            && self.verifier_key.key_id == VERIFIER_KEY_ID
            && self.chain.intent.issuer == INTENT_ISSUER
            && self.chain.intent.key_id == INTENT_KEY_ID
            && self.chain.evidence.issuer == VERIFIER_ISSUER
            && self.chain.evidence.key_id == VERIFIER_KEY_ID
            && self.chain.proof_bundle.issuer == VERIFIER_ISSUER
            && self.chain.proof_bundle.key_id == VERIFIER_KEY_ID
            && intent.candidate_id == candidate
            && intent.request == request
            && intent.verifier_service_id == VERIFIER_ISSUER
            && intent.verifier_key_id == VERIFIER_KEY_ID
            && intent.policy_digest == policy_digest
            && intent.gate_spec_digest == gate_spec_digest()?
            && !intent.independent_evidence_eligible
            && !intent.transaction_gate_eligible
            && evidence.candidate_id == candidate
            && evidence.intent_id == intent.intent_id
            && evidence.request_digest == intent.request_digest
            && evidence.verifier_service_id == VERIFIER_ISSUER
            && evidence.verifier_key_id == VERIFIER_KEY_ID
            && !evidence.independent_evidence_eligible
            && !evidence.transaction_gate_eligible
            && evidence.record.outcome == GateOutcome::Pass
            && proof.candidate_id == candidate
            && proof.intent_id == intent.intent_id
            && proof.evidence_id == evidence.evidence_id
            && proof.request_digest == intent.request_digest
            && proof.verifier_service_id == VERIFIER_ISSUER
            && proof.verifier_key_id == VERIFIER_KEY_ID
            && proof.proof_root.starts_with("prf_")
            && proof.outcome == GateOutcome::Pass
            && !proof.independent_evidence_eligible
            && !proof.transaction_gate_eligible;
        exact
            .then_some(())
            .ok_or_else(|| fail("signed verification closure differs from selected Candidate"))
    }
}

/// Run the sealed external fixture, then independently exercise the signed
/// component record chain against the same immutable Candidate subjects.
pub(super) async fn verify_candidate(
    candidate_id: &str,
    workspace: &Path,
    base: &str,
    head: &str,
    tree: &str,
    author_attempt_id: &str,
    policy_digest: &str,
) -> Result<SignedVerificationClosure, String> {
    let (writer_code, writer_body) =
        run_verifier(workspace, base, head, tree, author_attempt_id, true)?;
    let writer_proof_refused = writer_code != 0
        && writer_body
            .get("reason_code")
            .and_then(Value::as_str)
            .is_some_and(|code| code == "VERIFIER_IS_AUTHOR");
    if !writer_proof_refused {
        return Err(fail(format!("writer proof was not refused: {writer_body}")));
    }
    let (verifier_code, verifier_body) =
        run_verifier(workspace, base, head, tree, author_attempt_id, false)?;
    let verifier_outcome = verifier_body
        .get("outcome")
        .or_else(|| verifier_body.get("result"))
        .and_then(Value::as_str)
        .unwrap_or(if verifier_code == 0 { "PASS" } else { "FAIL" })
        .to_owned();
    if verifier_outcome != "PASS" {
        return Err(fail(format!(
            "external verifier fixture did not pass: {verifier_outcome}: {verifier_body}"
        )));
    }

    let candidate_id = CandidateId::parse(candidate_id).map_err(|error| fail(error.to_string()))?;
    let gate_id = GateId::parse(REPOSITORY_GATE_ID).map_err(|error| fail(error.to_string()))?;
    let request = VerifierRequest {
        workspace_repo_path: workspace.display().to_string(),
        base_sha: base.into(),
        head_sha: head.into(),
        tree_sha: tree.into(),
        gate_id,
        author_attempt_id: author_attempt_id.into(),
    };
    let intent_signing = VerificationIntentSigningKey::generate(INTENT_ISSUER, INTENT_KEY_ID)
        .map_err(|error| fail(error.to_string()))?;
    let verifier_signing = FixtureVerifierSigningKey::generate(VERIFIER_ISSUER, VERIFIER_KEY_ID)
        .map_err(|error| fail(error.to_string()))?;
    let intent_key = intent_signing.verification_key();
    let verifier_key = verifier_signing.verification_key();
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| fail("fixture signing time is before the Unix epoch"))?;
    let expires = now
        .checked_add(60_000)
        .ok_or_else(|| fail("fixture signing time overflow"))?;
    let signed_intent = intent_signing
        .issue(VerificationIntentInputV1 {
            candidate_id: candidate_id.clone(),
            request: request.clone(),
            verifier_service_id: VERIFIER_ISSUER.into(),
            verifier_key_id: VERIFIER_KEY_ID.into(),
            intent_nonce: typed_digest(
                "non",
                "offline-verification-nonce-v1",
                candidate_id.as_str(),
            ),
            policy_digest: policy_digest.into(),
            gate_spec_digest: gate_spec_digest()?,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires,
        })
        .map_err(|error| fail(error.to_string()))?;
    let chain = verifier_signing
        .execute_chain(signed_intent, &intent_key, now, false)
        .await
        .map_err(|error| fail(error.to_string()))?;
    if chain.evidence.record.record.outcome != GateOutcome::Pass
        || chain.proof_bundle.record.outcome != GateOutcome::Pass
    {
        return Err(fail("signed fixture chain did not retain PASS"));
    }
    let canonical = canonical_chain_bytes(&chain).map_err(|error| fail(error.to_string()))?;
    let retained_intent_key = VerificationIntentVerificationKey::from_public_hex(
        intent_key.issuer(),
        intent_key.key_id(),
        intent_key.public_hex(),
    )
    .map_err(|error| fail(error.to_string()))?;
    let retained_verifier_key = FixtureVerifierVerificationKey::from_public_hex(
        verifier_key.issuer(),
        verifier_key.key_id(),
        verifier_key.public_hex(),
    )
    .map_err(|error| fail(error.to_string()))?;
    let verified = decode_and_verify_fixture_chain(
        &canonical,
        &retained_intent_key,
        &retained_verifier_key,
        &candidate_id,
        &request,
        now,
    )
    .map_err(|error| fail(error.to_string()))?;
    let chain_reverified = verified == chain;
    if !chain_reverified {
        return Err(fail(
            "signed fixture chain changed after retained-key verification",
        ));
    }

    Ok(SignedVerificationClosure {
        verifier_outcome,
        writer_proof_refused,
        signing_trust: "FIXTURE_KEY_ONLY".into(),
        independent_evidence_eligible: false,
        transaction_gate_eligible: false,
        chain_reverified,
        canonical_chain_blake3: format!("blake3:{}", Digest::of(&canonical).to_hex()),
        intent_key: PublicKeySubject::intent(&intent_key),
        verifier_key: PublicKeySubject::verifier(&verifier_key),
        chain,
    })
}

fn typed_digest(prefix: &str, domain: &str, subject: &str) -> String {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    bytes.extend_from_slice(subject.as_bytes());
    format!("{prefix}_{}", Digest::of(&bytes).to_hex())
}

fn gate_spec_digest() -> Result<String, String> {
    let gate = gate_definition(
        &GateId::parse(REPOSITORY_GATE_ID).map_err(|error| fail(error.to_string()))?,
    )
    .ok_or_else(|| fail("repository gate is absent from the immutable catalog"))?;
    let mut bytes = b"bullet.gate-spec.v1\0".to_vec();
    for argument in gate.argv() {
        bytes.extend_from_slice(&(argument.len() as u64).to_be_bytes());
        bytes.extend_from_slice(argument.as_bytes());
    }
    bytes.extend_from_slice(&gate.timeout_secs().to_be_bytes());
    Ok(Digest::of(&bytes).to_hex())
}
