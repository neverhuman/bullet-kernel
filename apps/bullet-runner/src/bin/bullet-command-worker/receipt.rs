//! Strict retained component-receipt admission for public command settlement.

use super::error::{WorkerContext, WorkerError};
use bullet_application::CommandDispatchClaim;
use bullet_domain::{CandidateId, CommandId, Digest, GateOutcome, REPOSITORY_GATE_ID};
use bullet_effects_core::{
    canonical_observation_bytes, decode_and_verify_fixture_observation,
    FixtureObserverVerificationKey, ObservationOutcomeV1, ObservationSubjectV1,
    SignedObservationV1,
};
use bullet_runner_core::CandidatePreservation;
use bullet_verifier_core::{
    decode_and_verify_fixture_chain, FixtureVerifierVerificationKey, SignedVerificationChainV1,
    VerificationIntentVerificationKey,
};
use serde::Deserialize;
use sha2::{Digest as ShaDigest, Sha256};
use std::path::{Path, PathBuf};

#[path = "receipt/artifacts.rs"]
mod artifacts;
#[path = "receipt/bounded_output.rs"]
mod bounded_output;
#[path = "receipt/preservation.rs"]
mod preservation;
#[path = "receipt/provider.rs"]
mod provider;
#[path = "receipt/validation.rs"]
mod validation;

use provider::ProviderExecution;

const TARGET: &str = "refs/heads/main";

#[derive(Debug)]
pub(super) struct AdmittedReceipt {
    raw_sha256: String,
    receipt_digest: Digest,
}

impl AdmittedReceipt {
    pub(super) fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }

    pub(super) const fn receipt_digest(&self) -> Digest {
        self.receipt_digest
    }
}

pub(super) fn admit_receipt(
    path: &Path,
    run_root: &Path,
    claim: &CommandDispatchClaim,
    manifest_sha256: &str,
) -> Result<AdmittedReceipt, WorkerError> {
    admit_inner(
        path,
        run_root,
        claim,
        manifest_sha256,
        Some(artifacts::now_unix_ms()?),
        None,
    )
}

pub(super) fn readback_retained_receipt(
    path: &Path,
    run_root: &Path,
    claim: &CommandDispatchClaim,
    manifest_sha256: &str,
    expected_raw_sha256: &str,
    expected_receipt_digest: Digest,
) -> Result<AdmittedReceipt, WorkerError> {
    admit_inner(
        path,
        run_root,
        claim,
        manifest_sha256,
        None,
        Some((expected_raw_sha256, expected_receipt_digest)),
    )
}

fn admit_inner(
    path: &Path,
    run_root: &Path,
    claim: &CommandDispatchClaim,
    manifest_sha256: &str,
    current_time: Option<u64>,
    expected: Option<(&str, Digest)>,
) -> Result<AdmittedReceipt, WorkerError> {
    claim
        .validate()
        .worker("COMMAND_RECEIPT_INVALID", "validate expected command claim")?;
    let bytes = artifacts::read_receipt(path, run_root)?;
    let admitted = AdmittedReceipt {
        raw_sha256: hex::encode(Sha256::digest(&bytes)),
        receipt_digest: Digest::of(&bytes),
    };
    if expected.is_some_and(|(raw, digest)| {
        raw != admitted.raw_sha256 || digest != admitted.receipt_digest
    }) {
        return Err(invalid(
            "retained receipt hashes differ from durable custody",
        ));
    }
    let receipt: ComponentReceipt = serde_json::from_slice(&bytes)
        .worker("COMMAND_RECEIPT_INVALID", "decode closed component receipt")?;
    let paths = receipt.validate_outer(run_root, claim, manifest_sha256)?;
    receipt.provider_execution.validate(run_root, &receipt)?;
    let verification_time = current_time.unwrap_or(
        receipt
            .signed_verification
            .chain
            .intent
            .record
            .issued_at_unix_ms,
    );
    let observation_time = current_time.unwrap_or(
        receipt
            .local_forge
            .signed_observation
            .signed
            .record
            .observed_at_unix_ms,
    );
    receipt.validate_verification(&paths, verification_time)?;
    receipt.validate_observation_and_artifacts(&paths, observation_time)?;
    Ok(admitted)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentReceipt {
    artifact_custody: ArtifactCustody,
    attempt_first: String,
    attempt_second: String,
    base_oid: String,
    candidate_id: String,
    children: Children,
    command_id: String,
    command_phase: String,
    command_dispatch: DispatchBinding,
    effect_candidate_bound: bool,
    effect_delivered_oid: String,
    effect_settled: String,
    effect_unknown: String,
    evidence_class: String,
    fence_first: u64,
    fence_second: u64,
    gitd_fixture: bool,
    head_oid: String,
    independent_evidence_eligible: bool,
    local_forge: LocalForgeReceipt,
    product_runner_candidate_id: String,
    product_runner_gate_passed: bool,
    product_runner_outcome: String,
    product_runner_preservation: CandidatePreservation,
    provider_execution: ProviderExecution,
    schema_version: String,
    scope_authority_epoch: u64,
    scope_grant_id: String,
    scope_paths_digest: String,
    signed_verification: VerificationClosure,
    signing_trust: String,
    stale_refused: bool,
    transaction_gate_eligible: bool,
    tree_oid: String,
    unknown_then_adopt: bool,
    verifier_outcome: String,
    writer_proof_refused: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactCustody {
    retained: bool,
    artifact_root_relative: String,
    source_repository_relative: String,
    candidate_repository_relative: String,
    local_forge_relative: String,
    ledger_relative: String,
    candidate_id: String,
    base_oid: String,
    head_oid: String,
    tree_oid: String,
    target_ref: String,
    target_oid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Children {
    farmd: String,
    runner: String,
    gitd: String,
    verifier: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchBinding {
    source: String,
    claim_id: Option<String>,
    command_id: Option<String>,
    request_digest: Option<String>,
    runner_id: Option<String>,
    runner_epoch: Option<u64>,
    canonical_claim_blake3: Option<String>,
    binary_manifest_sha256: Option<String>,
    transaction_gate_eligible: bool,
    independent_evidence_eligible: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeySubject {
    issuer: String,
    key_id: String,
    public_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationClosure {
    verifier_outcome: String,
    writer_proof_refused: bool,
    signing_trust: String,
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    chain_reverified: bool,
    canonical_chain_blake3: String,
    intent_key: PublicKeySubject,
    verifier_key: PublicKeySubject,
    chain: SignedVerificationChainV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationClosure {
    signing_trust: String,
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    release_gate_eligible: bool,
    chain_reverified: bool,
    canonical_observation_blake3: String,
    observer_key: PublicKeySubject,
    signed: SignedObservationV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalForgeReceipt {
    delivered_oid: String,
    effect_candidate_bound: bool,
    proof_root: String,
    check_name: String,
    check_sha: String,
    check_readback_matches: bool,
    integration_subject_id: String,
    integration_previous_oid: String,
    integration_oid: String,
    observation_target_oid: String,
    restart_readback_matches: bool,
    signed_observation: ObservationClosure,
}

struct RetainedPaths {
    source: PathBuf,
    candidate: PathBuf,
    forge: PathBuf,
    ledger: PathBuf,
    candidate_id: CandidateId,
}

impl ComponentReceipt {
    fn validate_outer(
        &self,
        run_root: &Path,
        claim: &CommandDispatchClaim,
        manifest: &str,
    ) -> Result<RetainedPaths, WorkerError> {
        let candidate_id = CandidateId::parse(&self.candidate_id).map_err(invalid)?;
        CommandId::parse(&self.command_id).map_err(invalid)?;
        let product_runner_candidate_id =
            CandidateId::parse(&self.product_runner_candidate_id).map_err(invalid)?;
        let fixed = self.schema_version == "v1alpha1"
            && self.evidence_class == "COMPONENT_PROOF"
            && self.signing_trust == "UNSIGNED_FIXTURE"
            && !self.transaction_gate_eligible
            && !self.independent_evidence_eligible
            && !self.gitd_fixture
            && self.unknown_then_adopt
            && self.stale_refused
            && self.command_phase == "pending"
            && self.effect_unknown == "OUTCOME_UNKNOWN"
            && self.effect_settled == "COMMITTED"
            && self.effect_candidate_bound
            && self.verifier_outcome == "PASS"
            && self.writer_proof_refused
            && self.product_runner_gate_passed
            && self.product_runner_outcome == "CANDIDATE_PRESERVED"
            && self.fence_first > 0
            && self.fence_second > 0
            && self.scope_authority_epoch > 0
            && artifacts::full_id(&self.attempt_first, "atm")
            && artifacts::full_id(&self.attempt_second, "atm")
            && self.attempt_second != self.attempt_first
            && artifacts::full_id(&self.scope_grant_id, "sgr")
            && artifacts::lower_hex(&self.scope_paths_digest, 64)
            && artifacts::oid(&self.base_oid)
            && artifacts::oid(&self.head_oid)
            && artifacts::oid(&self.tree_oid)
            && product_runner_candidate_id == candidate_id
            && self.effect_delivered_oid == self.head_oid
            && self.command_id != claim.command_id.as_str()
            && self.children.exact();
        if !fixed {
            return Err(invalid(
                "outer component classification or subject is not admitted",
            ));
        }
        self.command_dispatch.validate_for(claim, manifest)?;
        let paths = self.artifact_custody.paths(run_root, self, candidate_id)?;
        preservation::validate(self, &paths)?;
        Ok(paths)
    }

    fn validate_verification(
        &self,
        paths: &RetainedPaths,
        now_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        let closure = &self.signed_verification;
        let request = &closure.chain.intent.record.request;
        let fixed = closure.verifier_outcome == "PASS"
            && closure.writer_proof_refused
            && closure.signing_trust == "FIXTURE_KEY_ONLY"
            && !closure.independent_evidence_eligible
            && !closure.transaction_gate_eligible
            && closure.chain_reverified
            && request.workspace_repo_path == paths.candidate.display().to_string()
            && request.base_sha == self.base_oid
            && request.head_sha == self.head_oid
            && request.tree_sha == self.tree_oid
            && request.gate_id.as_str() == REPOSITORY_GATE_ID
            && request.author_attempt_id == self.attempt_first
            && closure.chain.intent.record.candidate_id == paths.candidate_id
            && closure.chain.evidence.record.record.outcome == GateOutcome::Pass
            && closure.chain.proof_bundle.record.outcome == GateOutcome::Pass;
        if !fixed {
            return Err(invalid(
                "signed verification closure is non-PASS or off-subject",
            ));
        }
        let intent = VerificationIntentVerificationKey::from_public_hex(
            &closure.intent_key.issuer,
            &closure.intent_key.key_id,
            &closure.intent_key.public_hex,
        )
        .map_err(invalid)?;
        let verifier = FixtureVerifierVerificationKey::from_public_hex(
            &closure.verifier_key.issuer,
            &closure.verifier_key.key_id,
            &closure.verifier_key.public_hex,
        )
        .map_err(invalid)?;
        let canonical = bullet_verifier_core::signed_chain::canonical_chain_bytes(&closure.chain)
            .map_err(invalid)?;
        if closure.canonical_chain_blake3 != artifacts::blake3_label(&canonical) {
            return Err(invalid("verification chain canonical digest differs"));
        }
        decode_and_verify_fixture_chain(
            &canonical,
            &intent,
            &verifier,
            &paths.candidate_id,
            request,
            now_unix_ms,
        )
        .map_err(invalid)?;
        Ok(())
    }

    fn validate_observation_and_artifacts(
        &self,
        paths: &RetainedPaths,
        now_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        let observation = &self.local_forge.signed_observation;
        let signed = &observation.signed;
        let subject = &signed.record.subject;
        let proof = &self.signed_verification.chain.proof_bundle.record;
        let fixed = observation.signing_trust == "FIXTURE_KEY_ONLY"
            && !observation.independent_evidence_eligible
            && !observation.transaction_gate_eligible
            && !observation.release_gate_eligible
            && observation.chain_reverified
            && signed.record.outcome == ObservationOutcomeV1::Matched
            && signed.record.integration_survived
            && signed.record.observed_oid.as_deref() == Some(self.head_oid.as_str())
            && subject.candidate_id == paths.candidate_id
            && subject.proof_bundle_id == proof.proof_bundle_id
            && subject.proof_root == proof.proof_root
            && self.local_forge.matches(self, subject);
        if !fixed {
            return Err(invalid("signed observation is non-MATCHED or off-subject"));
        }
        let key = FixtureObserverVerificationKey::from_public_hex(
            &observation.observer_key.issuer,
            &observation.observer_key.key_id,
            &observation.observer_key.public_hex,
        )
        .map_err(invalid)?;
        let canonical = canonical_observation_bytes(signed).map_err(invalid)?;
        if observation.canonical_observation_blake3 != artifacts::blake3_label(&canonical) {
            return Err(invalid("Observation canonical digest differs"));
        }
        decode_and_verify_fixture_observation(&canonical, &key, subject, now_unix_ms)
            .map_err(invalid)?;
        artifacts::validate_artifacts(paths, self, subject)
    }
}

fn invalid(detail: impl std::fmt::Display) -> WorkerError {
    WorkerError::input("COMMAND_RECEIPT_INVALID", detail.to_string())
}

#[cfg(test)]
#[path = "receipt/tests.rs"]
mod tests;
