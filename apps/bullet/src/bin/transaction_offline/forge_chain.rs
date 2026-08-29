//! Exact local check, protected integration, and restart read-back for the
//! offline component bridge.

use bullet_domain::Digest;
use bullet_effects_core::{
    CheckPublication, ForgeEffects, ForgeIntegration, IntegrationSubjectRequest, LocalBareForge,
    LostResponseForge, ProtectedIntegrationRequest, ZERO_OID,
};
use serde::{Deserialize, Serialize};
use std::process::Command;

use super::chaos::{self, Boundary};
use super::signed_observation::{observe_integration, SignedObservationClosure};
use super::support::{fail, strip_oid};

const TARGET: &str = "refs/heads/main";
const CHECK_NAME: &str = "bullet/offline-component-proof";

/// Exact local forge subjects observed after delivery and again after reopen.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalForgeClosure {
    pub(super) delivered_oid: String,
    pub(super) effect_candidate_bound: bool,
    proof_root: String,
    check_name: String,
    check_sha: String,
    check_readback_matches: bool,
    integration_subject_id: String,
    integration_previous_oid: String,
    integration_oid: String,
    observation_target_oid: String,
    restart_readback_matches: bool,
    signed_observation: SignedObservationClosure,
}

impl LocalForgeClosure {
    pub(super) fn validate_selected(
        &self,
        candidate_id: &str,
        base: &str,
        head: &str,
        proof_bundle_id: &str,
        proof_root: &str,
    ) -> Result<(), String> {
        self.signed_observation.validate_selected(
            candidate_id,
            proof_bundle_id,
            proof_root,
            &self.integration_subject_id,
            TARGET,
            base,
            head,
            CHECK_NAME,
        )?;
        let exact = self.delivered_oid == head
            && self.effect_candidate_bound
            && self.proof_root == proof_root
            && self.check_name == CHECK_NAME
            && self.check_sha == head
            && self.check_readback_matches
            && self.integration_subject_id == integration_subject_id(base, head, TARGET)
            && self.integration_previous_oid == base
            && self.integration_oid == head
            && self.observation_target_oid == head
            && self.restart_readback_matches;
        exact
            .then_some(())
            .ok_or_else(|| fail("local forge closure differs from selected Candidate proof"))
    }
}

fn integration_subject_id(base: &str, head: &str, target: &str) -> String {
    let mut bytes = b"bullet-local-integration-subject-v1".to_vec();
    for part in [base, head, target] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    format!("ins_{}", Digest::of(&bytes).to_hex())
}

/// Close the local component chain after the delivery response-loss fault has
/// settled. Initializing `main` is fixture setup, not an integration effect.
pub(super) fn close_local_forge(
    lossy: LostResponseForge<LocalBareForge>,
    candidate_ref: &str,
    candidate_id: &str,
    tagged_base: &str,
    tagged_head: &str,
    verification_proof_bundle_id: &str,
    verification_proof_root: &str,
) -> Result<LocalForgeClosure, String> {
    let mut forge = lossy
        .into_inner()
        .map_err(|error| fail(error.to_string()))?;
    let base = strip_oid(tagged_base);
    let head = strip_oid(tagged_head);
    let delivered_oid = forge
        .read_ref(candidate_ref)
        .map_err(|error| fail(format!("read back exact Candidate delivery: {error}")))?
        .ok_or_else(|| fail("Candidate delivery ref is absent after reconciliation"))?;
    let effect_candidate_bound = delivered_oid == head;
    if !effect_candidate_bound {
        return Err(fail(
            "delivered effect OID differs from the verified Candidate head",
        ));
    }

    seed_fixture_target(&forge, base)?;
    let proof_root = verification_proof_root.to_owned();
    let protection = forge
        .protect_target(TARGET, &proof_root)
        .map_err(|error| fail(format!("protect local target: {error}")))?;
    if !protection.protected
        || protection.required_proof_root.as_deref() != Some(proof_root.as_str())
    {
        return Err(fail("local target protection read-back differs"));
    }

    chaos::refuse_if_selected(Boundary::CheckPublication)?;
    let published = forge
        .publish_check(&CheckPublication {
            sha: head.to_owned(),
            name: CHECK_NAME.into(),
            proof_root: proof_root.clone(),
        })
        .map_err(|error| fail(format!("publish exact local check: {error}")))?;
    let check_readback = forge
        .read_check(head, CHECK_NAME)
        .map_err(|error| fail(format!("read exact local check: {error}")))?
        .ok_or_else(|| fail("published local check is absent"))?;
    let check_readback_matches = check_readback == published;
    if !check_readback_matches {
        return Err(fail("published local check differs on read-back"));
    }

    let subject = forge
        .ensure_integration_subject(&IntegrationSubjectRequest {
            base: base.to_owned(),
            head: head.to_owned(),
            target: TARGET.into(),
        })
        .map_err(|error| fail(format!("prepare local integration subject: {error}")))?;
    chaos::refuse_if_selected(Boundary::Integration)?;
    let receipt = forge
        .integrate_protected(&ProtectedIntegrationRequest {
            subject: subject.clone(),
            expected_old_oid: base.to_owned(),
            check_name: CHECK_NAME.into(),
            proof_root: proof_root.clone(),
        })
        .map_err(|error| fail(format!("integrate protected local target: {error}")))?;
    chaos::refuse_if_selected(Boundary::ObservationCleanup)?;
    let signed_observation = observe_integration(
        &forge,
        candidate_id,
        verification_proof_bundle_id,
        &proof_root,
        &receipt,
    )?;
    let observation_target_oid = forge
        .read_target(TARGET)
        .map_err(|error| fail(format!("observe integrated local target: {error}")))?
        .ok_or_else(|| fail("integrated local target is absent"))?;
    if observation_target_oid != head {
        return Err(fail("integrated local target differs from Candidate head"));
    }

    let reopened = LocalBareForge::open(forge.bare_path())
        .map_err(|error| fail(format!("reopen local forge: {error}")))?;
    let restart_target = reopened
        .read_target(TARGET)
        .map_err(|error| fail(format!("read target after restart: {error}")))?;
    let restart_check = reopened
        .read_check(head, CHECK_NAME)
        .map_err(|error| fail(format!("read check after restart: {error}")))?;
    let restart_protection = reopened
        .read_protection(TARGET)
        .map_err(|error| fail(format!("read protection after restart: {error}")))?;
    let restart_readback_matches = restart_target.as_deref() == Some(head)
        && restart_check.as_ref() == Some(&published)
        && restart_protection == protection;
    if !restart_readback_matches {
        return Err(fail("local forge restart read-back differs"));
    }

    Ok(LocalForgeClosure {
        delivered_oid,
        effect_candidate_bound,
        proof_root,
        check_name: CHECK_NAME.into(),
        check_sha: published.sha,
        check_readback_matches,
        integration_subject_id: subject.id,
        integration_previous_oid: receipt.previous_oid,
        integration_oid: receipt.integrated_oid,
        observation_target_oid,
        restart_readback_matches,
        signed_observation,
    })
}

fn seed_fixture_target(forge: &LocalBareForge, base: &str) -> Result<(), String> {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .args([
            "--git-dir",
            &forge.bare_path().display().to_string(),
            "update-ref",
            "--no-deref",
            TARGET,
            base,
            ZERO_OID,
        ])
        .output()
        .map_err(|error| fail(format!("start exact fixture git: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(fail(format!(
        "seed local fixture target: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
