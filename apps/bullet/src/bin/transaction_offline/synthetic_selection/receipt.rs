//! Closed, hard-false component receipt for one blinded synthetic selection.

use super::selector::{
    blinded_view, select_exact_pair, unblinding_digest, BlindedCandidateView, SelectionDecision,
};
use super::{fail, fault, LaneRun};
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{LeaseSettlementOutcome, LeaseSettlementRequest};
use bullet_application::Ledger;
use bullet_domain::{AttemptState, Digest, WorkPackageId, REPOSITORY_GATE_ID};
use bullet_harness_core::launch_grant::{
    canonical_json, decode_canonical, fill_random, hash_canonical, hash_framed_bytes,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "bullet.synthetic-selection-receipt.component.v1";
const BODY_DOMAIN: &str = "bullet.synthetic-selection-receipt.body.v1";
const MAX_ARTIFACT_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: String,
    body_digest: String,
    body: Body,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    evidence_class: String,
    signing_trust: String,
    execution_schedule: String,
    simulator: Simulator,
    shared: Shared,
    selection: Selection,
    lanes: Vec<LaneReceipt>,
    eligibility: Eligibility,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Simulator {
    provider: String,
    version: String,
    live_credentials_used: bool,
    external_effects: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Shared {
    plan_digest: String,
    mission_id: String,
    plan_revision_id: String,
    repository_id: String,
    work_package_id: String,
    selection_group_id: String,
    base_oid: String,
    scope_paths: Vec<String>,
    gate_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    decision: SelectionDecision,
    input_digest: String,
    blinded_views: Vec<BlindedCandidateView>,
    selected_candidate_id: String,
    revealed_run_salt: String,
    unblinding: Vec<Unblinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Unblinding {
    blinded_handle: String,
    candidate_id: String,
    binding_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaneReceipt {
    runner_id: String,
    runner_epoch: u64,
    variant_id: String,
    attempt_id: String,
    attempt_fence: u64,
    workspace_id: String,
    authority_digest: String,
    candidate_id: String,
    candidate_base_oid: String,
    candidate_head_oid: String,
    candidate_tree_oid: String,
    candidate_patch_blake3: String,
    candidate_row_digest: String,
    repository_relative: String,
    raw_artifact_relative: String,
    raw_artifact_blake3: String,
    journal_relative: String,
    journal_blake3: String,
    recovery_relative: String,
    recovery_blake3: String,
    acquire_request_digest: String,
    settlement_id: String,
    settlement_request_digest: String,
    terminal_state: String,
    requeue: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Eligibility {
    team_recipe_eligible: bool,
    evolution_profile_eligible: bool,
    provider_certification_eligible: bool,
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    release_gate_eligible: bool,
    live_eligible: bool,
    routing_activation_eligible: bool,
    comparative_claim_eligible: bool,
}

pub(super) fn require_distinct(a: &LaneRun, b: &LaneRun) -> Result<(), String> {
    let distinct = a.registration.runner_id != b.registration.runner_id
        && a.variant_id != b.variant_id
        && a.grant.attempt.id != b.grant.attempt.id
        && a.grant.attempt.workspace_id != b.grant.attempt.workspace_id
        && a.barrier.candidate.id != b.barrier.candidate.id
        && a.workspace_root != b.workspace_root
        && a.recovery_file != b.recovery_file
        && a.barrier.raw_artifact != b.barrier.raw_artifact
        && a.barrier.repository != b.barrier.repository;
    distinct
        .then_some(())
        .ok_or_else(|| fail("synthetic lanes are not fully isolated"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create(
    receipt_path: &Path,
    database: &Path,
    artifacts: &Path,
    plan_digest: Digest,
    package: &WorkPackageId,
    base: &str,
    lanes: [&LaneRun; 2],
) -> Result<Vec<u8>, String> {
    require_distinct(lanes[0], lanes[1])?;
    require_shared(lanes, package, base)?;
    let proof_root = receipt_path
        .parent()
        .ok_or_else(|| fail("selection receipt has no proof root"))?;
    let lane_receipts = vec![
        rederive_lane(database, artifacts, proof_root, lanes[0])?,
        rederive_lane(database, artifacts, proof_root, lanes[1])?,
    ];
    let mut run_salt = [0_u8; 32];
    fill_random(&mut run_salt).map_err(|error| fail(format!("selection salt: {error}")))?;
    let views = [view(&run_salt, lanes[0])?, view(&run_salt, lanes[1])?];
    let decision = select_exact_pair(views.clone()).map_err(fail)?;
    let mut blinded_views = views.to_vec();
    blinded_views.sort_by(|a, b| a.blinded_handle.cmp(&b.blinded_handle));
    let input_digest = hash_canonical("bullet.synthetic-selection.input.v1", &blinded_views)
        .map_err(|error| fail(format!("selection input digest: {error}")))?;
    let mut unblinding = lanes
        .iter()
        .zip(views.iter())
        .map(|(lane, view)| {
            let candidate_id = lane.barrier.candidate.id.to_string();
            Ok(Unblinding {
                blinded_handle: view.blinded_handle.clone(),
                binding_digest: unblinding_digest(&run_salt, &view.blinded_handle, &candidate_id)
                    .map_err(fail)?,
                candidate_id,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    unblinding.sort_by(|a, b| a.blinded_handle.cmp(&b.blinded_handle));
    let selected_candidate_id = unblinding
        .iter()
        .find(|item| item.blinded_handle == decision.selected_handle)
        .map(|item| item.candidate_id.clone())
        .ok_or_else(|| fail("selected blinded handle cannot be unblinded"))?;
    let authority = &lanes[0].grant.authority_token;
    let body = Body {
        evidence_class: "COMPONENT_PROOF".into(),
        signing_trust: "UNSIGNED_FIXTURE".into(),
        execution_schedule: "SEQUENTIAL".into(),
        simulator: Simulator {
            provider: "sim".into(),
            version: bullet_harness_sim::SIM_VERSION.into(),
            live_credentials_used: false,
            external_effects: false,
        },
        shared: Shared {
            plan_digest: plan_digest.to_hex(),
            mission_id: authority.mission_id.to_string(),
            plan_revision_id: authority.plan_revision_id.to_string(),
            repository_id: authority.repository_id.to_string(),
            work_package_id: package.to_string(),
            selection_group_id: authority.selection_group_id.to_string(),
            base_oid: base.into(),
            scope_paths: vec!["PONG.txt".into()],
            gate_ids: vec![REPOSITORY_GATE_ID.into()],
        },
        selection: Selection {
            decision,
            input_digest,
            blinded_views,
            selected_candidate_id,
            revealed_run_salt: lower_hex(&run_salt),
            unblinding,
        },
        lanes: lane_receipts,
        eligibility: Eligibility::none(),
    };
    body.validate()?;
    let body_bytes = canonical_json(&body)
        .map_err(|error| fail(format!("canonical selection receipt body: {error}")))?;
    let envelope = Envelope {
        schema_version: SCHEMA.into(),
        body_digest: hash_framed_bytes(BODY_DOMAIN, &body_bytes)
            .map_err(|error| fail(format!("selection receipt body digest: {error}")))?,
        body,
    };
    let bytes = canonical_json(&envelope)
        .map_err(|error| fail(format!("canonical selection receipt: {error}")))?;
    if fault::before_receipt() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_BEFORE_RECEIPT"));
    }
    let created = super::receipt_storage::create_once(receipt_path, &bytes)?;
    let reopened = super::receipt_storage::reopen_exact(receipt_path, &bytes)?;
    if created != bytes
        || reopened != bytes
        || decode_canonical::<Envelope>(&reopened).map_err(|error| fail(error.to_string()))?
            != envelope
    {
        return Err(fail("durable selection receipt readback differs"));
    }
    Ok(reopened)
}

fn view(run_salt: &[u8; 32], lane: &LaneRun) -> Result<BlindedCandidateView, String> {
    let candidate = &lane.barrier.candidate;
    blinded_view(
        run_salt,
        candidate.id.as_str(),
        candidate.base_sha.clone(),
        candidate.head_sha.clone(),
        candidate.tree_sha.clone(),
        candidate.patch_digest.to_hex(),
        vec![REPOSITORY_GATE_ID.into()],
        true,
    )
}

fn require_shared(lanes: [&LaneRun; 2], package: &WorkPackageId, base: &str) -> Result<(), String> {
    let first = &lanes[0].grant.authority_token;
    let second = &lanes[1].grant.authority_token;
    let shared = first.work_package_id == *package
        && second.work_package_id == *package
        && first.mission_id == second.mission_id
        && first.plan_revision_id == second.plan_revision_id
        && first.repository_id == second.repository_id
        && first.selection_group_id == second.selection_group_id
        && lanes
            .iter()
            .all(|lane| lane.barrier.candidate.base_sha == base);
    shared
        .then_some(())
        .ok_or_else(|| fail("synthetic selection shared subjects differ"))
}

fn rederive_lane(
    database: &Path,
    artifacts: &Path,
    proof_root: &Path,
    lane: &LaneRun,
) -> Result<LaneReceipt, String> {
    let candidate = &lane.barrier.candidate;
    let mut ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen selection ledger: {error}")))?;
    if ledger
        .get_candidate(&candidate.id)
        .map_err(|error| fail(format!("read selection Candidate: {error}")))?
        .as_ref()
        != Some(candidate)
    {
        return Err(fail("selection Candidate durable row differs"));
    }
    let attempt = ledger
        .get_attempt(&lane.grant.attempt.id)
        .map_err(|error| fail(format!("read selection Attempt: {error}")))?
        .ok_or_else(|| fail("selection Attempt disappeared"))?;
    if attempt.state != AttemptState::Superseded
        || ledger
            .get_lease(&lane.variant_id)
            .map_err(|error| fail(format!("read selection lease: {error}")))?
            .is_some()
    {
        return Err(fail("selection lane is not durably terminal"));
    }
    let settlement = ledger
        .with_lease_transport(|transaction| {
            transaction.get_transport_settlement(&lane.barrier.settlement_id)
        })
        .map_err(|error| fail(format!("read selection settlement: {error}")))?
        .ok_or_else(|| fail("selection settlement disappeared"))?;
    let LeaseSettlementRequest::Release(release) = &settlement.request else {
        return Err(fail("selection settlement is not release"));
    };
    let released = matches!(
        &settlement.outcome,
        LeaseSettlementOutcome::Released(value)
            if value.id == lane.grant.attempt.id && value.state == AttemptState::Superseded
    );
    if !released || !release.requeue || release.final_state != AttemptState::Superseded {
        return Err(fail("selection settlement terminal truth differs"));
    }
    let raw = super::private_artifact::read(
        &lane.barrier.raw_artifact,
        MAX_ARTIFACT_BYTES,
        "raw artifact",
    )?;
    if Digest::of(&raw).to_hex() != lane.barrier.raw_digest {
        return Err(fail("selection raw artifact digest differs"));
    }
    let journal_path = lane.workspace_root.join("lane-journal.jsonl");
    let journal = super::private_artifact::read(&journal_path, MAX_ARTIFACT_BYTES, "lane journal")?;
    let recovery =
        super::private_artifact::read(&lane.recovery_file, MAX_ARTIFACT_BYTES, "recovery record")?;
    Ok(LaneReceipt {
        runner_id: lane.registration.runner_id.to_string(),
        runner_epoch: lane.registration.runner_epoch,
        variant_id: lane.variant_id.to_string(),
        attempt_id: lane.grant.attempt.id.to_string(),
        attempt_fence: lane.grant.attempt.fence,
        workspace_id: lane.grant.attempt.workspace_id.to_string(),
        authority_digest: lane
            .grant
            .authority_token
            .digest()
            .map_err(|error| fail(format!("authority digest: {error}")))?
            .to_hex(),
        candidate_id: candidate.id.to_string(),
        candidate_base_oid: candidate.base_sha.clone(),
        candidate_head_oid: candidate.head_sha.clone(),
        candidate_tree_oid: candidate.tree_sha.clone(),
        candidate_patch_blake3: candidate.patch_digest.to_hex(),
        candidate_row_digest: hash_canonical(
            "bullet.synthetic-selection.candidate-row.v1",
            candidate,
        )
        .map_err(|error| fail(format!("Candidate row digest: {error}")))?,
        repository_relative: relative(artifacts, &lane.barrier.repository, "repository")?,
        raw_artifact_relative: relative(artifacts, &lane.barrier.raw_artifact, "raw artifact")?,
        raw_artifact_blake3: lane.barrier.raw_digest.clone(),
        journal_relative: relative(artifacts, &journal_path, "journal")?,
        journal_blake3: Digest::of(&journal).to_hex(),
        recovery_relative: relative(proof_root, &lane.recovery_file, "recovery")?,
        recovery_blake3: Digest::of(&recovery).to_hex(),
        acquire_request_digest: release.acquire_request_digest.clone(),
        settlement_id: settlement.settlement_id.clone(),
        settlement_request_digest: settlement.request_digest.clone(),
        terminal_state: "Superseded".into(),
        requeue: true,
    })
}

fn relative(root: &Path, path: &Path, label: &str) -> Result<String, String> {
    let value = path
        .strip_prefix(root)
        .map_err(|_| fail(format!("selection {label} escapes custody")))?;
    let text = value
        .to_str()
        .filter(|text| !text.is_empty() && !text.starts_with('/') && !text.contains(".."))
        .ok_or_else(|| fail(format!("selection {label} relative path is invalid")))?;
    Ok(text.into())
}

impl Eligibility {
    const fn none() -> Self {
        Self {
            team_recipe_eligible: false,
            evolution_profile_eligible: false,
            provider_certification_eligible: false,
            independent_evidence_eligible: false,
            transaction_gate_eligible: false,
            release_gate_eligible: false,
            live_eligible: false,
            routing_activation_eligible: false,
            comparative_claim_eligible: false,
        }
    }

    const fn all_false(&self) -> bool {
        !self.team_recipe_eligible
            && !self.evolution_profile_eligible
            && !self.provider_certification_eligible
            && !self.independent_evidence_eligible
            && !self.transaction_gate_eligible
            && !self.release_gate_eligible
            && !self.live_eligible
            && !self.routing_activation_eligible
            && !self.comparative_claim_eligible
    }
}

impl Body {
    fn validate(&self) -> Result<(), String> {
        let fixed = self.evidence_class == "COMPONENT_PROOF"
            && self.signing_trust == "UNSIGNED_FIXTURE"
            && self.execution_schedule == "SEQUENTIAL"
            && self.simulator.provider == "sim"
            && self.simulator.version == bullet_harness_sim::SIM_VERSION
            && !self.simulator.live_credentials_used
            && !self.simulator.external_effects
            && self.lanes.len() == 2
            && self.selection.blinded_views.len() == 2
            && self.selection.unblinding.len() == 2
            && self.eligibility.all_false();
        fixed
            .then_some(())
            .ok_or_else(|| fail("selection receipt classification is not hard-false component"))
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_higher_eligibility_is_hard_false() {
        assert!(Eligibility::none().all_false());
        let value = serde_json::to_value(Eligibility::none()).expect("eligibility");
        assert_eq!(value.as_object().expect("object").len(), 9);
        assert!(value
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == false));
    }
}
