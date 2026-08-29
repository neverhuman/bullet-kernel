//! Sealed cross-binding from one durable selection receipt to its winning Candidate.

mod origin;
mod validation;

use super::selector::{
    select_exact_pair, unblinding_digest, BlindedCandidateView, SelectionDecision,
    NONQUALITY_TIEBREAK_V1,
};
use super::LaneRun;
use bullet_domain::{Attempt, AuthorityToken, Candidate, Digest, REPOSITORY_GATE_ID};
use bullet_harness_core::launch_grant::{
    canonical_json, decode_canonical, hash_canonical, hash_framed_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "bullet.synthetic-selection.selected-subject.component.v1";
const RECEIPT_SCHEMA: &str = "bullet.synthetic-selection-receipt.component.v1";
const BODY_DOMAIN: &str = "bullet.synthetic-selection-receipt.body.v1";
const RECEIPT_DOMAIN: &str = "bullet.synthetic-selection-receipt.artifact.v1";
const SUBJECT_DOMAIN: &str = "bullet.synthetic-selection.selected-subject.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectedCandidateSubject {
    schema_version: String,
    selection: SelectionSubject,
    shared: SharedSubject,
    author: AuthorSubject,
    candidate: CandidateSubject,
    repository: RepositorySubject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[rustfmt::skip]
struct SelectionSubject {
    receipt_digest: String, body_digest: String, plan_digest: String,
    rubric: String, selected_handle: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[rustfmt::skip]
struct SharedSubject {
    organization_id: String, repository_id: String, mission_id: String,
    acceptance_contract_id: String, plan_revision_id: String, graph_sequence: u64,
    work_package_id: String, selection_group_id: String, base_oid: String,
    gate_ids: Vec<String>, scope_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[rustfmt::skip]
struct AuthorSubject {
    variant_id: String, attempt_id: String, attempt_fence: u64,
    runner_id: String, runner_epoch: u64, workspace_id: String,
    authority_digest: String, policy_snapshot_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[rustfmt::skip]
struct CandidateSubject {
    candidate_id: String, attempt_id: String, base_oid: String, head_oid: String,
    tree_oid: String, patch_digest: String, row_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[rustfmt::skip]
struct RepositorySubject {
    repository_id: String, workspace_path: PathBuf, receipt_relative_path: String,
}

#[derive(Clone)]
struct LaneFacts {
    variant_id: String,
    attempt: Attempt,
    authority: AuthorityToken,
    candidate: Candidate,
    repository: PathBuf,
}

pub(super) fn seal(
    durable_receipt_bytes: &[u8],
    lanes: [&LaneRun; 2],
) -> Result<SelectedCandidateSubject, String> {
    seal_facts(
        durable_receipt_bytes,
        [LaneFacts::from(lanes[0]), LaneFacts::from(lanes[1])],
    )
}

impl LaneFacts {
    fn from(lane: &LaneRun) -> Self {
        Self {
            variant_id: lane.variant_id.to_string(),
            attempt: lane.grant.attempt.clone(),
            authority: lane.grant.authority_token.clone(),
            candidate: lane.barrier.candidate.clone(),
            repository: lane.barrier.repository.clone(),
        }
    }
}

fn seal_facts(bytes: &[u8], lanes: [LaneFacts; 2]) -> Result<SelectedCandidateSubject, String> {
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err("SELECTED_SUBJECT_RECEIPT_SIZE_INVALID".into());
    }
    require_distinct_and_shared(&lanes)?;
    let envelope: Value = decode_canonical(bytes).map_err(|error| error.to_string())?;
    if string(&envelope, "schema_version")? != RECEIPT_SCHEMA {
        return Err("SELECTED_SUBJECT_RECEIPT_SCHEMA_INVALID".into());
    }
    let body = field(&envelope, "body")?;
    let body_bytes = canonical_json(body).map_err(|error| error.to_string())?;
    let body_digest = string(&envelope, "body_digest")?;
    if hash_framed_bytes(BODY_DOMAIN, &body_bytes).map_err(|error| error.to_string())?
        != body_digest
    {
        return Err("SELECTED_SUBJECT_BODY_DIGEST_MISMATCH".into());
    }
    let shared = field(body, "shared")?;
    let selection = field(body, "selection")?;
    let plan_digest = string(shared, "plan_digest")?;
    Digest::from_hex(plan_digest).map_err(|_| "SELECTED_SUBJECT_PLAN_DIGEST_INVALID")?;
    let gate_ids = strings(shared, "gate_ids")?;
    let scope_paths = strings(shared, "scope_paths")?;
    if gate_ids != [REPOSITORY_GATE_ID] || scope_paths != ["PONG.txt"] {
        return Err("SELECTED_SUBJECT_SCOPE_OR_GATES_INVALID".into());
    }
    require_shared_receipt(shared, &lanes[0], &gate_ids, &scope_paths)?;

    let views: Vec<BlindedCandidateView> =
        serde_json::from_value(field(selection, "blinded_views")?.clone())
            .map_err(|error| format!("SELECTED_SUBJECT_VIEWS_INVALID: {error}"))?;
    let views: [BlindedCandidateView; 2] = views
        .try_into()
        .map_err(|_| "SELECTED_SUBJECT_EXACT_PAIR_REQUIRED")?;
    let derived = select_exact_pair(views.clone())?;
    let decision: SelectionDecision = serde_json::from_value(field(selection, "decision")?.clone())
        .map_err(|error| format!("SELECTED_SUBJECT_DECISION_INVALID: {error}"))?;
    if decision != derived || decision.rubric != NONQUALITY_TIEBREAK_V1 {
        return Err("SELECTED_SUBJECT_DECISION_MISMATCH".into());
    }
    let selected_id = string(selection, "selected_candidate_id")?;
    let salt = decode_hex_32(string(selection, "revealed_run_salt")?)?;
    require_unblinding(selection, &decision, selected_id, &salt, &lanes)?;
    require_views(selection, &views, &lanes)?;
    let receipt_lanes = field(body, "lanes")?
        .as_array()
        .filter(|rows| rows.len() == 2)
        .ok_or("SELECTED_SUBJECT_RECEIPT_LANES_INVALID")?;
    for lane in &lanes {
        let row = receipt_lanes
            .iter()
            .find(|row| string(row, "candidate_id").ok() == Some(lane.candidate.id.as_str()))
            .ok_or("SELECTED_SUBJECT_CANDIDATE_ROW_ABSENT")?;
        require_lane_receipt(row, lane)?;
    }
    let winner = lanes
        .iter()
        .find(|lane| lane.candidate.id.as_str() == selected_id)
        .ok_or("SELECTED_SUBJECT_WINNER_ABSENT")?;
    let receipt_lane = receipt_lanes
        .iter()
        .find(|row| string(row, "candidate_id").ok() == Some(selected_id))
        .ok_or("SELECTED_SUBJECT_WINNER_ROW_ABSENT")?;
    let authority_digest = winner
        .authority
        .digest()
        .map_err(|error| error.to_string())?;
    let candidate_row_digest = hash_canonical(
        "bullet.synthetic-selection.candidate-row.v1",
        &winner.candidate,
    )
    .map_err(|error| error.to_string())?;
    let subject = SelectedCandidateSubject {
        schema_version: SCHEMA.into(),
        selection: SelectionSubject {
            receipt_digest: hash_framed_bytes(RECEIPT_DOMAIN, bytes)
                .map_err(|error| error.to_string())?,
            body_digest: body_digest.into(),
            plan_digest: plan_digest.into(),
            rubric: decision.rubric,
            selected_handle: decision.selected_handle,
        },
        shared: SharedSubject {
            organization_id: winner.authority.organization_id.to_string(),
            repository_id: winner.authority.repository_id.to_string(),
            mission_id: winner.authority.mission_id.to_string(),
            acceptance_contract_id: winner.authority.acceptance_contract_id.to_string(),
            plan_revision_id: winner.authority.plan_revision_id.to_string(),
            graph_sequence: winner.authority.graph_sequence,
            work_package_id: winner.authority.work_package_id.to_string(),
            selection_group_id: winner.authority.selection_group_id.to_string(),
            base_oid: winner.candidate.base_sha.clone(),
            gate_ids,
            scope_paths,
        },
        author: AuthorSubject {
            variant_id: winner.variant_id.clone(),
            attempt_id: winner.attempt.id.to_string(),
            attempt_fence: winner.attempt.fence,
            runner_id: winner.attempt.runner_id.to_string(),
            runner_epoch: winner.attempt.runner_epoch,
            workspace_id: winner.attempt.workspace_id.to_string(),
            authority_digest: authority_digest.to_hex(),
            policy_snapshot_digest: winner.authority.policy_snapshot_hash.to_hex(),
        },
        candidate: CandidateSubject {
            candidate_id: winner.candidate.id.to_string(),
            attempt_id: winner.candidate.attempt_id.to_string(),
            base_oid: winner.candidate.base_sha.clone(),
            head_oid: winner.candidate.head_sha.clone(),
            tree_oid: winner.candidate.tree_sha.clone(),
            patch_digest: winner.candidate.patch_digest.to_hex(),
            row_digest: candidate_row_digest,
        },
        repository: RepositorySubject {
            repository_id: winner.authority.repository_id.to_string(),
            workspace_path: winner.repository.clone(),
            receipt_relative_path: string(receipt_lane, "repository_relative")?.into(),
        },
    };
    Ok(subject)
}

#[rustfmt::skip]
impl SelectedCandidateSubject {
    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, String> { canonical_json(self).map_err(|error| error.to_string()) }
    pub(super) fn digest(&self) -> Result<String, String> { hash_canonical(SUBJECT_DOMAIN, self).map_err(|error| error.to_string()) }
    pub(super) fn selection_receipt_digest(&self) -> &str { &self.selection.receipt_digest }
    pub(super) fn selection_body_digest(&self) -> &str { &self.selection.body_digest }
    pub(super) fn plan_digest(&self) -> &str { &self.selection.plan_digest }
    pub(super) fn selected_handle(&self) -> &str { &self.selection.selected_handle }
    pub(super) fn work_package_id(&self) -> &str { &self.shared.work_package_id }
    pub(super) fn variant_id(&self) -> &str { &self.author.variant_id }
    pub(super) fn author_attempt_id(&self) -> &str { &self.author.attempt_id }
    pub(super) const fn author_fence(&self) -> u64 { self.author.attempt_fence }
    pub(super) fn author_runner_id(&self) -> &str { &self.author.runner_id }
    pub(super) fn author_workspace_id(&self) -> &str { &self.author.workspace_id }
    pub(super) fn policy_digest(&self) -> &str { &self.author.policy_snapshot_digest }
    pub(super) fn candidate_id(&self) -> &str { &self.candidate.candidate_id }
    pub(super) fn base_oid(&self) -> &str { &self.candidate.base_oid }
    pub(super) fn head_oid(&self) -> &str { &self.candidate.head_oid }
    pub(super) fn tree_oid(&self) -> &str { &self.candidate.tree_oid }
    pub(super) fn patch_digest(&self) -> &str { &self.candidate.patch_digest }
    pub(super) fn candidate_row_digest(&self) -> &str { &self.candidate.row_digest }
    pub(super) fn repository(&self) -> &Path { &self.repository.workspace_path }
}

fn require_distinct_and_shared(lanes: &[LaneFacts; 2]) -> Result<(), String> {
    if lanes[0].candidate.id == lanes[1].candidate.id || lanes[0].variant_id == lanes[1].variant_id
    {
        return Err("SELECTED_SUBJECT_PARTICIPANTS_NOT_DISTINCT".into());
    }
    for lane in lanes {
        let attempt = &lane.attempt;
        let authority = &lane.authority;
        if !lane.repository.is_absolute()
            || lane.variant_id != attempt.variant_id.as_str()
            || lane.variant_id != authority.variant_id.as_str()
            || lane.candidate.attempt_id != attempt.id
            || authority.attempt_id != attempt.id
            || authority.attempt_fence != attempt.fence
            || authority.work_package_id != attempt.work_package_id
            || authority.runner_id != attempt.runner_id
            || authority.runner_epoch != attempt.runner_epoch
            || authority.workspace_id != attempt.workspace_id
            || authority.workspace_nonce != attempt.workspace_nonce
            || authority.scope_revision != attempt.scope_revision
            || authority.context_revision != attempt.context_revision
        {
            return Err("SELECTED_SUBJECT_AUTHOR_BINDING_MISMATCH".into());
        }
    }
    let a = &lanes[0].authority;
    let b = &lanes[1].authority;
    if a.organization_id != b.organization_id
        || a.repository_id != b.repository_id
        || a.mission_id != b.mission_id
        || a.acceptance_contract_id != b.acceptance_contract_id
        || a.plan_revision_id != b.plan_revision_id
        || a.graph_sequence != b.graph_sequence
        || a.work_package_id != b.work_package_id
        || a.selection_group_id != b.selection_group_id
        || a.scope_revision != b.scope_revision
        || a.context_revision != b.context_revision
        || a.config_snapshot_hash != b.config_snapshot_hash
        || a.policy_snapshot_hash != b.policy_snapshot_hash
        || a.routing_policy_hash != b.routing_policy_hash
        || a.credential_profile_id != b.credential_profile_id
        || a.credential_generation != b.credential_generation
        || lanes[0].candidate.base_sha != lanes[1].candidate.base_sha
    {
        return Err("SELECTED_SUBJECT_SHARED_AUTHORITY_MISMATCH".into());
    }
    Ok(())
}

fn require_shared_receipt(
    value: &Value,
    lane: &LaneFacts,
    gates: &[String],
    scope: &[String],
) -> Result<(), String> {
    let authority = &lane.authority;
    let exact = string(value, "mission_id")? == authority.mission_id.as_str()
        && string(value, "plan_revision_id")? == authority.plan_revision_id.as_str()
        && string(value, "repository_id")? == authority.repository_id.as_str()
        && string(value, "work_package_id")? == authority.work_package_id.as_str()
        && string(value, "selection_group_id")? == authority.selection_group_id.as_str()
        && string(value, "base_oid")? == lane.candidate.base_sha
        && strings(value, "gate_ids")? == gates
        && strings(value, "scope_paths")? == scope;
    exact
        .then_some(())
        .ok_or_else(|| "SELECTED_SUBJECT_SHARED_RECEIPT_MISMATCH".into())
}

fn require_lane_receipt(value: &Value, lane: &LaneFacts) -> Result<(), String> {
    let authority_digest = lane.authority.digest().map_err(|error| error.to_string())?;
    let row_digest = hash_canonical(
        "bullet.synthetic-selection.candidate-row.v1",
        &lane.candidate,
    )
    .map_err(|error| error.to_string())?;
    let exact = string(value, "runner_id")? == lane.attempt.runner_id.as_str()
        && number(value, "runner_epoch")? == lane.attempt.runner_epoch
        && string(value, "variant_id")? == lane.variant_id
        && string(value, "attempt_id")? == lane.attempt.id.as_str()
        && number(value, "attempt_fence")? == lane.attempt.fence
        && string(value, "workspace_id")? == lane.attempt.workspace_id.as_str()
        && string(value, "authority_digest")? == authority_digest.to_hex()
        && string(value, "candidate_id")? == lane.candidate.id.as_str()
        && string(value, "candidate_base_oid")? == lane.candidate.base_sha
        && string(value, "candidate_head_oid")? == lane.candidate.head_sha
        && string(value, "candidate_tree_oid")? == lane.candidate.tree_sha
        && string(value, "candidate_patch_blake3")? == lane.candidate.patch_digest.to_hex()
        && string(value, "candidate_row_digest")? == row_digest;
    let relative = string(value, "repository_relative")?;
    if !exact || relative.is_empty() || relative.starts_with('/') || relative.contains("..") {
        return Err("SELECTED_SUBJECT_RECEIPT_LANE_MISMATCH".into());
    }
    Ok(())
}

#[rustfmt::skip]
fn require_views(selection: &Value, views: &[BlindedCandidateView; 2], lanes: &[LaneFacts; 2]) -> Result<(), String> {
    let rows = field(selection, "unblinding")?.as_array().ok_or("SELECTED_SUBJECT_UNBLINDING_INVALID")?;
    for view in views {
        let candidate = rows.iter().find(|row| string(row, "blinded_handle").ok() == Some(&view.blinded_handle)).and_then(|row| string(row, "candidate_id").ok());
        let lane = lanes.iter().find(|lane| {
            Some(lane.candidate.id.as_str()) == candidate
                && lane.candidate.base_sha == view.base_oid
                && lane.candidate.head_sha == view.head_oid
                && lane.candidate.tree_sha == view.tree_oid
                && lane.candidate.patch_digest.to_hex() == view.patch_blake3
        });
        if lane.is_none() || view.gate_ids != [REPOSITORY_GATE_ID] || !view.component_gate_passed {
            return Err("SELECTED_SUBJECT_VIEW_CANDIDATE_MISMATCH".into());
        }
    }
    Ok(())
}

#[rustfmt::skip]
fn require_unblinding(selection: &Value, decision: &SelectionDecision, selected_id: &str, salt: &[u8; 32], lanes: &[LaneFacts; 2]) -> Result<(), String> {
    let rows = field(selection, "unblinding")?.as_array().filter(|rows| rows.len() == 2).ok_or("SELECTED_SUBJECT_UNBLINDING_INVALID")?;
    if string(&rows[0], "candidate_id")? == string(&rows[1], "candidate_id")? {
        return Err("SELECTED_SUBJECT_UNBLINDING_DUPLICATE_CANDIDATE".into());
    }
    let mut selected_matches = 0;
    for row in rows {
        let handle = string(row, "blinded_handle")?;
        let candidate = string(row, "candidate_id")?;
        if !lanes
            .iter()
            .any(|lane| lane.candidate.id.as_str() == candidate)
            || string(row, "binding_digest")? != unblinding_digest(salt, handle, candidate)?
        {
            return Err("SELECTED_SUBJECT_UNBLINDING_MISMATCH".into());
        }
        if handle == decision.selected_handle && candidate == selected_id {
            selected_matches += 1;
        }
    }
    if selected_matches != 1 {
        return Err("SELECTED_SUBJECT_SELECTED_MAPPING_MISMATCH".into());
    }
    Ok(())
}

#[rustfmt::skip]
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> { value.get(name).ok_or_else(|| format!("SELECTED_SUBJECT_FIELD_ABSENT: {name}")) }
#[rustfmt::skip]
fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> { field(value, name)?.as_str().ok_or_else(|| format!("SELECTED_SUBJECT_STRING_INVALID: {name}")) }
#[rustfmt::skip]
fn number(value: &Value, name: &str) -> Result<u64, String> { field(value, name)?.as_u64().ok_or_else(|| format!("SELECTED_SUBJECT_NUMBER_INVALID: {name}")) }

#[rustfmt::skip]
fn strings(value: &Value, name: &str) -> Result<Vec<String>, String> { field(value, name)?.as_array().ok_or_else(|| format!("SELECTED_SUBJECT_ARRAY_INVALID: {name}"))?.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(|| format!("SELECTED_SUBJECT_ARRAY_ITEM_INVALID: {name}"))).collect() }
#[rustfmt::skip]
fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err("SELECTED_SUBJECT_SALT_INVALID".into()); }
    Digest::from_hex(value).map(|digest| *digest.as_bytes()).map_err(|_| "SELECTED_SUBJECT_SALT_INVALID".into())
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    use bullet_domain::{AcceptanceContractId, AttemptId, AttemptState, MissionId, OrganizationId, PlanRevisionId, RepositoryId, RunnerId, SelectionGroupId, VariantId, WorkPackageId, WorkspaceId};
    use serde_json::json;

    fn lane(label: &str) -> LaneFacts {
        let variant = VariantId::from_seed(label);
        let attempt = Attempt {
            id: AttemptId::from_seed(label), variant_id: variant.clone(), work_package_id: WorkPackageId::from_seed("shared"),
            fence: 1, runner_id: RunnerId::from_seed(label), runner_epoch: 1, workspace_id: WorkspaceId::from_seed(label),
            workspace_nonce: [label.as_bytes()[0]; 32], scope_revision: 1, context_revision: 1, state: AttemptState::Starting,
        };
        let authority = AuthorityToken {
            organization_id: OrganizationId::from_seed("shared"), repository_id: RepositoryId::from_seed("shared"),
            mission_id: MissionId::from_seed("shared"), acceptance_contract_id: AcceptanceContractId::from_seed("shared"),
            plan_revision_id: PlanRevisionId::from_seed("shared"), graph_sequence: 3, work_package_id: attempt.work_package_id.clone(),
            selection_group_id: SelectionGroupId::from_seed("shared"), variant_id: variant.clone(), attempt_id: attempt.id.clone(),
            attempt_fence: 1, runner_id: attempt.runner_id.clone(), runner_epoch: 1, workspace_id: attempt.workspace_id.clone(),
            workspace_nonce: attempt.workspace_nonce, scope_revision: 1, context_revision: 1,
            config_snapshot_hash: Digest::of(b"config"), policy_snapshot_hash: Digest::of(b"policy"),
            routing_policy_hash: Digest::of(b"routing"), credential_profile_id: None, credential_generation: None,
        };
        LaneFacts { variant_id: variant.to_string(), attempt: attempt.clone(), authority, candidate: Candidate {
            id: bullet_domain::CandidateId::from_seed(label), attempt_id: attempt.id, base_sha: format!("sha1:{}", "1".repeat(40)),
            head_sha: format!("sha1:{}", label.chars().next().unwrap().to_string().repeat(40)),
            tree_sha: format!("sha1:{}", label.chars().last().unwrap().to_string().repeat(40)), patch_digest: Digest::of(label.as_bytes()),
        }, repository: PathBuf::from(format!("/tmp/{label}")) }
    }

    fn shared(lane: &LaneFacts) -> Value { json!({
        "mission_id": lane.authority.mission_id, "plan_revision_id": lane.authority.plan_revision_id,
        "repository_id": lane.authority.repository_id, "work_package_id": lane.authority.work_package_id,
        "selection_group_id": lane.authority.selection_group_id, "base_oid": lane.candidate.base_sha,
        "gate_ids": [REPOSITORY_GATE_ID], "scope_paths": ["PONG.txt"]
    }) }

    #[test]
    fn selected_swap_and_every_author_graph_candidate_drift_refuse() {
        let lanes = [lane("a"), lane("b")];
        assert!(require_distinct_and_shared(&lanes).is_ok());
        let mut drift = lanes.clone(); drift[0].attempt.fence += 1; assert!(require_distinct_and_shared(&drift).is_err());
        let mut drift = lanes.clone(); drift[0].variant_id = VariantId::from_seed("wrong").to_string(); assert!(require_distinct_and_shared(&drift).is_err());
        let mut drift = lanes.clone(); drift[0].authority.policy_snapshot_hash = Digest::of(b"wrong"); assert!(require_distinct_and_shared(&drift).is_err());
        let mut drift = lanes.clone(); drift[0].authority.graph_sequence += 1; assert!(require_distinct_and_shared(&drift).is_err());
        let mut drift = lanes.clone(); drift[0].candidate.base_sha.push('0'); assert!(require_distinct_and_shared(&drift).is_err());
        let mut drift = lanes.clone(); drift[0].repository = PathBuf::from("relative"); assert!(require_distinct_and_shared(&drift).is_err());

        let common = shared(&lanes[0]);
        assert!(require_shared_receipt(&common, &lanes[0], &[REPOSITORY_GATE_ID.into()], &["PONG.txt".into()]).is_ok());
        for key in ["mission_id", "plan_revision_id", "repository_id", "work_package_id", "selection_group_id", "base_oid"] {
            let mut changed = common.clone(); changed[key] = json!("wrong");
            assert!(require_shared_receipt(&changed, &lanes[0], &[REPOSITORY_GATE_ID.into()], &["PONG.txt".into()]).is_err(), "admitted {key} drift");
        }
        let salt = [7; 32]; let handles = [format!("bvh_{}", "a".repeat(64)), format!("bvh_{}", "b".repeat(64))];
        let rows = lanes.iter().zip(handles.iter()).map(|(lane, handle)| json!({"blinded_handle": handle, "candidate_id": lane.candidate.id, "binding_digest": unblinding_digest(&salt, handle, lane.candidate.id.as_str()).unwrap()})).collect::<Vec<_>>();
        let selection = json!({"unblinding": rows});
        let decision = SelectionDecision { rubric: NONQUALITY_TIEBREAK_V1.into(), selected_handle: handles[0].clone(), ordered_handles: handles.clone() };
        assert!(require_unblinding(&selection, &decision, lanes[0].candidate.id.as_str(), &salt, &lanes).is_ok());
        assert!(require_unblinding(&selection, &decision, lanes[1].candidate.id.as_str(), &salt, &lanes).is_err());
        let views = [BlindedCandidateView { blinded_handle: handles[0].clone(), base_oid: lanes[0].candidate.base_sha.clone(), head_oid: lanes[0].candidate.head_sha.clone(), tree_oid: lanes[0].candidate.tree_sha.clone(), patch_blake3: lanes[0].candidate.patch_digest.to_hex(), gate_ids: vec![REPOSITORY_GATE_ID.into()], component_gate_passed: true }, BlindedCandidateView { blinded_handle: handles[1].clone(), base_oid: lanes[1].candidate.base_sha.clone(), head_oid: lanes[1].candidate.head_sha.clone(), tree_oid: lanes[1].candidate.tree_sha.clone(), patch_blake3: lanes[1].candidate.patch_digest.to_hex(), gate_ids: vec![REPOSITORY_GATE_ID.into()], component_gate_passed: true }];
        assert!(require_views(&selection, &views, &lanes).is_ok());
        let swapped = json!({"unblinding": [{"blinded_handle": handles[0], "candidate_id": lanes[1].candidate.id, "binding_digest": unblinding_digest(&salt, &handles[0], lanes[1].candidate.id.as_str()).unwrap()}, {"blinded_handle": handles[1], "candidate_id": lanes[0].candidate.id, "binding_digest": unblinding_digest(&salt, &handles[1], lanes[0].candidate.id.as_str()).unwrap()}]});
        assert!(require_unblinding(&swapped, &decision, lanes[1].candidate.id.as_str(), &salt, &lanes).is_ok());
        assert!(require_views(&swapped, &views, &lanes).is_err());
    }

    #[test]
    fn every_nested_selected_subject_record_rejects_unknown_fields() {
        let lane = lane("a"); let digest = lane.authority.digest().unwrap().to_hex();
        let subject = SelectedCandidateSubject { schema_version: SCHEMA.into(),
            selection: SelectionSubject { receipt_digest: digest.clone(), body_digest: digest.clone(), plan_digest: digest.clone(), rubric: NONQUALITY_TIEBREAK_V1.into(), selected_handle: format!("bvh_{}", "a".repeat(64)) },
            shared: SharedSubject { organization_id: lane.authority.organization_id.to_string(), repository_id: lane.authority.repository_id.to_string(), mission_id: lane.authority.mission_id.to_string(), acceptance_contract_id: lane.authority.acceptance_contract_id.to_string(), plan_revision_id: lane.authority.plan_revision_id.to_string(), graph_sequence: 3, work_package_id: lane.authority.work_package_id.to_string(), selection_group_id: lane.authority.selection_group_id.to_string(), base_oid: lane.candidate.base_sha.clone(), gate_ids: vec![REPOSITORY_GATE_ID.into()], scope_paths: vec!["PONG.txt".into()] },
            author: AuthorSubject { variant_id: lane.variant_id, attempt_id: lane.attempt.id.to_string(), attempt_fence: 1, runner_id: lane.attempt.runner_id.to_string(), runner_epoch: 1, workspace_id: lane.attempt.workspace_id.to_string(), authority_digest: digest.clone(), policy_snapshot_digest: lane.authority.policy_snapshot_hash.to_hex() },
            candidate: CandidateSubject { candidate_id: lane.candidate.id.to_string(), attempt_id: lane.candidate.attempt_id.to_string(), base_oid: lane.candidate.base_sha, head_oid: lane.candidate.head_sha, tree_oid: lane.candidate.tree_sha, patch_digest: lane.candidate.patch_digest.to_hex(), row_digest: digest },
            repository: RepositorySubject { repository_id: lane.authority.repository_id.to_string(), workspace_path: lane.repository, receipt_relative_path: "lane/repository".into() } };
        for record in ["selection", "shared", "author", "candidate", "repository"] {
            let mut value = serde_json::to_value(&subject).unwrap(); value[record]["unknown"] = json!(true);
            let bytes = canonical_json(&value).unwrap(); assert!(decode_canonical::<SelectedCandidateSubject>(&bytes).is_err(), "admitted unknown {record} field");
        }
    }
    #[test]
    fn salt_is_exact_lowercase_32_bytes() {
        assert_eq!(decode_hex_32(&"a5".repeat(32)).unwrap(), [0xa5; 32]);
        for invalid in ["a5".repeat(31), "A5".repeat(32), format!("{}g0", "a5".repeat(31))] { assert!(decode_hex_32(&invalid).is_err(), "admitted {invalid}"); }
    }
}
