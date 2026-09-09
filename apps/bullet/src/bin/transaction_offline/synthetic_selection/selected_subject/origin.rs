//! Replay validation for the exact retained selection receipt.

#[cfg(test)]
mod tests;

use super::*;
use bullet_application::lease_transport::{
    workspace_for_key, LeaseSettlementRequest, ReleaseSettlementRequest,
    SyntheticSelectedAcquireBody,
};
use bullet_domain::{
    AcceptanceContractId, AttemptId, AttemptState, CandidateId, MissionId, OrganizationId,
    PlanRevisionId, RepositoryId, RunnerId, SelectionGroupId, VariantId, WorkPackageId,
};

const MAX_RECEIPT_BYTES: usize = 1_048_576;

struct ReplayedLane {
    candidate_id: String,
    view: BlindedCandidateView,
}

impl SelectedCandidateSubject {
    pub(crate) fn validate_origin_receipt(&self, bytes: &[u8]) -> Result<(), String> {
        self.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err("SELECTED_ORIGIN_RECEIPT_SIZE_INVALID".into());
        }
        let envelope: Value = decode_canonical(bytes).map_err(|error| error.to_string())?;
        exact_fields(&envelope, &["schema_version", "body_digest", "body"])?;
        if string(&envelope, "schema_version")? != RECEIPT_SCHEMA {
            return Err("SELECTED_ORIGIN_RECEIPT_SCHEMA_INVALID".into());
        }
        let body = field(&envelope, "body")?;
        let body_bytes = canonical_json(body).map_err(|error| error.to_string())?;
        let body_digest =
            hash_framed_bytes(BODY_DOMAIN, &body_bytes).map_err(|error| error.to_string())?;
        let artifact_digest =
            hash_framed_bytes(RECEIPT_DOMAIN, bytes).map_err(|error| error.to_string())?;
        if string(&envelope, "body_digest")? != body_digest
            || self.selection.body_digest != body_digest
            || self.selection.receipt_digest != artifact_digest
        {
            return Err("SELECTED_ORIGIN_RECEIPT_DIGEST_MISMATCH".into());
        }
        exact_fields(
            body,
            &[
                "evidence_class",
                "signing_trust",
                "execution_schedule",
                "simulator",
                "shared",
                "selection",
                "lanes",
                "eligibility",
            ],
        )?;
        require_classification(body)?;
        self.require_origin_shared(field(body, "shared")?)?;
        let selection = field(body, "selection")?;
        exact_fields(
            selection,
            &[
                "decision",
                "input_digest",
                "blinded_views",
                "selected_candidate_id",
                "revealed_run_salt",
                "unblinding",
            ],
        )?;
        let salt = decode_hex_32(string(selection, "revealed_run_salt")?)?;
        let rows = field(body, "lanes")?
            .as_array()
            .filter(|rows| rows.len() == 2)
            .ok_or("SELECTED_ORIGIN_LANES_INVALID")?;
        let replayed = [
            self.replay_origin_lane(&rows[0], 0, &salt)?,
            self.replay_origin_lane(&rows[1], 1, &salt)?,
        ];
        if replayed[0].candidate_id == replayed[1].candidate_id {
            return Err("SELECTED_ORIGIN_CANDIDATES_NOT_DISTINCT".into());
        }
        self.require_origin_selection(selection, replayed)
    }

    fn require_origin_shared(&self, shared: &Value) -> Result<(), String> {
        exact_fields(
            shared,
            &[
                "plan_digest",
                "mission_id",
                "plan_revision_id",
                "repository_id",
                "work_package_id",
                "selection_group_id",
                "base_oid",
                "scope_paths",
                "gate_ids",
            ],
        )?;
        let exact = string(shared, "plan_digest")? == self.selection.plan_digest
            && string(shared, "mission_id")? == self.shared.mission_id
            && string(shared, "plan_revision_id")? == self.shared.plan_revision_id
            && string(shared, "repository_id")? == self.shared.repository_id
            && string(shared, "work_package_id")? == self.shared.work_package_id
            && string(shared, "selection_group_id")? == self.shared.selection_group_id
            && string(shared, "base_oid")? == self.shared.base_oid
            && strings(shared, "scope_paths")? == self.shared.scope_paths
            && strings(shared, "gate_ids")? == self.shared.gate_ids;
        exact
            .then_some(())
            .ok_or_else(|| "SELECTED_ORIGIN_SHARED_MISMATCH".into())
    }

    fn replay_origin_lane(
        &self,
        row: &Value,
        index: usize,
        salt: &[u8; 32],
    ) -> Result<ReplayedLane, String> {
        const FIELDS: [&str; 25] = [
            "runner_id",
            "runner_epoch",
            "variant_id",
            "attempt_id",
            "attempt_fence",
            "workspace_id",
            "authority_digest",
            "candidate_id",
            "candidate_base_oid",
            "candidate_head_oid",
            "candidate_tree_oid",
            "candidate_patch_blake3",
            "candidate_row_digest",
            "repository_relative",
            "raw_artifact_relative",
            "raw_artifact_blake3",
            "journal_relative",
            "journal_blake3",
            "recovery_relative",
            "recovery_blake3",
            "acquire_request_digest",
            "settlement_id",
            "settlement_request_digest",
            "terminal_state",
            "requeue",
        ];
        exact_fields(row, &FIELDS)?;
        let mut variants = [
            VariantId::from_seed("df-dog1-two-lane:synthetic-selection:0"),
            VariantId::from_seed("df-dog1-two-lane:synthetic-selection:1"),
        ];
        variants.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let variant = variants[index].clone();
        let runner = RunnerId::from_seed(if index == 0 {
            "df-dog1-runner-a"
        } else {
            "df-dog1-runner-b"
        });
        let package = WorkPackageId::parse(&self.shared.work_package_id).map_err(origin_invalid)?;
        let acquire = SyntheticSelectedAcquireBody::new(
            Digest::from_hex(&self.selection.plan_digest).map_err(origin_invalid)?,
            package.clone(),
            runner.clone(),
            1,
            variant.clone(),
            15,
        )
        .map_err(origin_invalid)?;
        let attempt = AttemptId::from_seed(&acquire.inner().idempotency_key);
        let (workspace, workspace_nonce) = workspace_for_key(&acquire.inner().idempotency_key);
        let authority = AuthorityToken {
            organization_id: OrganizationId::parse(&self.shared.organization_id)
                .map_err(origin_invalid)?,
            repository_id: RepositoryId::parse(&self.shared.repository_id)
                .map_err(origin_invalid)?,
            mission_id: MissionId::parse(&self.shared.mission_id).map_err(origin_invalid)?,
            acceptance_contract_id: AcceptanceContractId::parse(
                &self.shared.acceptance_contract_id,
            )
            .map_err(origin_invalid)?,
            plan_revision_id: PlanRevisionId::parse(&self.shared.plan_revision_id)
                .map_err(origin_invalid)?,
            graph_sequence: self.shared.graph_sequence,
            work_package_id: package.clone(),
            selection_group_id: SelectionGroupId::parse(&self.shared.selection_group_id)
                .map_err(origin_invalid)?,
            variant_id: variant.clone(),
            attempt_id: attempt.clone(),
            attempt_fence: 1,
            runner_id: runner.clone(),
            runner_epoch: 1,
            workspace_id: workspace.clone(),
            workspace_nonce,
            scope_revision: 1,
            context_revision: 1,
            config_snapshot_hash: Digest::of(b"cfg"),
            policy_snapshot_hash: Digest::of(b"pol"),
            routing_policy_hash: Digest::of(b"route"),
            credential_profile_id: None,
            credential_generation: None,
        };
        let candidate = Candidate {
            id: CandidateId::parse(string(row, "candidate_id")?).map_err(origin_invalid)?,
            attempt_id: attempt.clone(),
            base_sha: string(row, "candidate_base_oid")?.into(),
            head_sha: string(row, "candidate_head_oid")?.into(),
            tree_sha: string(row, "candidate_tree_oid")?.into(),
            patch_digest: closed_digest(string(row, "candidate_patch_blake3")?)?,
        };
        let acquire_digest = acquire.inner().request_digest().map_err(origin_invalid)?;
        let release = LeaseSettlementRequest::Release(ReleaseSettlementRequest {
            acquire_request_digest: acquire_digest.clone(),
            work_package_id: package,
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: acquire.inner().idempotency_key.clone(),
            variant_id: variant.clone(),
            attempt_id: attempt.clone(),
            attempt_fence: 1,
            expected_state: AttemptState::Preparing,
            final_state: AttemptState::Superseded,
            requeue: true,
        });
        let release_digest = release.digest().map_err(origin_invalid)?;
        let row_digest = hash_canonical("bullet.synthetic-selection.candidate-row.v1", &candidate)
            .map_err(|error| error.to_string())?;
        let exact = string(row, "runner_id")? == runner.as_str()
            && number(row, "runner_epoch")? == 1
            && string(row, "variant_id")? == variant.as_str()
            && string(row, "attempt_id")? == attempt.as_str()
            && number(row, "attempt_fence")? == 1
            && string(row, "workspace_id")? == workspace.as_str()
            && string(row, "authority_digest")?
                == authority.digest().map_err(origin_invalid)?.to_hex()
            && candidate.base_sha == self.shared.base_oid
            && closed_oid(&candidate.head_sha)
            && closed_oid(&candidate.tree_sha)
            && candidate.head_sha != candidate.base_sha
            && string(row, "candidate_row_digest")? == row_digest
            && string(row, "acquire_request_digest")? == acquire_digest
            && string(row, "settlement_request_digest")? == release_digest
            && string(row, "settlement_id")? == format!("lts_{release_digest}")
            && string(row, "terminal_state")? == "Superseded"
            && field(row, "requeue")?.as_bool() == Some(true)
            && [
                "repository_relative",
                "raw_artifact_relative",
                "journal_relative",
                "recovery_relative",
            ]
            .iter()
            .all(|name| string(row, name).is_ok_and(closed_relative))
            && ["raw_artifact_blake3", "journal_blake3", "recovery_blake3"]
                .iter()
                .all(|name| string(row, name).is_ok_and(|value| closed_digest(value).is_ok()));
        if !exact {
            return Err("SELECTED_ORIGIN_LANE_MISMATCH".into());
        }
        if candidate.id.as_str() == self.candidate.candidate_id {
            let winner_exact = attempt.as_str() == self.author.attempt_id
                && candidate.base_sha == self.candidate.base_oid
                && candidate.head_sha == self.candidate.head_oid
                && candidate.tree_sha == self.candidate.tree_oid
                && candidate.patch_digest.to_hex() == self.candidate.patch_digest
                && row_digest == self.candidate.row_digest
                && string(row, "repository_relative")? == self.repository.receipt_relative_path;
            if !winner_exact {
                return Err("SELECTED_ORIGIN_WINNER_MISMATCH".into());
            }
        }
        let view = super::super::selector::blinded_view(
            salt,
            candidate.id.as_str(),
            candidate.base_sha,
            candidate.head_sha,
            candidate.tree_sha,
            candidate.patch_digest.to_hex(),
            vec![REPOSITORY_GATE_ID.into()],
            true,
        )?;
        Ok(ReplayedLane {
            candidate_id: candidate.id.to_string(),
            view,
        })
    }

    fn require_origin_selection(
        &self,
        selection: &Value,
        replayed: [ReplayedLane; 2],
    ) -> Result<(), String> {
        let views: Vec<BlindedCandidateView> =
            serde_json::from_value(field(selection, "blinded_views")?.clone())
                .map_err(|error| error.to_string())?;
        let mut expected_views = [replayed[0].view.clone(), replayed[1].view.clone()];
        expected_views.sort_by(|left, right| left.blinded_handle.cmp(&right.blinded_handle));
        if views != expected_views {
            return Err("SELECTED_ORIGIN_VIEWS_MISMATCH".into());
        }
        let decision: SelectionDecision =
            serde_json::from_value(field(selection, "decision")?.clone())
                .map_err(|error| error.to_string())?;
        let derived = select_exact_pair(expected_views.clone())?;
        let input_digest = hash_canonical("bullet.synthetic-selection.input.v1", &views)
            .map_err(|error| error.to_string())?;
        let salt = decode_hex_32(string(selection, "revealed_run_salt")?)?;
        let rows = field(selection, "unblinding")?
            .as_array()
            .filter(|rows| rows.len() == 2)
            .ok_or("SELECTED_ORIGIN_UNBLINDING_INVALID")?;
        let mut expected_rows = replayed
            .iter()
            .map(|lane| {
                Ok((
                    lane.view.blinded_handle.clone(),
                    lane.candidate_id.clone(),
                    unblinding_digest(&salt, &lane.view.blinded_handle, &lane.candidate_id)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        expected_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (row, expected) in rows.iter().zip(expected_rows.iter()) {
            exact_fields(row, &["blinded_handle", "candidate_id", "binding_digest"])?;
            if string(row, "blinded_handle")? != expected.0
                || string(row, "candidate_id")? != expected.1
                || string(row, "binding_digest")? != expected.2
            {
                return Err("SELECTED_ORIGIN_UNBLINDING_MISMATCH".into());
            }
        }
        let selected = replayed
            .iter()
            .find(|lane| lane.view.blinded_handle == derived.selected_handle)
            .ok_or("SELECTED_ORIGIN_WINNER_ABSENT")?;
        let exact = decision == derived
            && decision.rubric == NONQUALITY_TIEBREAK_V1
            && decision.selected_handle == self.selection.selected_handle
            && selected.candidate_id == self.candidate.candidate_id
            && string(selection, "selected_candidate_id")? == self.candidate.candidate_id
            && string(selection, "input_digest")? == input_digest;
        exact
            .then_some(())
            .ok_or_else(|| "SELECTED_ORIGIN_SELECTION_MISMATCH".into())
    }
}

fn require_classification(body: &Value) -> Result<(), String> {
    let simulator = field(body, "simulator")?;
    exact_fields(
        simulator,
        &[
            "provider",
            "version",
            "live_credentials_used",
            "external_effects",
        ],
    )?;
    let eligibility = field(body, "eligibility")?;
    exact_fields(
        eligibility,
        &[
            "team_recipe_eligible",
            "evolution_profile_eligible",
            "provider_certification_eligible",
            "independent_evidence_eligible",
            "transaction_gate_eligible",
            "release_gate_eligible",
            "live_eligible",
            "routing_activation_eligible",
            "comparative_claim_eligible",
        ],
    )?;
    let exact = string(body, "evidence_class")? == "COMPONENT_PROOF"
        && string(body, "signing_trust")? == "UNSIGNED_FIXTURE"
        && string(body, "execution_schedule")? == "SEQUENTIAL"
        && string(simulator, "provider")? == "sim"
        && string(simulator, "version")? == bullet_harness_sim::SIM_VERSION
        && field(simulator, "live_credentials_used")?.as_bool() == Some(false)
        && field(simulator, "external_effects")?.as_bool() == Some(false)
        && eligibility
            .as_object()
            .is_some_and(|values| values.values().all(|value| value.as_bool() == Some(false)));
    exact
        .then_some(())
        .ok_or_else(|| "SELECTED_ORIGIN_CLASSIFICATION_INVALID".into())
}

fn exact_fields(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("SELECTED_ORIGIN_OBJECT_REQUIRED")?;
    (object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)))
        .then_some(())
        .ok_or_else(|| "SELECTED_ORIGIN_FIELDS_INVALID".into())
}

fn closed_digest(value: &str) -> Result<Digest, String> {
    let digest = Digest::from_hex(value).map_err(origin_invalid)?;
    (digest.to_hex() == value)
        .then_some(digest)
        .ok_or_else(|| "SELECTED_ORIGIN_DIGEST_INVALID".into())
}

fn closed_oid(value: &str) -> bool {
    value.strip_prefix("sha1:").is_some_and(|hex| {
        hex.len() == 40
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn closed_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn origin_invalid(error: impl std::fmt::Display) -> String {
    format!("SELECTED_ORIGIN_VALUE_INVALID: {error}")
}
