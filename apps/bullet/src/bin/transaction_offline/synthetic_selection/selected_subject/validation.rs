//! Decode-time semantic validation for a sealed selected-Candidate subject.

use super::*;
use bullet_application::lease_transport::{workspace_for_key, SyntheticSelectedAcquireBody};
use bullet_application::CommandRequest;
use bullet_domain::{
    AcceptanceContractId, AttemptId, CandidateId, MissionId, OrganizationId, PlanRevisionId,
    RepositoryId, RunnerId, SelectionGroupId, TaskClass, VariantId, WorkPackageId,
};
use serde::Serialize;
use std::path::Component;

const SEED: &str = "df-dog1-two-lane";

#[derive(Serialize)]
struct Materialization<'a> {
    protocol: &'static str,
    seed: &'a str,
    plan: Plan<'a>,
    work_package_id: WorkPackageId,
    selection_group_id: SelectionGroupId,
    variant_ids: [VariantId; 2],
}

#[derive(Serialize)]
struct Plan<'a> {
    seed: &'a str,
    title: &'static str,
    objective: &'static str,
    packages: Vec<Package>,
}

#[derive(Serialize)]
struct Package {
    title: &'static str,
    task_class: TaskClass,
}

impl SelectedCandidateSubject {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let package = WorkPackageId::from_seed(&format!("{SEED}:wp:0"));
        let group = SelectionGroupId::from_seed(&format!("{SEED}:synthetic-selection"));
        let mut variants = [
            VariantId::from_seed(&format!("{SEED}:synthetic-selection:0")),
            VariantId::from_seed(&format!("{SEED}:synthetic-selection:1")),
        ];
        variants.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let materialization = Materialization {
            protocol: "bullet.synthetic-selection.component.v1",
            seed: SEED,
            plan: Plan {
                seed: SEED,
                title: "DF-DOG1 synthetic selection",
                objective: "Run two isolated simulator Candidates and select one blinded handle.",
                packages: vec![Package {
                    title: "two isolated lanes",
                    task_class: TaskClass::BoundedBugFix,
                }],
            },
            work_package_id: package.clone(),
            selection_group_id: group.clone(),
            variant_ids: variants.clone(),
        };
        let request = CommandRequest::new(
            format!("materialize-synthetic-selection:{SEED}"),
            "materialize_synthetic_selection",
            &materialization,
        )
        .map_err(invalid)?;
        let plan_digest = Digest::of(request.payload.as_bytes());
        let selected_variant = VariantId::parse(&self.author.variant_id).map_err(invalid)?;
        let runner = match variants
            .iter()
            .position(|variant| variant == &selected_variant)
        {
            Some(0) => RunnerId::from_seed("df-dog1-runner-a"),
            Some(1) => RunnerId::from_seed("df-dog1-runner-b"),
            _ => return Err("SELECTED_SUBJECT_VARIANT_INVALID".into()),
        };
        let acquire = SyntheticSelectedAcquireBody::new(
            plan_digest,
            package.clone(),
            runner.clone(),
            1,
            selected_variant.clone(),
            15,
        )
        .map_err(invalid)?;
        let expected_attempt = AttemptId::from_seed(&acquire.inner().idempotency_key);
        let (workspace, workspace_nonce) = workspace_for_key(&acquire.inner().idempotency_key);
        let candidate_id = CandidateId::parse(&self.candidate.candidate_id).map_err(invalid)?;
        let candidate_attempt = AttemptId::parse(&self.candidate.attempt_id).map_err(invalid)?;
        let author_attempt = AttemptId::parse(&self.author.attempt_id).map_err(invalid)?;
        let patch = exact_digest(&self.candidate.patch_digest)?;
        let candidate = Candidate {
            id: candidate_id,
            attempt_id: candidate_attempt,
            base_sha: self.candidate.base_oid.clone(),
            head_sha: self.candidate.head_oid.clone(),
            tree_sha: self.candidate.tree_oid.clone(),
            patch_digest: patch,
        };
        let row_digest = hash_canonical("bullet.synthetic-selection.candidate-row.v1", &candidate)
            .map_err(|error| error.to_string())?;
        let authority = AuthorityToken {
            organization_id: OrganizationId::from_seed(SEED),
            repository_id: RepositoryId::from_seed(SEED),
            mission_id: MissionId::from_seed(SEED),
            acceptance_contract_id: AcceptanceContractId::from_seed(SEED),
            plan_revision_id: PlanRevisionId::from_seed(SEED),
            graph_sequence: 1,
            work_package_id: package.clone(),
            selection_group_id: group.clone(),
            variant_id: selected_variant,
            attempt_id: expected_attempt.clone(),
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
        let authority_digest = authority.digest().map_err(invalid)?.to_hex();
        let exact = self.schema_version == SCHEMA
            && exact_digest(&self.selection.receipt_digest).is_ok()
            && exact_digest(&self.selection.body_digest).is_ok()
            && self.selection.plan_digest == plan_digest.to_hex()
            && self.selection.rubric == NONQUALITY_TIEBREAK_V1
            && typed_hex(&self.selection.selected_handle, "bvh")
            && self.shared.organization_id == authority.organization_id.as_str()
            && self.shared.repository_id == authority.repository_id.as_str()
            && self.shared.mission_id == authority.mission_id.as_str()
            && self.shared.acceptance_contract_id == authority.acceptance_contract_id.as_str()
            && self.shared.plan_revision_id == authority.plan_revision_id.as_str()
            && self.shared.graph_sequence == 1
            && self.shared.work_package_id == package.as_str()
            && self.shared.selection_group_id == group.as_str()
            && exact_oid(&self.shared.base_oid)
            && self.shared.gate_ids == [REPOSITORY_GATE_ID]
            && self.shared.scope_paths == ["PONG.txt"]
            && self.author.attempt_fence == 1
            && self.author.attempt_id == expected_attempt.as_str()
            && self.author.variant_id == authority.variant_id.as_str()
            && self.author.runner_epoch == 1
            && self.author.runner_id == runner.as_str()
            && self.author.workspace_id == workspace.as_str()
            && self.author.authority_digest == authority_digest
            && self.author.policy_snapshot_digest == Digest::of(b"pol").to_hex()
            && candidate.attempt_id == author_attempt
            && candidate.base_sha == self.shared.base_oid
            && exact_oid(&candidate.base_sha)
            && exact_oid(&candidate.head_sha)
            && exact_oid(&candidate.tree_sha)
            && candidate.head_sha != candidate.base_sha
            && self.candidate.row_digest == row_digest
            && self.repository.repository_id == self.shared.repository_id
            && safe_absolute(&self.repository.workspace_path)
            && safe_relative(&self.repository.receipt_relative_path);
        exact
            .then_some(())
            .ok_or_else(|| "SELECTED_SUBJECT_SEMANTIC_VALIDATION_FAILED".into())
    }

    pub(crate) fn effect_authority_binding(
        &self,
    ) -> Result<
        (
            SyntheticSelectedAcquireBody,
            AttemptId,
            String,
            [u8; 32],
            String,
        ),
        String,
    > {
        self.validate()?;
        let runner = RunnerId::from_seed("df-dog1-selected-effect-runner");
        let variant = VariantId::parse(&self.author.variant_id).map_err(invalid)?;
        let package = WorkPackageId::parse(&self.shared.work_package_id).map_err(invalid)?;
        let acquire = SyntheticSelectedAcquireBody::new(
            Digest::from_hex(&self.selection.plan_digest).map_err(invalid)?,
            package.clone(),
            runner.clone(),
            1,
            variant.clone(),
            15,
        )
        .map_err(invalid)?;
        let attempt = AttemptId::from_seed(&acquire.inner().idempotency_key);
        let (workspace, workspace_nonce) = workspace_for_key(&acquire.inner().idempotency_key);
        let authority = AuthorityToken {
            organization_id: OrganizationId::parse(&self.shared.organization_id)
                .map_err(invalid)?,
            repository_id: RepositoryId::parse(&self.shared.repository_id).map_err(invalid)?,
            mission_id: MissionId::parse(&self.shared.mission_id).map_err(invalid)?,
            acceptance_contract_id: AcceptanceContractId::parse(
                &self.shared.acceptance_contract_id,
            )
            .map_err(invalid)?,
            plan_revision_id: PlanRevisionId::parse(&self.shared.plan_revision_id)
                .map_err(invalid)?,
            graph_sequence: self.shared.graph_sequence,
            work_package_id: package,
            selection_group_id: SelectionGroupId::parse(&self.shared.selection_group_id)
                .map_err(invalid)?,
            variant_id: variant,
            attempt_id: attempt.clone(),
            attempt_fence: self
                .author
                .attempt_fence
                .checked_add(1)
                .ok_or("SELECTED_SUBJECT_EFFECT_FENCE_OVERFLOW")?,
            runner_id: runner,
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
        let authority_digest = authority.digest().map_err(invalid)?.to_hex();
        Ok((
            acquire,
            attempt,
            workspace.to_string(),
            workspace_nonce,
            authority_digest,
        ))
    }
}

fn exact_digest(value: &str) -> Result<Digest, String> {
    let digest = Digest::from_hex(value).map_err(|_| "SELECTED_SUBJECT_DIGEST_INVALID")?;
    (digest.to_hex() == value)
        .then_some(digest)
        .ok_or_else(|| "SELECTED_SUBJECT_DIGEST_INVALID".into())
}

fn typed_hex(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|hex| exact_digest(hex).is_ok())
}

fn exact_oid(value: &str) -> bool {
    value.strip_prefix("sha1:").is_some_and(|hex| {
        hex.len() == 40
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| !matches!(part, Component::ParentDir | Component::CurDir))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn invalid(error: impl std::fmt::Display) -> String {
    format!("SELECTED_SUBJECT_ID_INVALID: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::WorkspaceId;

    fn fixture() -> SelectedCandidateSubject {
        SelectedCandidateSubject {
            schema_version: SCHEMA.into(),
            selection: SelectionSubject {
                receipt_digest: "a".repeat(64),
                body_digest: "b".repeat(64),
                plan_digest: "4a1cfc34791033f74f6a1062446db556dc1d97828566173bd64499d3b2bfa3d7"
                    .into(),
                rubric: NONQUALITY_TIEBREAK_V1.into(),
                selected_handle: format!("bvh_{}", "c".repeat(64)),
            },
            shared: SharedSubject {
                organization_id:
                    "org_5bb6e17b857cfb0ef7a9d968652dd9538b6d1d5d83ba19d37884ecfd049d7c93".into(),
                repository_id:
                    "rep_733b85e9f14f9b5c1daf61421ec57bf65d9b3ba459004ef0828a23e4c16565c6".into(),
                mission_id: "mis_5c2547d2a5f07bb2eb2105166255f0d7eb8582312cf096122658de813b9e1f6b"
                    .into(),
                acceptance_contract_id:
                    "acc_b0cb615d5c144cf031b87db64695b0384f6027ddec6feb6673562a29d41906af".into(),
                plan_revision_id:
                    "pln_4c586d3c5ce417206509980aada17e7c2d411d0a8817bb11db8dc5cd7a283373".into(),
                graph_sequence: 1,
                work_package_id:
                    "wpk_6f93021df75899c2d0c316048937e06381d15d603d5d03da4767d6755fb5a36a".into(),
                selection_group_id:
                    "sel_fce9b70264e9f52dcc53b247bcee54bfb44e680cac3d005a6cafef9f9fd959fe".into(),
                base_oid: format!("sha1:{}", "1".repeat(40)),
                gate_ids: vec![REPOSITORY_GATE_ID.into()],
                scope_paths: vec!["PONG.txt".into()],
            },
            author: AuthorSubject {
                variant_id: "var_0be8f4dbce62cf36d40ac07f7605d728b9f4f50d471ab509ce3b7de9271866f9"
                    .into(),
                attempt_id: "atm_8049076a3dd68855f6660ef4ddf64289ca075d606c867a5c7e3b6f1d9591699e"
                    .into(),
                attempt_fence: 1,
                runner_id: "run_0276216d1fab063373af300321f2eb26b8832857880c6ab2bc288988a59498e6"
                    .into(),
                runner_epoch: 1,
                workspace_id:
                    "wsp_c3d6a498226cb8706de9941709486799143d7bfd9617f3c498aa7c05d8770997".into(),
                authority_digest:
                    "601e235bf3113eeff8c148dfb55e35b48a60b4c7a65893c6f6782d4cb790c9be".into(),
                policy_snapshot_digest: Digest::of(b"pol").to_hex(),
            },
            candidate: CandidateSubject {
                candidate_id:
                    "can_d5686f33468b36a22f62cec59140b722029fc59a6e8faa29281ad863154e8a14".into(),
                attempt_id: "atm_8049076a3dd68855f6660ef4ddf64289ca075d606c867a5c7e3b6f1d9591699e"
                    .into(),
                base_oid: format!("sha1:{}", "1".repeat(40)),
                head_oid: format!("sha1:{}", "2".repeat(40)),
                tree_oid: format!("sha1:{}", "3".repeat(40)),
                patch_digest: "0b5081e13dab98caee9b63f0987fd0d995dd1ea5f5bd55650c0e51d75c94e9b4"
                    .into(),
                row_digest: String::new(),
            },
            repository: RepositorySubject {
                repository_id:
                    "rep_733b85e9f14f9b5c1daf61421ec57bf65d9b3ba459004ef0828a23e4c16565c6".into(),
                workspace_path: PathBuf::from("/tmp/selected"),
                receipt_relative_path: "lane-0/repository".into(),
            },
        }
    }

    fn bind_candidate_row(subject: &mut SelectedCandidateSubject) {
        let candidate = Candidate {
            id: CandidateId::parse(&subject.candidate.candidate_id).unwrap(),
            attempt_id: AttemptId::parse(&subject.candidate.attempt_id).unwrap(),
            base_sha: subject.candidate.base_oid.clone(),
            head_sha: subject.candidate.head_oid.clone(),
            tree_sha: subject.candidate.tree_oid.clone(),
            patch_digest: Digest::from_hex(&subject.candidate.patch_digest).unwrap(),
        };
        subject.candidate.row_digest =
            hash_canonical("bullet.synthetic-selection.candidate-row.v1", &candidate).unwrap();
    }

    #[test]
    fn selected_subject_refuses_representative_self_consistent_drifts() {
        let mut valid = fixture();
        bind_candidate_row(&mut valid);
        assert!(valid.validate().is_ok());

        let mut schema = valid.clone();
        schema.schema_version = "retired".into();
        let mut repository = valid.clone();
        repository.shared.repository_id = RepositoryId::from_seed("rebound").to_string();
        repository.repository.repository_id = repository.shared.repository_id.clone();
        let mut candidate = valid.clone();
        candidate.candidate.attempt_id = AttemptId::from_seed("rebound").to_string();
        bind_candidate_row(&mut candidate);
        let mut author = valid;
        author.author.authority_digest = "0".repeat(64);
        for drift in [schema, repository, candidate, author] {
            assert!(drift.validate().is_err());
        }
    }

    #[test]
    fn effect_authority_binding_derives_every_minted_identity() {
        let mut selected = fixture();
        bind_candidate_row(&mut selected);
        let (acquire, attempt, workspace, nonce, authority_digest) =
            selected.effect_authority_binding().expect("binding");
        let expected_attempt = AttemptId::from_seed(&acquire.inner().idempotency_key);
        let (expected_workspace, expected_nonce) =
            workspace_for_key(&acquire.inner().idempotency_key);
        assert_eq!(attempt, expected_attempt);
        assert_eq!(workspace, expected_workspace.as_str());
        assert_eq!(nonce, expected_nonce);
        assert_ne!(attempt, AttemptId::from_seed("rebound-effect-attempt"));
        assert_ne!(
            workspace,
            WorkspaceId::from_seed("rebound-workspace").as_str()
        );
        assert_ne!(nonce, [0; 32]);
        assert_ne!(authority_digest, "0".repeat(64));
    }
}
