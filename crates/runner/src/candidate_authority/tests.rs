use super::*;
use bullet_application::ActiveLease;
use bullet_domain::{
    AcceptanceContractId, Attempt, AttemptId, AttemptState, AuthorityToken, Digest, MissionId,
    OrganizationId, PlanRevisionId, RepositoryId, RunnerId, SelectionGroupId, VariantId,
    WorkPackageId, WorkspaceId,
};
use bullet_harness_core::candidate_preparation::{
    candidate_preparation_envelope_digest, candidate_preparation_scope_paths_digest,
    canonical_candidate_preparation_json, CandidatePreparationSigningKey,
};
use std::os::unix::fs::{symlink, PermissionsExt};

const REQUEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn granted_scope() -> Vec<String> {
    vec!["src".into(), "docs".into()]
}

pub(crate) fn acquire_grant() -> AcquireGrant {
    let work_package_id = WorkPackageId::from_seed("candidate-work-package");
    let variant_id = VariantId::from_seed("candidate-variant");
    let attempt_id = AttemptId::from_seed("candidate-attempt");
    let runner_id = RunnerId::from_seed("candidate-runner");
    let workspace_id = WorkspaceId::from_seed("candidate-workspace");
    let workspace_nonce = *Digest::of(b"candidate-workspace-nonce").as_bytes();
    let attempt = Attempt {
        id: attempt_id.clone(),
        variant_id: variant_id.clone(),
        work_package_id: work_package_id.clone(),
        fence: 7,
        runner_id: runner_id.clone(),
        runner_epoch: 3,
        workspace_id: workspace_id.clone(),
        workspace_nonce,
        scope_revision: 5,
        context_revision: 9,
        state: AttemptState::Preparing,
    };
    let authority_token = AuthorityToken {
        organization_id: OrganizationId::from_seed("candidate-organization"),
        repository_id: RepositoryId::from_seed("candidate-repository"),
        mission_id: MissionId::from_seed("candidate-mission"),
        acceptance_contract_id: AcceptanceContractId::from_seed("candidate-acceptance"),
        plan_revision_id: PlanRevisionId::from_seed("candidate-plan"),
        graph_sequence: 11,
        work_package_id: work_package_id.clone(),
        selection_group_id: SelectionGroupId::from_seed("candidate-selection"),
        variant_id: variant_id.clone(),
        attempt_id: attempt_id.clone(),
        attempt_fence: 7,
        runner_id: runner_id.clone(),
        runner_epoch: 3,
        workspace_id,
        workspace_nonce,
        scope_revision: 5,
        context_revision: 9,
        config_snapshot_hash: Digest::of(b"candidate-config"),
        policy_snapshot_hash: Digest::of(b"candidate-policy"),
        routing_policy_hash: Digest::of(b"candidate-routing"),
        credential_profile_id: None,
        credential_generation: None,
    };
    AcquireGrant {
        attempt,
        authority_token,
        lease: ActiveLease {
            variant_id,
            attempt_id,
            fence: 7,
            runner_id,
            runner_epoch: 3,
            workspace_nonce,
            heartbeat_at: "2026-08-27T00:00:00Z".into(),
            expires_at: "2026-08-27T00:00:15Z".into(),
            ttl_seconds: 15,
        },
    }
}

fn claims(grant: &AcquireGrant, not_before: u64, expires: u64) -> CandidatePreparationGrantV1 {
    let token = &grant.authority_token;
    let seed = Digest::of(grant.attempt.id.as_str().as_bytes()).to_hex();
    CandidatePreparationGrantV1 {
        schema_version: "v1alpha1".into(),
        candidate_preparation_grant_id: format!("cpg_{seed}"),
        issuer: "kernel-local".into(),
        key_id: "candidate-preparation-1".into(),
        signing_purpose: "candidate-preparation-grant-signing".into(),
        claims_domain: "candidate-preparation.grant.v1alpha1".into(),
        envelope_domain: "candidate-preparation.envelope.v1alpha1".into(),
        request_digest: REQUEST_DIGEST.into(),
        authority_token_digest: token.digest().unwrap().to_hex(),
        grant_nonce: Digest::of(format!("candidate-nonce:{seed}").as_bytes()).to_hex(),
        repository_id: token.repository_id.to_string(),
        mission_id: token.mission_id.to_string(),
        plan_revision_id: token.plan_revision_id.to_string(),
        work_package_id: token.work_package_id.to_string(),
        variant_id: token.variant_id.to_string(),
        attempt_id: token.attempt_id.to_string(),
        attempt_fence: token.attempt_fence,
        runner_id: token.runner_id.to_string(),
        runner_epoch: token.runner_epoch,
        workspace_id: token.workspace_id.to_string(),
        scope_grant_digest: candidate_preparation_scope_paths_digest(&granted_scope()).unwrap(),
        scope_revision: token.scope_revision,
        context_revision: token.context_revision,
        change_id: format!("chg_{seed}"),
        graph_revision_id: format!("grf_{seed}"),
        parent_candidate_ids: Vec::new(),
        context_capsule_id: format!("cnt_{seed}"),
        execution_envelope_id: format!("exe_{seed}"),
        environment_digest: Digest::of(b"candidate-environment").to_hex(),
        toolchain_digest: Digest::of(b"candidate-toolchain").to_hex(),
        authority_epoch: 13,
        freeze_generation: 2,
        issued_at_unix_ms: not_before,
        not_before_unix_ms: not_before,
        expires_at_unix_ms: expires,
    }
}

fn response(
    signer: &CandidatePreparationSigningKey,
    claims: &CandidatePreparationGrantV1,
) -> CandidatePreparationGrant {
    let signed = signer.sign(claims).unwrap();
    let canonical =
        String::from_utf8(canonical_candidate_preparation_json(&signed).unwrap()).unwrap();
    let digest = candidate_preparation_envelope_digest(&signed).unwrap();
    CandidatePreparationGrant::test_only(
        AttemptId::parse(&claims.attempt_id).unwrap(),
        claims.request_digest.clone(),
        claims.candidate_preparation_grant_id.clone(),
        canonical,
        signed,
        digest,
    )
}

fn signer() -> CandidatePreparationSigningKey {
    CandidatePreparationSigningKey::generate("kernel-local", "candidate-preparation-1").unwrap()
}

#[test]
fn authenticated_subject_time_key_and_replay_fail_closed() {
    let grant = acquire_grant();
    let signer = signer();
    let exact_claims = claims(&grant, 100, 200);
    let exact = response(&signer, &exact_claims);
    let scope = granted_scope();
    let admission = CandidatePreparationAdmission::from_verification_key(
        REQUEST_DIGEST,
        signer.verification_key().unwrap(),
    )
    .unwrap();
    let verified = admission.verify_at(&exact, &grant, &scope, 150).unwrap();
    assert_eq!(verified.claims(), &exact_claims);
    assert_eq!(verified.signed(), exact.signed_grant());
    assert_eq!(
        admission
            .verify_at(&exact, &grant, &scope, 150)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_REPLAYED"
    );

    let mut changed = exact_claims.clone();
    changed.scope_revision += 1;
    let stale = response(&signer, &changed);
    let fresh_admission = || {
        CandidatePreparationAdmission::from_verification_key(
            REQUEST_DIGEST,
            signer.verification_key().unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        fresh_admission()
            .verify_at(&stale, &grant, &scope, 150)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_SUBJECT_MISMATCH"
    );
    assert_eq!(
        fresh_admission()
            .verify_at(&exact, &grant, &scope, 99)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_NOT_YET_VALID"
    );
    assert_eq!(
        fresh_admission()
            .verify_at(&exact, &grant, &scope, 200)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_EXPIRED"
    );

    let wrong = CandidatePreparationSigningKey::generate("other-kernel", "other-key").unwrap();
    let wrong_admission = CandidatePreparationAdmission::from_verification_key(
        REQUEST_DIGEST,
        wrong.verification_key().unwrap(),
    )
    .unwrap();
    assert_eq!(
        wrong_admission
            .verify_at(&exact, &grant, &scope, 150)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_KEY_UNKNOWN"
    );
    let scope_admission = fresh_admission();
    assert_eq!(
        scope_admission
            .verify_at(&exact, &grant, &["other".into()], 150)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_SUBJECT_MISMATCH"
    );
    assert!(scope_admission
        .verify_at(&exact, &grant, &scope, 150)
        .is_ok());
}

#[test]
fn protected_public_key_record_is_exact() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("candidate-public.json");
    let signer = signer();
    let record = serde_json::json!({
        "schema_version": "v1alpha1",
        "issuer": "kernel-local",
        "key_id": "candidate-preparation-1",
        "public_key_hex": signer.public_key_hex(),
    });
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let admission = CandidatePreparationAdmission::from_key_file(REQUEST_DIGEST, &path).unwrap();
    assert_eq!(admission.request_digest(), REQUEST_DIGEST);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        CandidatePreparationAdmission::from_key_file(REQUEST_DIGEST, &path)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let duplicate = format!(
        "{{\"schema_version\":\"v1alpha1\",\"issuer\":\"kernel-local\",\"key_id\":\"candidate-preparation-1\",\"public_key_hex\":\"{}\",\"key_id\":\"candidate-preparation-1\"}}",
        signer.public_key_hex()
    );
    std::fs::write(&path, duplicate).unwrap();
    assert!(CandidatePreparationAdmission::from_key_file(REQUEST_DIGEST, &path).is_err());
    assert!(CandidatePreparationAdmission::from_key_file("A".repeat(64), &path).is_err());

    let target = root.path().join("target.json");
    std::fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert!(CandidatePreparationAdmission::from_key_file(REQUEST_DIGEST, &path).is_err());
    assert!(
        CandidatePreparationAdmission::from_key_file(REQUEST_DIGEST, Path::new("relative"))
            .is_err()
    );
}
