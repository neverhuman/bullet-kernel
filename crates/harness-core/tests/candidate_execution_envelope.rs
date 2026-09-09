use bullet_harness_core::candidate_preparation::{
    execution_envelope_digest, execution_toolchain_digest, validate_candidate_preparation_binding,
    validate_execution_envelope, CandidatePreparationGrantV1, ExecutionEnvelopeV1, ExecutionToolV1,
};

fn id(prefix: &str, byte: char) -> String {
    format!("{prefix}_{}", byte.to_string().repeat(64))
}

fn envelope() -> ExecutionEnvelopeV1 {
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: id("etl", '1'),
        role: "git".into(),
        executable_path: "/usr/bin/git".into(),
        executable_digest: "2".repeat(64),
        descriptor_digest: "3".repeat(64),
        version: "2.45.2".into(),
    }];
    ExecutionEnvelopeV1 {
        schema_version: "v1alpha1".into(),
        execution_envelope_id: id("exe", '4'),
        issuer: "bullet-kernel".into(),
        key_id: "execution-1".into(),
        signing_purpose: "execution-envelope-signing".into(),
        claims_domain: "execution.envelope.v1alpha1".into(),
        runner_id: id("run", '5'),
        runner_epoch: 1,
        provider: "simulator".into(),
        model: "deterministic".into(),
        adapter: "simulator-v1".into(),
        provider_profile_id: id("prf", '6'),
        platform: "linux-x86_64".into(),
        containment_profile_id: id("ctp", '7'),
        environment_digest: "8".repeat(64),
        toolchain_digest: execution_toolchain_digest(&tools).unwrap(),
        sandbox_image_digest: "9".repeat(64),
        tools,
        authority_epoch: 1,
        freeze_generation: 0,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 16_000,
    }
}

fn grant(envelope: &ExecutionEnvelopeV1) -> CandidatePreparationGrantV1 {
    CandidatePreparationGrantV1 {
        schema_version: "v1alpha1".into(),
        candidate_preparation_grant_id: id("cpg", 'a'),
        issuer: "bullet-kernel".into(),
        key_id: "candidate-1".into(),
        signing_purpose: "candidate-preparation-grant-signing".into(),
        claims_domain: "candidate-preparation.grant.v1alpha1".into(),
        envelope_domain: "candidate-preparation.envelope.v1alpha1".into(),
        request_digest: "b".repeat(64),
        authority_token_digest: "c".repeat(64),
        grant_nonce: "d".repeat(64),
        repository_id: id("rep", 'e'),
        mission_id: id("mis", 'f'),
        plan_revision_id: id("pln", '1'),
        work_package_id: id("wpk", '2'),
        variant_id: id("var", '3'),
        attempt_id: id("atm", '4'),
        attempt_fence: 1,
        runner_id: envelope.runner_id.clone(),
        runner_epoch: envelope.runner_epoch,
        workspace_id: id("wsp", '5'),
        scope_grant_digest: "6".repeat(64),
        scope_revision: 1,
        context_revision: 1,
        change_id: id("chg", '7'),
        graph_revision_id: id("grf", '8'),
        parent_candidate_ids: vec![],
        context_capsule_id: id("cnt", '9'),
        execution_envelope_id: envelope.execution_envelope_id.clone(),
        environment_digest: envelope.environment_digest.clone(),
        toolchain_digest: envelope.toolchain_digest.clone(),
        authority_epoch: envelope.authority_epoch,
        freeze_generation: envelope.freeze_generation,
        issued_at_unix_ms: 2_000,
        not_before_unix_ms: 2_000,
        expires_at_unix_ms: 10_000,
    }
}

#[test]
fn execution_envelope_binds_the_ordered_tool_manifest() {
    let envelope = envelope();
    validate_execution_envelope(&envelope).unwrap();
    assert_eq!(
        execution_envelope_digest(&envelope).unwrap(),
        execution_envelope_digest(&envelope).unwrap()
    );
    let mut changed = envelope.clone();
    changed.tools[0].version = "different".into();
    assert_eq!(
        validate_execution_envelope(&changed)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
}

#[test]
fn binding_refuses_environment_time_and_runner_substitution() {
    let envelope = envelope();
    let valid = grant(&envelope);
    validate_candidate_preparation_binding(&valid, &envelope).unwrap();
    for changed in [
        {
            let mut value = valid.clone();
            value.environment_digest = "0".repeat(64);
            value
        },
        {
            let mut value = valid.clone();
            value.runner_epoch = 2;
            value
        },
        {
            let mut value = valid;
            value.expires_at_unix_ms = envelope.expires_at_unix_ms + 1;
            value
        },
    ] {
        assert_eq!(
            validate_candidate_preparation_binding(&changed, &envelope)
                .unwrap_err()
                .reason_code(),
            "CANDIDATE_PREPARATION_GRANT_INVALID"
        );
    }
}
