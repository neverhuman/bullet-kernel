//! Table-driven mutation of every launch-grant claim field: shape violations
//! refuse before signing; bound-subject deviations refuse at verification with
//! the field named; no mutation ever consumes the nonce.

use bullet_harness_core::launch_grant::{
    decode_canonical, verify_launch_grant, LaunchGrantClaims, LaunchGrantExpectation,
    LaunchGrantSigningKey, LaunchGrantVerificationKey, LeaseBinding, MemoryNonceLedger,
    PolicyBinding, ProviderBinding,
};
use bullet_harness_core::{HarnessError, ProviderProtocol};
use serde_json::Value;

/// Fixture-only key material shared with bullet-wire's golden generator.
const SECRET_KEY: [u8; 64] = [
    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125, 159,
    133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3, 253, 112,
    96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177,
    162,
];
const GOLDEN: &str = include_str!("fixtures/launch-grant-golden.json");

fn golden_claims() -> LaunchGrantClaims {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    decode_canonical(golden["claims_canonical_json"].as_str().unwrap().as_bytes()).unwrap()
}

fn signer() -> LaunchGrantSigningKey {
    LaunchGrantSigningKey::from_bytes("bullet-kernel-local", "authority-test-1", &SECRET_KEY)
        .unwrap()
}

fn verifier() -> LaunchGrantVerificationKey {
    signer().verification_key().unwrap()
}

fn expectation(claims: &LaunchGrantClaims, now_unix_ms: u64, live: bool) -> LaunchGrantExpectation {
    LaunchGrantExpectation {
        now_unix_ms,
        lease: LeaseBinding {
            mission_id: claims.mission_id.clone(),
            repository_id: claims.repository_id.clone(),
            graph_revision_id: claims.graph_revision_id.clone(),
            work_package_id: claims.work_package_id.clone(),
            variant_id: claims.variant_id.clone(),
            attempt_id: claims.attempt_id.clone(),
            attempt_fence: claims.attempt_fence,
            runner_id: claims.runner_id.clone(),
            runner_epoch: claims.runner_epoch,
            workspace_id: claims.workspace_id.clone(),
            workspace_nonce_digest: claims.workspace_nonce_digest.clone(),
            authority_epoch: claims.authority_epoch,
            freeze_generation: claims.freeze_generation,
        },
        provider: ProviderBinding {
            provider: claims.provider.clone(),
            adapter: claims.adapter.clone(),
            provider_profile_id: claims.provider_profile_id.clone(),
            model: claims.model.clone(),
            credential_generation: claims.credential_generation,
            protocol: ProviderProtocol::ClaudeStreamJson,
            executable_path: claims.executable_path.clone(),
            executable_digest: claims.executable_digest.clone(),
            descriptor_digest: claims.descriptor_digest.clone(),
            capability_digest: claims.capability_digest.clone(),
            sandbox_manifest_digest: claims.sandbox_manifest_digest.clone(),
            environment_digest: claims.environment_digest.clone(),
        },
        policy: PolicyBinding {
            policy_snapshot_digest: claims.policy_snapshot_digest.clone(),
            policy_generation: claims.policy_generation,
            live_admission_enabled: live,
        },
    }
}

fn ledger_for(claims: &LaunchGrantClaims) -> MemoryNonceLedger {
    let mut ledger = MemoryNonceLedger::new();
    assert!(ledger.register(
        &claims.grant_nonce,
        &claims.attempt_id,
        claims.expires_at_unix_ms
    ));
    ledger
}

type Mutation = fn(&mut LaunchGrantClaims);

#[test]
fn every_shape_violation_is_a_typed_refusal_before_signing() {
    let hex64 = "a".repeat(64);
    let cases: [(&str, Mutation, &str); 31] = [
        (
            "schema",
            |c| c.schema_version = "v1".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "audience",
            |c| c.audience = "bullet-gitd".into(),
            "LAUNCH_GRANT_AUDIENCE_MISMATCH",
        ),
        (
            "operation",
            |c| c.operation = "apply-patch".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "issuer",
            |c| c.issuer = "bad issuer".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "key_id",
            |c| c.key_id = String::new(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "grant_id",
            |c| c.grant_id.truncate(63),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "grant_nonce",
            |c| c.grant_nonce = "G".repeat(64),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "mission_id",
            |c| c.mission_id = "mis_short".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "repository_id",
            |c| c.repository_id = c.mission_id.clone(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "graph_revision_id",
            |c| c.graph_revision_id = c.mission_id.clone(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "work_package_id",
            |c| c.work_package_id.push('a'),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "variant_id",
            |c| c.variant_id = c.variant_id.replace("var_", "VAR_"),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "attempt_id",
            |c| c.attempt_id = c.attempt_id.replace("atm_", "run_"),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "attempt_fence",
            |c| c.attempt_fence = 0,
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "runner_id",
            |c| c.runner_id = "run_".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "runner_epoch",
            |c| c.runner_epoch = 1 << 60,
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "workspace_id",
            |c| c.workspace_id = c.attempt_id.clone(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "workspace_nonce_digest",
            |c| c.workspace_nonce_digest = "zz".repeat(32),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "provider",
            |c| c.provider = "gemini".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "adapter",
            |c| c.adapter = "with space".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "provider_profile_id",
            |c| c.provider_profile_id = "profile-1".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "model",
            |c| c.model = "claude\u{0}".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "protocol",
            |c| c.protocol = "claude_stream_yaml".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "executable_path",
            |c| c.executable_path = "usr/bin/claude".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "executable_path_dotdot",
            |c| c.executable_path = "/usr/../bin/claude".into(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "policy_generation",
            |c| c.policy_generation = 0,
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "gate_ids_empty",
            |c| c.gate_ids.clear(),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "gate_ids_duplicate",
            |c| c.gate_ids.push(c.gate_ids[0].clone()),
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "gate_ids_command",
            |c| c.gate_ids = vec!["cargo test".into()],
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "max_invocations",
            |c| c.max_invocations = 0,
            "LAUNCH_GRANT_INVALID",
        ),
        (
            "max_wall_clock_ms",
            |c| c.max_wall_clock_ms = 0,
            "LAUNCH_GRANT_INVALID",
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut claims = golden_claims();
        mutate(&mut claims);
        let error = claims
            .validate_shape()
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(error.reason_code(), expected, "{name}: {error}");
        assert_eq!(
            signer().sign(&claims).unwrap_err().reason_code(),
            expected,
            "{name}"
        );
    }
    let mut too_many_gates = golden_claims();
    too_many_gates.gate_ids = (0..17).map(|i| format!("gat_{:064x}", i)).collect();
    assert_eq!(
        too_many_gates.validate_shape().unwrap_err().reason_code(),
        "LAUNCH_GRANT_INVALID"
    );
    let mut digest = golden_claims();
    digest.executable_digest = hex64;
    assert!(digest.validate_shape().is_ok());
}

#[test]
fn window_bounds_and_ttl_are_enforced() {
    let mut inverted = golden_claims();
    inverted.not_before_unix_ms = inverted.expires_at_unix_ms;
    assert_eq!(
        inverted.validate_shape().unwrap_err().reason_code(),
        "LAUNCH_GRANT_INVALID"
    );
    let mut issued_late = golden_claims();
    issued_late.issued_at_unix_ms = issued_late.not_before_unix_ms + 1;
    assert_eq!(
        issued_late.validate_shape().unwrap_err().reason_code(),
        "LAUNCH_GRANT_INVALID"
    );
    let mut long = golden_claims();
    long.expires_at_unix_ms = long.not_before_unix_ms + 15_001;
    assert_eq!(
        long.validate_shape().unwrap_err().reason_code(),
        "LAUNCH_GRANT_TTL_EXCEEDED"
    );
    let mut unsafe_integer = golden_claims();
    unsafe_integer.expires_at_unix_ms = 1 << 53;
    unsafe_integer.not_before_unix_ms = (1 << 53) - 1;
    assert_eq!(
        unsafe_integer.validate_shape().unwrap_err().reason_code(),
        "LAUNCH_GRANT_INVALID"
    );
}

#[test]
fn every_bound_subject_field_is_compared_exactly() {
    let cases: [(&str, Mutation); 27] = [
        ("mission_id", |c| {
            c.mission_id = format!("mis_{}", "1".repeat(64))
        }),
        ("repository_id", |c| {
            c.repository_id = format!("rep_{}", "1".repeat(64))
        }),
        ("graph_revision_id", |c| {
            c.graph_revision_id = format!("grf_{}", "1".repeat(64))
        }),
        ("work_package_id", |c| {
            c.work_package_id = format!("wpk_{}", "1".repeat(64))
        }),
        ("variant_id", |c| {
            c.variant_id = format!("var_{}", "1".repeat(64))
        }),
        ("attempt_id", |c| {
            c.attempt_id = format!("atm_{}", "1".repeat(64))
        }),
        ("attempt_fence", |c| c.attempt_fence += 1),
        ("runner_id", |c| {
            c.runner_id = format!("run_{}", "1".repeat(64))
        }),
        ("runner_epoch", |c| c.runner_epoch += 1),
        ("workspace_id", |c| {
            c.workspace_id = format!("wsp_{}", "1".repeat(64))
        }),
        ("workspace_nonce_digest", |c| {
            c.workspace_nonce_digest = "1".repeat(64)
        }),
        ("authority_epoch", |c| c.authority_epoch += 1),
        ("freeze_generation", |c| c.freeze_generation += 1),
        ("provider", |c| c.provider = "codex".into()),
        ("adapter", |c| c.adapter = "other-adapter".into()),
        ("provider_profile_id", |c| {
            c.provider_profile_id = format!("prf_{}", "1".repeat(64))
        }),
        ("model", |c| c.model = "other-model".into()),
        ("credential_generation", |c| c.credential_generation += 1),
        ("protocol", |c| c.protocol = "codex_app_server_jsonl".into()),
        ("executable_path", |c| {
            c.executable_path = "/usr/bin/claude".into()
        }),
        ("executable_digest", |c| {
            c.executable_digest = "1".repeat(64)
        }),
        ("descriptor_digest", |c| {
            c.descriptor_digest = "1".repeat(64)
        }),
        ("capability_digest", |c| {
            c.capability_digest = "1".repeat(64)
        }),
        ("sandbox_manifest_digest", |c| {
            c.sandbox_manifest_digest = "1".repeat(64)
        }),
        ("environment_digest", |c| {
            c.environment_digest = "1".repeat(64)
        }),
        ("policy_snapshot_digest", |c| {
            c.policy_snapshot_digest = "1".repeat(64)
        }),
        ("policy_generation", |c| c.policy_generation += 1),
    ];
    let expected_claims = golden_claims();
    let now = expected_claims.not_before_unix_ms;
    for (field, mutate) in cases {
        let mut claims = golden_claims();
        mutate(&mut claims);
        let grant = signer().sign(&claims).unwrap();
        let mut ledger = ledger_for(&claims);
        let error = verify_launch_grant(
            &grant,
            &verifier(),
            &expectation(&expected_claims, now, true),
            &mut ledger,
        )
        .unwrap_err();
        assert_eq!(
            error.reason_code(),
            "LAUNCH_GRANT_SUBJECT_MISMATCH",
            "{field}"
        );
        assert_eq!(
            error,
            HarnessError::LaunchGrantSubjectMismatch {
                field: field.to_string()
            }
        );
        assert!(!ledger.is_consumed(&claims.grant_nonce), "{field}");
    }
}
