use super::{
    refuse_launch_grant_alpha, run_dogfood_read_only, DogfoodReadOnlyOptions, DogfoodRunStatus,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn options() -> DogfoodReadOnlyOptions {
    DogfoodReadOnlyOptions {
        provider: "claude".to_owned(),
        data_dir: PathBuf::from("/tmp/missing-dogfood-data"),
        policy: PathBuf::from("/tmp/missing-policy.json"),
        binding: PathBuf::from("/tmp/missing-binding.json"),
        enrollment: PathBuf::from("/tmp/missing-enrollment.json"),
        issuer: "operator-local".into(),
        key_id: "operator-runner-1".into(),
        executable: PathBuf::from("/usr/bin/true"),
        credentials: Vec::new(),
        workdir: PathBuf::from("/tmp"),
        prompt: Some("fix a stale sentence".into()),
        max_budget_usd: Some(0.25),
        receipt: PathBuf::from("/tmp/missing-receipt.json"),
    }
}

#[test]
fn unknown_and_unimplemented_providers_refuse_before_any_staging() {
    // An unknown name is a typed refusal, never a silent claude fallback.
    let mut unknown = options();
    unknown.provider = "gemini".to_owned();
    let error = run_dogfood_read_only(unknown).expect_err("unknown provider must refuse");
    assert_eq!(error.code, "DOGFOOD_PROVIDER_UNKNOWN");

    // A known provider with no wired dispatch refuses with its own code,
    // before any policy read or staging: the options here point at paths
    // that do not exist, so reaching any later step would surface a
    // different code.
    for provider in ["codex", "cursor", "antigravity"] {
        let mut pending = options();
        pending.provider = provider.to_owned();
        let error = run_dogfood_read_only(pending).expect_err("unimplemented provider must refuse");
        assert_eq!(error.code, "DOGFOOD_PROVIDER_UNIMPLEMENTED", "{provider}");
    }
}

#[test]
fn passported_runtime_is_none_outside_the_deployment_prefix_and_required_inside() {
    // Outside the frozen prefix, nothing changes: no passport is consulted.
    use std::path::Path;
    let outside =
        super::passported_runtime(Path::new("/usr/bin/true")).expect("non-deployment path is fine");
    assert!(outside.is_none());

    // Inside the prefix, a missing passport is a typed refusal, never a
    // silent fall back to the 64 MiB unpassported path.
    let error = super::passported_runtime(Path::new(
        "/usr/lib/bullet/providers/claude/0.0.0-test-absent/bin/claude",
    ))
    .expect_err("deployment path without a passport must refuse");
    assert_eq!(error.code, "DOGFOOD_PASSPORT_MISSING");

    // A malformed layout under the prefix refuses with its own code.
    let error = super::passported_runtime(Path::new("/usr/lib/bullet/providers/claude"))
        .expect_err("prefix with no version segment must refuse");
    assert_eq!(error.code, "DOGFOOD_PASSPORT_LAYOUT");
}

#[test]
fn run_evidence_is_create_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence.proposal.json");
    super::write_create_once_0600(&path, b"{}").expect("first write");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "evidence must be owner-private");
    let error = super::write_create_once_0600(&path, b"{}")
        .expect_err("a rerun must never overwrite evidence");
    assert_eq!(error.code, "DOGFOOD_ARTIFACT_EXISTS");
}

#[test]
fn launch_grant_alpha_is_refused() {
    assert!(refuse_launch_grant_alpha("bullet-kernel", "launch-grant-alpha").is_err());
    assert!(refuse_launch_grant_alpha("operator-local", "operator-runner-1").is_ok());
}

#[test]
fn live_enabled_policy_fixture_is_refused() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/policy-v1alpha2-live-enabled.json");
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.json");
    std::fs::copy(&source, &policy).unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut options = options();
    options.policy = policy;
    options.prompt = Some("x".into());
    match run_dogfood_read_only(options) {
        Err(error) => assert_eq!(error.code, "DOGFOOD_REFUSES_LIVE_ADMISSION"),
        Ok(DogfoodRunStatus::Neutral { code, .. }) => {
            panic!("expected live refuse, got neutral {code}");
        }
        Ok(DogfoodRunStatus::Succeeded { .. }) => panic!("live policy must not compose"),
    }
}

#[test]
fn missing_prompt_is_designed_neutral() {
    let mut options = options();
    options.prompt = None;
    match run_dogfood_read_only(options).unwrap() {
        DogfoodRunStatus::Neutral { code, .. } => assert_eq!(code, "DOGFOOD_PROMPT_MISSING"),
        other => panic!("expected neutral, got {other:?}"),
    }
}
