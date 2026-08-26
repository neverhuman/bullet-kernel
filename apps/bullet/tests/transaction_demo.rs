//! Transaction-component negatives and the Kernel consumer proving that
//! production gitd still refuses clone. The fixture saga is `just demo`.

use bullet_domain::{GateOutcome, REASON_ZERO_TESTS};
use bullet_harness_core::transaction_proof::{
    verify_transaction_component, TransactionComponentSigningKey, TransactionComponentSubject,
    TRANSACTION_COMPONENT_CLASS, TRANSACTION_COMPONENT_SCHEMA_VERSION, TRANSACTION_COMPONENT_TRUST,
};
use bullet_runner_core::{gitd_binary, GitdSession};
use serde_json::json;
use std::process::Command;

const TRANSACTION_DEMO_ROOT_SOURCE: &str = include_str!("../src/bin/transaction_demo.rs");
const TRANSACTION_DEMO_SOURCE: &str = include_str!("../src/bin/transaction_demo/app.rs");
const TRANSACTION_DEMO_SUPPORT_SOURCE: &str =
    include_str!("../src/bin/transaction_demo/support.rs");
const VERIFIER_BINARY_SOURCE: &str = include_str!("../src/bin/transaction_demo/verifier_binary.rs");

fn subject() -> TransactionComponentSubject {
    TransactionComponentSubject {
        schema_version: TRANSACTION_COMPONENT_SCHEMA_VERSION.into(),
        evidence_class: TRANSACTION_COMPONENT_CLASS.into(),
        signing_trust: TRANSACTION_COMPONENT_TRUST.into(),
        transaction_gate_eligible: false,
        fence_first: 1,
        fence_second: 2,
        attempt_first: "atm_1".into(),
        attempt_second: "atm_2".into(),
        candidate_id: "can_1".into(),
        verifier_outcome: "FAIL".into(),
        writer_proof_refused: true,
        effect_unknown: "OUTCOME_UNKNOWN".into(),
        effect_settled: "ORPHANED_REMOTE".into(),
        stale_refused: true,
        gitd_fixture: true,
        command_id: "cmd_1".into(),
        command_phase: "pending".into(),
    }
}

#[test]
fn signed_transaction_component_roundtrip() {
    let key =
        TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1").expect("key");
    let proof = key.sign(&subject()).expect("sign");
    verify_transaction_component(&proof).expect("verify");

    assert!(TRANSACTION_DEMO_SOURCE.contains("tempfile::Builder::new()"));
    assert!(TRANSACTION_DEMO_SOURCE.contains(".prefix(\"bullet-txn.\")"));
    assert!(!TRANSACTION_DEMO_SOURCE.contains("std::process::id()"));
    assert!(!TRANSACTION_DEMO_SOURCE.contains("fn free_port("));
    assert!(TRANSACTION_DEMO_ROOT_SOURCE.contains("mod transaction_demo"));
    assert!(TRANSACTION_DEMO_ROOT_SOURCE.contains("mod app;"));
    assert!(TRANSACTION_DEMO_ROOT_SOURCE.contains("mod support;"));
    assert!(TRANSACTION_DEMO_ROOT_SOURCE.contains("mod verifier_binary;"));
    assert!(TRANSACTION_DEMO_ROOT_SOURCE.contains("app::main_entry()"));
    assert!(!TRANSACTION_DEMO_ROOT_SOURCE.contains("#[path"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains(".arg(\"127.0.0.1:0\")"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains(".arg(\"--fixture-lease-peer-registration\")"));
    assert!(TRANSACTION_DEMO_SOURCE.contains("fs::Permissions::from_mode(0o710)"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("fs::metadata(\"/proc/self\")"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("SignedLeaseRpcClient::new_admitted("));
    assert!(!TRANSACTION_DEMO_SUPPORT_SOURCE.contains("SignedLeaseRpcClient::new("));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("struct LeaseHeartbeatGuard"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("Duration::from_secs(3)"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("MissedTickBehavior::Delay"));
    assert!(TRANSACTION_DEMO_SOURCE.contains("heartbeat.stop().await?"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("impl Drop for FarmdGuard"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE
        .contains("const FARMD_BIN_ENV: &str = \"BULLET_FARMD_BIN\";"));
    assert!(VERIFIER_BINARY_SOURCE.contains("const FD_ENV: &str = \"BULLET_VERIFIER_FIXTURE_FD\";"));
    assert!(VERIFIER_BINARY_SOURCE
        .contains("const DIGEST_ENV: &str = \"BULLET_VERIFIER_FIXTURE_SHA256\";"));
    assert!(VERIFIER_BINARY_SOURCE.contains("MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING"));
    assert!(VERIFIER_BINARY_SOURCE.contains("SourceIdentity::from_metadata(&after) != before"));
    assert!(!VERIFIER_BINARY_SOURCE.contains("BULLET_VERIFIER_FIXTURE_BIN"));
    assert!(VERIFIER_BINARY_SOURCE.contains("SealFlags::WRITE"));
    assert!(VERIFIER_BINARY_SOURCE.contains("/proc/self/fd/"));
    assert!(VERIFIER_BINARY_SOURCE.contains("#[cfg(target_os = \"linux\")]"));
    assert!(VERIFIER_BINARY_SOURCE.contains("#[cfg(not(target_os = \"linux\"))]"));
    assert!(VERIFIER_BINARY_SOURCE
        .contains("verifier fixture execution requires Linux sealed-memfd admission"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("verifier_fixture_binary()?"));
    assert!(!TRANSACTION_DEMO_SUPPORT_SOURCE.contains("kernel_bin(\"bullet-verifier"));
    assert!(!TRANSACTION_DEMO_SUPPORT_SOURCE.contains("BULLET_VERIFIER_BIN"));
    assert!(!TRANSACTION_DEMO_SUPPORT_SOURCE.contains("BULLET_BULLET_"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("impl Drop for ProcessGuard"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains(".process_group(0)"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("kill_process_group_members"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("fn write_request"));
    assert!(TRANSACTION_DEMO_SUPPORT_SOURCE.contains("verifier stdin pipe missing"));
    let work = TRANSACTION_DEMO_SOURCE
        .find("let gitd_work = async")
        .unwrap();
    let shutdown = TRANSACTION_DEMO_SOURCE.find("gitd.kill().await").unwrap();
    let reconciliation = TRANSACTION_DEMO_SOURCE
        .find("match (gitd_work, gitd_shutdown)")
        .unwrap();
    assert!(work < shutdown && shutdown < reconciliation);
    assert_eq!(
        TRANSACTION_DEMO_SOURCE.matches("gitd.kill().await").count(),
        1
    );
    assert!(TRANSACTION_DEMO_SOURCE.contains("farmd.stop()?"));

    let missing = "/definitely/missing/bullet-farmd";
    let refused = Command::new(env!("CARGO_BIN_EXE_transaction_demo"))
        .env("BULLET_FARMD_BIN", missing)
        .output()
        .expect("run transaction demo with exact override");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains(missing));
}

#[test]
fn painted_success_and_stale_pass_cannot_be_signed() {
    let key =
        TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1").expect("key");
    let mut painted = subject();
    painted.command_phase = "verified".into();
    assert!(key.sign(&painted).is_err());
    let mut stale = subject();
    stale.stale_refused = false;
    assert!(key.sign(&stale).is_err());
}

#[test]
fn self_signed_component_cannot_claim_transaction_admission() {
    let key =
        TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1").expect("key");
    let mut promoted = subject();
    promoted.transaction_gate_eligible = true;
    assert!(key.sign(&promoted).is_err());

    let mut relabelled = subject();
    relabelled.evidence_class = "TRANSACTION_PROOF".into();
    assert!(key.sign(&relabelled).is_err());
}

#[test]
fn zero_tests_never_satisfy_a_blocking_gate() {
    assert!(!GateOutcome::NotRun.satisfies_requirement());
    assert_eq!(REASON_ZERO_TESTS, "ZERO_TESTS");
}

#[tokio::test]
async fn production_gitd_constructor_child_still_refuses_clone() {
    let binary = gitd_binary().expect("family proof requires an admitted production daemon");
    let temp = tempfile::tempdir().expect("tempdir");
    let token = json!({
        "organization_id": "org_x",
        "variant_id": format!("var_{}", "2".repeat(64)),
        "attempt_id": format!("atm_{}", "1".repeat(64)),
        "attempt_fence": 1,
        "workspace_nonce": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
    });
    let mut session = GitdSession::spawn_with(binary, std::iter::empty::<&str>(), token)
        .await
        .expect("spawn production gitd");
    let error = session
        .invoke(
            "clone",
            json!({
                "source_repo": "/does/not/matter",
                "base_sha": format!("sha1:{}", "a".repeat(40)),
                "root": temp.path().join("farm").display().to_string(),
                "created_at": "2026-08-24T00:00:00Z",
                "allowed_prefixes": ["src"],
                "commit_date": "2026-08-24T00:00:00+00:00"
            }),
        )
        .await
        .expect_err("production authority remains unavailable");
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
    let _ = session.kill().await;
}
