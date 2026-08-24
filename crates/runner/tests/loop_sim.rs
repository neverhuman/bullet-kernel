//! Production BulletGit authority refusal is exact, typed, and repository-inert.

mod support;

use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, DirectLeaseClient, MemoryJournal, MonotonicClock,
    RunnerError,
};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git observation");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[tokio::test]
async fn production_authority_refusal_is_typed_and_repository_inert() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let before_tree = git(&origin, &["rev-parse", "HEAD^{tree}"]);
    let (ledger, package) = support::seeded_ledger("authority-unavailable");
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let adapter = Arc::new(support::ScriptedSim::new());
    let journal = Arc::new(MemoryJournal::new());
    let key = "authority-unavailable-1";
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("authority-unavailable"),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    };
    let workspace_root = dir.path().join("farm");
    let config = AttemptConfig::new(
        origin.clone(),
        base_sha,
        workspace_root.clone(),
        "must not run".into(),
        vec!["PONG.txt".into()],
        vec![bullet_runner_core::REPOSITORY_GATE_ID.into()],
    );

    let error = run_attempt(
        client,
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect_err("production authority is unavailable");
    assert!(matches!(
        error,
        RunnerError::AuthorityContractUnavailable { ref method, .. } if method == "clone"
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
    assert_eq!(git(&origin, &["rev-parse", "HEAD^{tree}"]), before_tree);
    assert!(git(&origin, &["status", "--porcelain"]).is_empty());
    assert!(!workspace_root.exists(), "refusal created a workspace");
    assert!(adapter.prompts().is_empty(), "provider was started");
    assert_eq!(
        journal.stages(),
        vec!["lease_acquired", "workspace_refused", "released"]
    );

    let ledger: std::sync::MutexGuard<'_, MemoryLedger> = ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(&AttemptId::from_seed(key))
        .expect("read")
        .expect("attempt");
    assert_eq!(attempt.state, AttemptState::Failed);
    assert!(ledger
        .get_lease(&attempt.variant_id)
        .expect("lease")
        .is_none());
    assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
}
