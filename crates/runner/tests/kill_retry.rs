//! Refused production incarnations consume monotonic fences without cloning.

mod support;

use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, DirectLeaseClient, MemoryJournal, MonotonicClock,
};
use std::sync::Arc;

async fn refused_attempt(
    ledger: Arc<std::sync::Mutex<MemoryLedger>>,
    package: bullet_domain::WorkPackageId,
    origin: std::path::PathBuf,
    base_sha: String,
    root: std::path::PathBuf,
    key: &str,
) {
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed(key),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    };
    let preservation_destination = root.with_file_name(format!("{key}-preserved"));
    let config = AttemptConfig::new(
        origin,
        base_sha,
        root.clone(),
        "must not run".into(),
        vec!["PONG.txt".into()],
        vec![bullet_runner_core::REPOSITORY_GATE_ID.into()],
    )
    .with_preservation_destination(preservation_destination.clone());
    let error = run_attempt(
        Arc::new(DirectLeaseClient::new(ledger)),
        Arc::new(support::ScriptedSim::new()),
        Arc::new(MemoryJournal::new()),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect_err("production authority unavailable");
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
    assert!(std::fs::read_dir(&root)
        .expect("workspace root remains")
        .next()
        .is_none());
    assert!(!preservation_destination.exists());
}

#[tokio::test]
async fn successor_refusals_never_reuse_a_fence_or_create_a_clone() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("refused-successor");
    let workspace_root = dir.path().join("farm");
    std::fs::create_dir(&workspace_root).expect("new empty workspace root");
    refused_attempt(
        ledger.clone(),
        package.clone(),
        origin.clone(),
        base_sha.clone(),
        workspace_root.clone(),
        "refused-successor-1",
    )
    .await;
    refused_attempt(
        ledger.clone(),
        package,
        origin,
        base_sha,
        workspace_root.clone(),
        "refused-successor-2",
    )
    .await;

    let ledger: std::sync::MutexGuard<'_, MemoryLedger> = ledger.lock().expect("ledger");
    let first = ledger
        .get_attempt(&AttemptId::from_seed("refused-successor-1"))
        .expect("read first")
        .expect("first");
    let second = ledger
        .get_attempt(&AttemptId::from_seed("refused-successor-2"))
        .expect("read second")
        .expect("second");
    assert_eq!((first.fence, second.fence), (1, 2));
    assert_eq!(first.state, AttemptState::Failed);
    assert_eq!(second.state, AttemptState::Failed);
    assert!(std::fs::read_dir(&workspace_root)
        .expect("workspace root remains after both refusals")
        .next()
        .is_none());
    assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
}
