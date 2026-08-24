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
    let config = AttemptConfig::new(
        origin,
        base_sha,
        root,
        "must not run".into(),
        vec!["PONG.txt".into()],
        vec![bullet_runner_core::REPOSITORY_GATE_ID.into()],
    );
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
}

#[tokio::test]
async fn successor_refusals_never_reuse_a_fence_or_create_a_clone() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("refused-successor");
    refused_attempt(
        ledger.clone(),
        package.clone(),
        origin.clone(),
        base_sha.clone(),
        dir.path().join("farm"),
        "refused-successor-1",
    )
    .await;
    refused_attempt(
        ledger.clone(),
        package,
        origin,
        base_sha,
        dir.path().join("farm"),
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
    assert!(!dir.path().join("farm").exists());
    assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
}
