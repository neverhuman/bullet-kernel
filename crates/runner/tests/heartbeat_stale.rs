//! Production authority refusal stops before provider and heartbeat activity.

mod support;

use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, DirectLeaseClient, HeartbeatConfig, MemoryJournal,
    MonotonicClock,
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn unavailable_authority_stops_before_running_and_heartbeat() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("authority-before-heartbeat");
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let adapter = Arc::new(support::ScriptedSim::new());
    let journal = Arc::new(MemoryJournal::new());
    let key = "authority-before-heartbeat-1";
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("authority-before-heartbeat"),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    };
    let mut config = AttemptConfig::new(
        origin,
        base_sha,
        dir.path().join("farm"),
        "must not run".into(),
        vec!["PONG.txt".into()],
        vec![bullet_runner_core::REPOSITORY_GATE_ID.into()],
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(1),
    };

    let error = run_attempt(
        client,
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect_err("authority refusal");
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(adapter.prompts().is_empty());
    assert!(!journal.stages().iter().any(|stage| {
        matches!(
            stage.as_str(),
            "workspace_cloned" | "turn_finished" | "patch_applied"
        )
    }));

    let ledger: std::sync::MutexGuard<'_, MemoryLedger> = ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(&AttemptId::from_seed(key))
        .expect("read")
        .expect("attempt");
    assert_eq!(attempt.state, AttemptState::Failed);
    assert_eq!(attempt.fence, 1);
}
