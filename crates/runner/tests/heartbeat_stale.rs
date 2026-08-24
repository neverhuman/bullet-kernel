//! Heartbeat-stale: the lease is expired behind a live runner; the next
//! heartbeat matches zero rows, the runner freezes before applying anything,
//! checkpoints salvage through gitd, terminates the provider session, and
//! surfaces typed STALE_AUTHORITY.

mod support;

use bullet_application::{LeaseService, Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId, WorkPackageId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, DirectLeaseClient, HeartbeatConfig, MemoryJournal,
    MonotonicClock,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type SharedLedger = Arc<Mutex<MemoryLedger>>;

fn config_for(origin: PathBuf, base_sha: String, root: PathBuf) -> AttemptConfig {
    let mut config = AttemptConfig::new(
        origin,
        base_sha,
        root,
        "create PONG.txt".into(),
        vec!["PONG.txt".into()],
        "test -f PONG.txt".into(),
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(50),
        ttl_seconds: 60,
    };
    config
}

fn request_for(package: WorkPackageId, key: &str) -> AcquireRequest {
    AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("hb-stale"),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 60,
    }
}

async fn wait_for_attempt_state(
    ledger: &SharedLedger,
    attempt_id: &AttemptId,
    expected: AttemptState,
) -> bool {
    for _ in 0..250 {
        let reached = {
            let ledger = ledger.lock().expect("ledger");
            ledger
                .get_attempt(attempt_id)
                .expect("read")
                .is_some_and(|attempt| attempt.state == expected)
        };
        if reached {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn expire_all(ledger: &SharedLedger) -> usize {
    let mut ledger = ledger.lock().expect("ledger");
    ledger
        .expire_leases(&LeaseService::rfc3339(
            chrono::Utc::now() + chrono::Duration::hours(2),
        ))
        .expect("expire")
        .len()
}

fn assert_freeze_journal(stages: &[String]) {
    let has = |stage: &str| stages.iter().any(|s| s == stage);
    assert!(has("frozen"), "{stages:?}");
    assert!(has("salvage_checkpoint"), "{stages:?}");
    assert!(has("terminated"), "{stages:?}");
    assert!(!has("patch_applied"), "froze before applying: {stages:?}");
    let frozen_at = stages.iter().position(|s| s == "frozen").expect("frozen");
    let terminated_at = stages
        .iter()
        .rposition(|s| s == "terminated")
        .expect("terminated");
    assert!(frozen_at < terminated_at);
}

#[tokio::test]
async fn tampered_lease_freezes_checkpoints_and_terminates() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("hb-stale");
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let adapter = Arc::new(support::ScriptedSim::new());
    // Hold the first turn open long enough for the tamper to land.
    adapter.delay_turn(0, Duration::from_millis(1500));
    let journal = Arc::new(MemoryJournal::new());
    let key = "hb-stale-1";
    let attempt_id = AttemptId::from_seed(key);
    let request = request_for(package, key);
    let config = config_for(origin, base_sha, dir.path().join("farm"));
    let task = {
        let client = client.clone();
        let adapter = adapter.clone();
        let journal = journal.clone();
        tokio::spawn(async move {
            run_attempt(
                client,
                adapter,
                journal,
                Arc::new(MonotonicClock::new()),
                &request,
                &config,
            )
            .await
        })
    };
    assert!(
        wait_for_attempt_state(&ledger, &attempt_id, AttemptState::Running).await,
        "attempt never reached Running"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(expire_all(&ledger), 1, "the live lease was expired");

    let err = task
        .await
        .expect("task joins")
        .expect_err("runner must freeze with a typed error");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY", "{err}");
    assert_freeze_journal(&journal.stages());
    let repo = dir
        .path()
        .join("farm/work")
        .join(attempt_id.as_str())
        .join("repo");
    assert!(!repo.join("PONG.txt").exists(), "no write after the freeze");
    let ledger = ledger.lock().expect("ledger");
    let attempt = ledger.get_attempt(&attempt_id).expect("read").expect("row");
    assert_eq!(attempt.state, AttemptState::Crashed);
    assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
}
