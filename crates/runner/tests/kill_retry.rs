//! Kill/retry: a runner is killed mid-loop after apply but before candidate
//! preparation; the lease expires, a successor acquires fence N+1 and
//! completes from a fresh clone, and the dead incarnation's authority is
//! refused by both the ledger and a workspace daemon pinned to the new fence.

mod support;

use bullet_application::{ExpiredLease, LeaseService, Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, Digest, RunnerId, WorkPackageId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, DirectLeaseClient, GitdSession,
    HeartbeatCall, HeartbeatConfig, LeaseClient, MemoryJournal, MonotonicClock,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type SharedLedger = Arc<Mutex<MemoryLedger>>;
type Client = Arc<DirectLeaseClient<MemoryLedger>>;

fn config_with_gate(origin: &Path, base_sha: &str, root: PathBuf, gate: &str) -> AttemptConfig {
    let mut config = AttemptConfig::new(
        origin.to_path_buf(),
        base_sha.to_string(),
        root,
        "create PONG.txt".into(),
        vec!["PONG.txt".into()],
        gate.into(),
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(50),
        ttl_seconds: 2,
    };
    config
}

async fn wait_for_apply(repo: &Path) -> bool {
    for _ in 0..200 {
        if repo.join("PONG.txt").is_file() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn expire_all(ledger: &SharedLedger) -> Vec<ExpiredLease> {
    let mut ledger = ledger.lock().expect("ledger");
    ledger
        .expire_leases(&LeaseService::rfc3339(
            chrono::Utc::now() + chrono::Duration::hours(2),
        ))
        .expect("expire")
}

fn stale_heartbeat(key: &str, expired: &ExpiredLease) -> HeartbeatCall {
    HeartbeatCall {
        variant_id: expired.variant_id.clone(),
        attempt_id: expired.attempt_id.clone(),
        fence: expired.fence,
        runner_id: RunnerId::from_seed("kill-1"),
        runner_epoch: 1,
        workspace_nonce: *Digest::of(key.as_bytes()).as_bytes(),
        ttl_seconds: 2,
    }
}

async fn run_successor(
    client: &Client,
    origin: &Path,
    base_sha: &str,
    root: PathBuf,
    package: WorkPackageId,
) -> AttemptOutcome {
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("kill-2"),
        runner_epoch: 1,
        idempotency_key: "kill-retry-2".into(),
        ttl_seconds: 60,
    };
    let mut config = config_with_gate(origin, base_sha, root, "test -f PONG.txt");
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(100),
        ttl_seconds: 60,
    };
    run_attempt(
        client.clone(),
        Arc::new(support::ScriptedSim::new()),
        Arc::new(MemoryJournal::new()),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect("successor completes")
}

/// Start attempt 1 with a stalled gate, wait until its patch is applied in
/// the private clone, then kill the loop task mid-flight (after apply,
/// before prepare_candidate).
async fn run_and_kill_first(
    client: &Client,
    origin: &Path,
    base_sha: &str,
    farm_root: PathBuf,
    package: WorkPackageId,
    key1: &str,
    attempt1_id: &AttemptId,
) {
    let request1 = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("kill-1"),
        runner_epoch: 1,
        idempotency_key: key1.into(),
        ttl_seconds: 2,
    };
    let repo1 = farm_root
        .join("work")
        .join(attempt1_id.as_str())
        .join("repo");
    let config1 = config_with_gate(origin, base_sha, farm_root, "sleep 30");
    let task = {
        let client = client.clone();
        tokio::spawn(async move {
            run_attempt(
                client,
                Arc::new(support::ScriptedSim::new()),
                Arc::new(MemoryJournal::new()),
                Arc::new(MonotonicClock::new()),
                &request1,
                &config1,
            )
            .await
        })
    };
    assert!(wait_for_apply(&repo1).await, "attempt 1 never applied");
    task.abort();
    let _ = task.await;
}

fn assert_crashed_and_requeued(ledger: &SharedLedger, attempt1_id: &AttemptId) {
    let ledger = ledger.lock().expect("ledger");
    let attempt1 = ledger.get_attempt(attempt1_id).expect("read").expect("row");
    assert_eq!(attempt1.state, AttemptState::Crashed);
    assert_eq!(ledger.ready_rows().expect("ready").len(), 1, "requeued");
}

/// A daemon pinned to the successor's fence refuses the dead fence-1 token
/// while still serving the live one.
async fn assert_stale_gitd_refusal(
    ledger: &SharedLedger,
    origin: &Path,
    base_sha: &str,
    proof_root: PathBuf,
    attempt1_id: &AttemptId,
    attempt2_id: &AttemptId,
) {
    let (token1, token2) = {
        let ledger = ledger.lock().expect("ledger");
        let mission = ledger.list_missions().expect("missions")[0].id.clone();
        let graph = ledger.get_graph(&mission).expect("graph").expect("stored");
        let attempt1 = ledger.get_attempt(attempt1_id).expect("read").expect("row");
        let attempt2 = ledger.get_attempt(attempt2_id).expect("read").expect("row");
        (
            LeaseService::token_for(&graph, &attempt1).expect("token1"),
            LeaseService::token_for(&graph, &attempt2).expect("token2"),
        )
    };
    let mut gitd = GitdSession::spawn(&token2).await.expect("spawn gitd");
    gitd.clone_workspace(origin, base_sha, &proof_root, &["PONG.txt".to_string()])
        .await
        .expect("clone under the live fence");
    let stale_token = serde_json::to_value(&token1).expect("token json");
    let err = gitd
        .call_with(&stale_token, "read_tree", serde_json::json!({}))
        .await
        .expect_err("stale token refused");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY");
    let files = gitd.read_tree().await.expect("live token works");
    assert!(files.contains(&"README.md".to_string()));
}

#[tokio::test]
async fn successor_fences_out_a_killed_runner() {
    if !support::gitd_ready() {
        eprintln!("{}", support::SKIP_REASON);
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("kill-retry");
    let client: Client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let key1 = "kill-retry-1";
    let attempt1_id = AttemptId::from_seed(key1);
    run_and_kill_first(
        &client,
        &origin,
        &base_sha,
        dir.path().join("farm"),
        package.clone(),
        key1,
        &attempt1_id,
    )
    .await;

    let expired = expire_all(&ledger);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].fence, 1);
    assert_eq!(expired[0].attempt_id, attempt1_id);
    assert_crashed_and_requeued(&ledger, &attempt1_id);
    let err = client
        .heartbeat(&stale_heartbeat(key1, &expired[0]))
        .await
        .expect_err("stale");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY");

    let outcome = run_successor(
        &client,
        &origin,
        &base_sha,
        dir.path().join("farm"),
        package,
    )
    .await;
    assert_eq!(outcome.fence, 2, "successor holds fence N+1");
    assert_eq!(outcome.candidate.base_commit, base_sha, "fresh clone");
    assert_ne!(outcome.candidate.head_commit, base_sha);
    assert_stale_gitd_refusal(
        &ledger,
        &origin,
        &base_sha,
        dir.path().join("fence-proof"),
        &attempt1_id,
        &outcome.attempt_id,
    )
    .await;
}
