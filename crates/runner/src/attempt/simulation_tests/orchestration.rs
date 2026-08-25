//! Test-only Runner orchestration after a simulated private clone.

use super::harness::ScriptedSim;
use super::{build_origin, proposal, seeded_ledger, SimWorkspace};
use crate::journal::JournalSink;
use crate::{DirectLeaseClient, HeartbeatConfig, LeaseClient, MemoryJournal, MonotonicClock};
use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId, WorkPackageId};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::{run_cloned_attempt, AttemptConfig};

type SharedLedger = Arc<Mutex<MemoryLedger>>;
type TestClient = Arc<DirectLeaseClient<MemoryLedger>>;

struct FrozenFixture {
    _temp: tempfile::TempDir,
    ledger: SharedLedger,
    client: TestClient,
    package: WorkPackageId,
    origin: PathBuf,
    base_sha: String,
    farm_root: PathBuf,
    attempt_id: AttemptId,
    repo_dir: PathBuf,
    runtime_dir: PathBuf,
    journal: Arc<MemoryJournal>,
    adapter: Arc<ScriptedSim>,
}

fn request(package: WorkPackageId, key: &str) -> crate::AcquireRequest {
    crate::AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed(key),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    }
}

fn config(origin: PathBuf, base_sha: String, farm_root: PathBuf) -> AttemptConfig {
    let mut config = AttemptConfig::new(
        origin,
        base_sha,
        farm_root,
        "test-only orchestration".into(),
        vec!["PONG.txt".into()],
        vec![crate::REPOSITORY_GATE_ID.into()],
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(10),
    };
    config
}

async fn wait_for_state(ledger: &SharedLedger, attempt_id: &AttemptId, expected: AttemptState) {
    for _ in 0..200 {
        let reached = {
            let ledger = ledger.lock().expect("ledger");
            ledger
                .get_attempt(attempt_id)
                .expect("attempt read")
                .is_some_and(|attempt| attempt.state == expected)
        };
        if reached {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("attempt {attempt_id} never reached {expected:?}");
}

fn expire_live_lease(ledger: &SharedLedger) {
    let mut ledger = ledger.lock().expect("ledger");
    ledger
        .advance_simulation_time(15)
        .expect("advance deterministic lease clock");
    let expired = ledger.expire_leases().expect("expire lease");
    assert_eq!(expired.len(), 1, "one live test lease expires");
    assert_eq!(expired[0].fence, 1);
}

async fn freeze_after_clone(seed: &str) -> FrozenFixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = build_origin(temp.path());
    let (ledger, package) = seeded_ledger(seed);
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let key = format!("{seed}-1");
    let grant = client
        .acquire(&request(package.clone(), &key))
        .await
        .expect("test lease");
    assert_eq!(grant.attempt.fence, 1);

    let farm_root = temp.path().join("farm");
    let config = config(origin.clone(), base_sha.clone(), farm_root.clone());
    let journal = Arc::new(MemoryJournal::new());
    journal.record("lease_acquired", "TEST_ONLY_SIMULATOR fence 1");
    let mut workspace = SimWorkspace::new(grant.attempt.id.clone());
    let info = workspace
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
        .expect("test-only clone");
    journal.record("workspace_cloned", "TEST_ONLY_SIMULATOR");

    let attempt_id = grant.attempt.id.clone();
    let repo_dir = info.repo_dir.clone();
    let runtime_dir = info.runtime_dir.clone();
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    adapter.delay_send(Duration::from_millis(250));

    let task = {
        let client = client.clone();
        let adapter = adapter.clone();
        let journal = journal.clone();
        tokio::spawn(async move {
            run_cloned_attempt(
                client,
                adapter,
                journal,
                Arc::new(MonotonicClock::new()),
                &grant,
                &config,
                &mut workspace,
                &info,
            )
            .await
        })
    };
    wait_for_state(&ledger, &attempt_id, AttemptState::Running).await;
    expire_live_lease(&ledger);
    let error = task
        .await
        .expect("runner task joins")
        .expect_err("stale lease freezes the cloned attempt");
    assert_eq!(error.reason_code(), "STALE_AUTHORITY");

    FrozenFixture {
        _temp: temp,
        ledger,
        client,
        package,
        origin,
        base_sha,
        farm_root,
        attempt_id,
        repo_dir,
        runtime_dir,
        journal,
        adapter,
    }
}

fn assert_salvaged_without_apply(fixture: &FrozenFixture) {
    let stages = fixture.journal.stages();
    assert!(stages.contains(&"frozen".to_string()), "{stages:?}");
    assert!(
        stages.contains(&"salvage_checkpoint".to_string()),
        "{stages:?}"
    );
    assert!(stages.contains(&"terminated".to_string()), "{stages:?}");
    assert!(!stages.contains(&"patch_applied".to_string()), "{stages:?}");
    assert!(!stages.contains(&"released".to_string()), "{stages:?}");
    let frozen_at = stages
        .iter()
        .position(|stage| stage == "frozen")
        .expect("frozen stage");
    let salvage_at = stages
        .iter()
        .position(|stage| stage == "salvage_checkpoint")
        .expect("salvage stage");
    let terminated_at = stages
        .iter()
        .position(|stage| stage == "terminated")
        .expect("termination stage");
    assert!(frozen_at < salvage_at && salvage_at < terminated_at);
    assert!(fixture.adapter.was_terminated());
    assert_eq!(fixture.adapter.prompts().len(), 1);
    assert!(!fixture.repo_dir.join("PONG.txt").exists());
    assert!(
        stages.contains(&"salvage_preserved".to_string()),
        "{stages:?}"
    );

    let checkpoint = std::fs::read_to_string(fixture.runtime_dir.join("checkpoint.json"))
        .expect("preserved test checkpoint");
    assert!(checkpoint.contains("TEST_ONLY_SIMULATOR"));
    assert!(checkpoint.contains(fixture.attempt_id.as_str()));
    let salvage = fixture
        .farm_root
        .join("salvage")
        .join(fixture.attempt_id.as_str())
        .join("preservation.json");
    assert!(
        salvage.is_file(),
        "freeze must preserve bytes outside the live workspace"
    );

    let ledger = fixture.ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(&fixture.attempt_id)
        .expect("attempt read")
        .expect("attempt row");
    assert_eq!(attempt.state, AttemptState::Crashed);
    assert!(ledger
        .get_lease(&attempt.variant_id)
        .expect("lease read")
        .is_none());
    assert_eq!(ledger.ready_rows().expect("ready rows").len(), 1);
}

#[tokio::test]
async fn stale_heartbeat_after_clone_salvages_terminates_and_never_applies() {
    let fixture = freeze_after_clone("post-clone-stale").await;
    assert_salvaged_without_apply(&fixture);
}

#[tokio::test]
async fn successor_uses_fence_two_while_salvaged_workspace_stays_inert() {
    let fixture = freeze_after_clone("post-clone-successor").await;
    assert_salvaged_without_apply(&fixture);

    let grant = fixture
        .client
        .acquire(&request(fixture.package.clone(), "post-clone-successor-2"))
        .await
        .expect("successor lease");
    assert_eq!(grant.attempt.fence, 2);
    let mut config = config(
        fixture.origin.clone(),
        fixture.base_sha.clone(),
        fixture.farm_root.clone(),
    );
    config.bindings = super::test_only_bindings(&grant);
    let mut workspace = SimWorkspace::new(grant.attempt.id.clone());
    let info = workspace
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
        .expect("successor test clone");
    assert_ne!(info.repo_dir, fixture.repo_dir);
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    let successor_journal = Arc::new(MemoryJournal::new());
    let outcome = run_cloned_attempt(
        fixture.client.clone(),
        adapter,
        successor_journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &info,
    )
    .await
    .expect("successor completes in test simulator");
    assert_eq!(outcome.fence, 2);
    assert_eq!(outcome.candidate.prepared_at, "TEST_ONLY_SIMULATOR");
    assert!(info.repo_dir.join("PONG.txt").is_file());
    assert!(!fixture.repo_dir.join("PONG.txt").exists());
    assert!(fixture.runtime_dir.join("checkpoint.json").is_file());
    let successor_stages = successor_journal.stages();
    assert!(successor_stages.contains(&"candidate_prepared".to_string()));
    assert!(successor_stages.contains(&"released".to_string()));
    assert_eq!(
        successor_stages.last().map(String::as_str),
        Some("terminated")
    );

    let ledger = fixture.ledger.lock().expect("ledger");
    let first = ledger
        .get_attempt(&fixture.attempt_id)
        .expect("first read")
        .expect("first attempt");
    let second = ledger
        .get_attempt(&outcome.attempt_id)
        .expect("second read")
        .expect("second attempt");
    assert_eq!(first.state, AttemptState::Crashed);
    assert_eq!(second.state, AttemptState::Succeeded);
    assert_eq!((first.fence, second.fence), (1, 2));
    assert!(ledger.ready_rows().expect("ready rows").is_empty());
}
