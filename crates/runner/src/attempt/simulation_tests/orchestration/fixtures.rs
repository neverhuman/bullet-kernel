//! Shared test-only orchestration setup, retained separately from assertions.

use super::*;

pub(super) type SharedLedger = Arc<Mutex<MemoryLedger>>;
pub(super) type TestClient = Arc<TestCandidateClient>;
pub(super) struct FailAdvanceClient {
    pub(super) inner: TestClient,
    pub(super) releases: AtomicUsize,
}

#[async_trait::async_trait]
impl LeaseClient for FailAdvanceClient {
    async fn acquire(
        &self,
        request: &crate::AcquireRequest,
    ) -> Result<crate::AcquireGrant, crate::RunnerError> {
        self.inner.acquire(request).await
    }

    async fn heartbeat(&self, call: &crate::HeartbeatCall) -> Result<(), crate::RunnerError> {
        self.inner.heartbeat(call).await
    }

    async fn advance(
        &self,
        _attempt_id: &AttemptId,
        _state: AttemptState,
    ) -> Result<(), crate::RunnerError> {
        Err(crate::RunnerError::Lease {
            code: "TEST_ADVANCE_REFUSED".into(),
            message: "injected Running transition refusal".into(),
        })
    }

    async fn release(&self, call: &crate::ReleaseCall) -> Result<(), crate::RunnerError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        self.inner.release(call).await
    }

    async fn next_ready(&self) -> Result<Option<crate::ReadyView>, crate::RunnerError> {
        self.inner.next_ready().await
    }
}

pub(super) struct FrozenFixture {
    pub(super) _temp: tempfile::TempDir,
    pub(super) ledger: SharedLedger,
    pub(super) client: TestClient,
    pub(super) package: WorkPackageId,
    pub(super) origin: PathBuf,
    pub(super) base_sha: String,
    pub(super) farm_root: PathBuf,
    pub(super) attempt_id: AttemptId,
    pub(super) repo_dir: PathBuf,
    pub(super) runtime_dir: PathBuf,
    pub(super) journal: Arc<MemoryJournal>,
    pub(super) adapter: Arc<ScriptedSim>,
}

pub(super) fn request(package: WorkPackageId, key: &str) -> crate::AcquireRequest {
    crate::AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed(key),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    }
}

pub(super) fn config(origin: PathBuf, base_sha: String, farm_root: PathBuf) -> AttemptConfig {
    let preservation = farm_root.join("retained");
    let mut config = AttemptConfig::new(
        origin,
        base_sha,
        farm_root,
        "test-only orchestration".into(),
        vec!["PONG.txt".into()],
        vec![crate::REPOSITORY_GATE_ID.into()],
    )
    .with_preservation_destination(preservation);
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(10),
    };
    config
}

pub(super) async fn wait_for_state(
    ledger: &SharedLedger,
    attempt_id: &AttemptId,
    expected: AttemptState,
) {
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

pub(super) fn expire_live_lease(ledger: &SharedLedger) {
    let mut ledger = ledger.lock().expect("ledger");
    ledger
        .advance_simulation_time(15)
        .expect("advance deterministic lease clock");
    let expired = ledger.expire_leases().expect("expire lease");
    assert_eq!(expired.len(), 1, "one live test lease expires");
    assert_eq!(expired[0].fence, 1);
}

pub(super) async fn freeze_after_clone(seed: &str) -> FrozenFixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = build_origin(temp.path());
    let (ledger, package) = seeded_ledger(seed);
    let client = Arc::new(TestCandidateClient::new(ledger.clone()));
    let key = format!("{seed}-1");
    let grant = client
        .acquire(&request(package.clone(), &key))
        .await
        .expect("test lease");
    assert_eq!(grant.attempt.fence, 1);

    let farm_root = temp.path().join("farm");
    let config = client.admit_config(config(origin.clone(), base_sha.clone(), farm_root.clone()));
    let journal = Arc::new(MemoryJournal::new());
    journal.record("lease_acquired", "TEST_ONLY_SIMULATOR fence 1");
    let mut workspace = SimWorkspace::new(grant.authority_token.clone());
    let mut info = workspace
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
                &mut info,
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

pub(super) async fn cloned_attempt(
    seed: &str,
) -> (
    tempfile::TempDir,
    SharedLedger,
    TestClient,
    crate::AcquireGrant,
    AttemptConfig,
    SimWorkspace,
    crate::WorkspaceInfo,
    Arc<MemoryJournal>,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = build_origin(temp.path());
    let (ledger, package) = seeded_ledger(seed);
    let client = Arc::new(TestCandidateClient::new(ledger.clone()));
    let grant = client
        .acquire(&request(package, &format!("{seed}-attempt")))
        .await
        .expect("test lease");
    let config = client.admit_config(config(origin, base_sha, temp.path().join("farm")));
    let mut workspace = SimWorkspace::new(grant.authority_token.clone());
    let info = workspace
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
        .expect("test-only clone");
    let journal = Arc::new(MemoryJournal::new());
    (
        temp, ledger, client, grant, config, workspace, info, journal,
    )
}

pub(super) fn assert_failed_and_requeued(
    ledger: &SharedLedger,
    attempt_id: &AttemptId,
    journal: &MemoryJournal,
) {
    let ledger = ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(attempt_id)
        .expect("attempt read")
        .expect("attempt row");
    assert_eq!(attempt.state, AttemptState::Failed);
    assert!(ledger
        .get_lease(&attempt.variant_id)
        .expect("lease read")
        .is_none());
    assert_eq!(ledger.ready_rows().expect("ready rows").len(), 1);
    assert!(journal.stages().contains(&"released".to_string()));
}
