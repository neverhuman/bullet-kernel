//! The runner phase: bullet-runner-core's attempt loop over the shared
//! ledger, a real bullet-gitd private clone, and the simulator adapter.

use crate::demo_synthetic::fixture::{Fixture, OBJECTIVE};
use crate::demo_synthetic::synthetic_adapter::adapter_for;
use crate::demo_synthetic::turns::{events_cost, events_session};
use crate::demo_synthetic::SharedLedger;
use bullet_application::StoredGraph;
use bullet_domain::{RunnerId, WorkPackageId};
use bullet_harness_core::{AgentEvent, AgentSessionId, SessionHandle};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, DirectLeaseClient, MemoryJournal,
    MonotonicClock,
};
use futures::StreamExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Everything the runner phase proved.
pub struct RunnerPhase {
    /// The successful attempt.
    pub outcome: AttemptOutcome,
    /// The private clone the candidate lives in.
    pub workspace_repo: PathBuf,
    /// Provider-native session id when reported.
    pub session: Option<String>,
    /// Reported spend; `None` is honest not-reported.
    pub cost_usd: Option<f64>,
    /// Wall time of the whole attempt.
    pub wall_ms: u64,
    /// Journal stages in order.
    pub journal: Vec<(String, String)>,
}

/// Run one complete fenced attempt with the chosen provider.
pub async fn run_phase(
    ledger: &SharedLedger,
    graph: &StoredGraph,
    fixture: &Fixture,
    data_dir: &Path,
) -> Result<RunnerPhase, String> {
    let adapter = adapter_for("sim").ok_or("SIMULATOR_ADAPTER_UNAVAILABLE")?;
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let journal = Arc::new(MemoryJournal::new());
    let clock = Arc::new(MonotonicClock::new());
    let package: WorkPackageId = graph
        .packages
        .first()
        .map(|package| package.id.clone())
        .ok_or("graph has no packages")?;
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("demo-synthetic-runner"),
        runner_epoch: 1,
        idempotency_key: format!("demo-synthetic-runner:{}", graph.mission.id),
        ttl_seconds: 15,
    };
    let workspace_root = data_dir.join("runner");
    let mut config = AttemptConfig::new(
        fixture.origin.clone(),
        fixture.base_sha.clone(),
        workspace_root.clone(),
        OBJECTIVE.to_string(),
        vec!["PONG.txt".into()],
        fixture.writer_gate_ids.clone(),
    );
    config.turn_timeout = Duration::from_secs(240);
    let started = Instant::now();
    let outcome = run_attempt(
        client,
        adapter.clone(),
        journal.clone(),
        clock,
        &request,
        &config,
    )
    .await
    .map_err(|err| format!("RUNNER:{}: {err}", err.reason_code()))?;
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let workspace_repo = workspace_root
        .join("work")
        .join(outcome.attempt_id.as_str())
        .join("repo");
    if !workspace_repo.is_dir() {
        return Err(format!("WORKSPACE_MISSING: {}", workspace_repo.display()));
    }
    let handle = SessionHandle {
        session_id: AgentSessionId::new(outcome.attempt_id.as_str()),
        provider: "sim".to_string(),
        native_session_id: None,
    };
    let events: Vec<AgentEvent> = adapter.events(&handle).collect().await;
    Ok(RunnerPhase {
        session: events_session(&events, &handle),
        cost_usd: events_cost(&events),
        outcome,
        workspace_repo,
        wall_ms,
        journal: journal.entries(),
    })
}
