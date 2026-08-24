//! The runner phase: bullet-runner-core's attempt loop over the shared
//! ledger, a real bullet-gitd private clone, and the admitted provider
//! adapter (the simulator by default).

use crate::demo_live::fixture::{Fixture, OBJECTIVE};
use crate::demo_live::live_adapters;
use crate::demo_live::synthetic_adapter;
use crate::demo_live::turns::{events_cost, events_session};
use crate::demo_live::SharedLedger;
use bullet_application::StoredGraph;
use bullet_domain::{RunnerId, WorkPackageId};
use bullet_harness_core::{AgentEvent, AgentSessionId, SessionHandle};
use bullet_runner_core::{
    gitd_available, run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, DirectLeaseClient,
    MemoryJournal, MonotonicClock,
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
    provider: &str,
    ledger: &SharedLedger,
    graph: &StoredGraph,
    fixture: &Fixture,
    data_dir: &Path,
) -> Result<RunnerPhase, String> {
    if !gitd_available() {
        return Err("GITD_BINARY_ABSENT: build bullet-gitd or set BULLET_GITD_BIN".into());
    }
    let adapter = if provider == "sim" {
        synthetic_adapter::adapter_for(provider)
    } else {
        live_adapters::adapter_for(provider)
    }
    .ok_or_else(|| format!("UNKNOWN_PROVIDER: {provider}"))?;
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
        ttl_seconds: 60,
    };
    let workspace_root = data_dir.join("runner");
    let mut config = AttemptConfig::new(
        fixture.origin.clone(),
        fixture.base_sha.clone(),
        workspace_root.clone(),
        OBJECTIVE.to_string(),
        vec!["PONG.txt".into()],
        fixture.gate_command.clone(),
    );
    config.turn_timeout = Duration::from_secs(240);
    config.gate_timeout = Duration::from_secs(60);
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
        provider: provider.to_string(),
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
