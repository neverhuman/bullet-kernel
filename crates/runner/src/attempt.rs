//! The Attempt loop (ADR 0001): acquire → private clone → read-only provider
//! session → scope-checked apply → deterministic gate → bounded repair →
//! exact candidate → release. A freeze (stale authority or self-kill) stops
//! all applying, checkpoints salvage, and terminates the provider.

use crate::capsule::Capsule;
use crate::clock::Clock;
use crate::error::RunnerError;
use crate::gate::{run_gate, GateReport};
use crate::gitd::{CandidateReceipt, GitdSession, WorkspaceInfo};
use crate::heartbeat::{start_heartbeat, HeartbeatConfig, HeartbeatHandle};
use crate::journal::JournalSink;
use crate::lease::{AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient, ReleaseCall};
use crate::scope;
use bullet_domain::{AttemptId, AttemptState};
use bullet_harness_core::{
    AgentEventKind, AgentSessionId, HarnessAdapter, PatchProposal, SessionHandle, StartSession,
    Turn,
};
use futures::StreamExt;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Everything one attempt run needs beyond the lease request.
#[derive(Clone, Debug)]
pub struct AttemptConfig {
    /// Source repository (the mirror bullet-gitd clones from).
    pub source_repo: PathBuf,
    /// Exact base commit SHA.
    pub base_sha: String,
    /// Root under which `work/` and `runtime/` live.
    pub workspace_root: PathBuf,
    /// Mission objective for the prompt capsule.
    pub objective: String,
    /// Granted change-intent path prefixes.
    pub scope_prefixes: Vec<String>,
    /// Deterministic gate command.
    pub gate_command: String,
    /// Bounded repair rounds after the initial turn (ADR 0001: 2).
    pub max_repair_rounds: u32,
    /// Wall-clock bound for one gate run.
    pub gate_timeout: Duration,
    /// Wall-clock bound for one provider invocation.
    pub turn_timeout: Duration,
    /// Heartbeat cadence and lease TTL.
    pub heartbeat: HeartbeatConfig,
}

impl AttemptConfig {
    /// Config with ADR 0001 defaults for the bounded loop.
    #[must_use]
    pub fn new(
        source_repo: PathBuf,
        base_sha: String,
        workspace_root: PathBuf,
        objective: String,
        scope_prefixes: Vec<String>,
        gate_command: String,
    ) -> Self {
        Self {
            source_repo,
            base_sha,
            workspace_root,
            objective,
            scope_prefixes,
            gate_command,
            max_repair_rounds: 2,
            gate_timeout: Duration::from_secs(120),
            turn_timeout: Duration::from_secs(600),
            heartbeat: HeartbeatConfig::default(),
        }
    }

    fn capsule(&self) -> Capsule {
        Capsule {
            objective: self.objective.clone(),
            scope_prefixes: self.scope_prefixes.clone(),
            base_sha: self.base_sha.clone(),
            gate_command: self.gate_command.clone(),
        }
    }
}

/// Successful attempt result.
#[derive(Clone, Debug)]
pub struct AttemptOutcome {
    /// The fenced attempt.
    pub attempt_id: AttemptId,
    /// Permanent fence epoch.
    pub fence: u64,
    /// Exact candidate receipt with real SHAs.
    pub candidate: CandidateReceipt,
    /// Repair rounds consumed.
    pub repair_rounds: u32,
    /// The passing gate report.
    pub gate: GateReport,
}

fn check_freeze(heartbeat: &HeartbeatHandle) -> Result<(), RunnerError> {
    match heartbeat.frozen() {
        Some(reason) => Err(reason.to_error()),
        None => Ok(()),
    }
}

fn start_request(grant: &AcquireGrant, ws: &WorkspaceInfo, config: &AttemptConfig) -> StartSession {
    StartSession {
        session_id: AgentSessionId::new(grant.attempt.id.as_str()),
        workdir: ws.repo_dir.clone(),
        artifact_dir: config
            .workspace_root
            .join("artifacts")
            .join(grant.attempt.id.as_str()),
        model: None,
        structured_schema: serde_json::from_str(bullet_harness_core::proposal::schema_source())
            .ok(),
        max_budget_usd: None,
        wall_timeout: config.turn_timeout,
    }
}

/// Run one complete attempt.
///
/// # Errors
///
/// Typed runner failure; a freeze surfaces as `STALE_AUTHORITY` or
/// `SELF_KILL_DEADLINE` after salvage and provider termination.
pub async fn run_attempt(
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<dyn JournalSink>,
    clock: Arc<dyn Clock>,
    request: &AcquireRequest,
    config: &AttemptConfig,
) -> Result<AttemptOutcome, RunnerError> {
    let grant = client.acquire(request).await?;
    journal.record(
        "lease_acquired",
        &format!("attempt {} fence {}", grant.attempt.id, grant.attempt.fence),
    );
    let mut gitd = GitdSession::spawn(&grant.authority_token).await?;
    let ws = gitd
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await?;
    journal.record("workspace_cloned", &ws.repo_dir.display().to_string());
    let heartbeat = start_heartbeat(
        client.clone(),
        HeartbeatCall::for_grant(&grant, config.heartbeat.ttl_seconds),
        config.heartbeat.clone(),
        clock,
    );
    let session = adapter.start(start_request(&grant, &ws, config)).await?;
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await?;
    match drive_and_finish(
        client.as_ref(),
        adapter.as_ref(),
        &mut gitd,
        &ws,
        &grant,
        config,
        journal.as_ref(),
        &heartbeat,
        &session,
    )
    .await
    {
        Ok(outcome) => {
            heartbeat.abort();
            let _ = adapter.terminate(&session).await;
            journal.record("terminated", "success");
            Ok(outcome)
        }
        Err(err) => {
            heartbeat.abort();
            cleanup_failure(
                client.as_ref(),
                adapter.as_ref(),
                &mut gitd,
                &grant,
                journal.as_ref(),
                &session,
                &err,
            )
            .await;
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_and_finish(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut GitdSession,
    ws: &WorkspaceInfo,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
) -> Result<AttemptOutcome, RunnerError> {
    let capsule = config.capsule();
    let (gate, rounds) = session_loop(
        adapter, gitd, ws, &capsule, config, journal, heartbeat, session,
    )
    .await?;
    check_freeze(heartbeat)?;
    client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await?;
    let candidate = gitd
        .prepare_candidate(grant.attempt.id.as_str(), &capsule.objective)
        .await?;
    journal.record("candidate_prepared", &candidate.id);
    client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Succeeded,
            requeue: false,
        })
        .await?;
    journal.record("released", "succeeded");
    Ok(AttemptOutcome {
        attempt_id: grant.attempt.id.clone(),
        fence: grant.attempt.fence,
        candidate,
        repair_rounds: rounds,
        gate,
    })
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    adapter: &dyn HarnessAdapter,
    gitd: &mut GitdSession,
    ws: &WorkspaceInfo,
    capsule: &Capsule,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
) -> Result<(GateReport, u32), RunnerError> {
    let mut prompt = capsule.initial_prompt();
    let mut rounds: u32 = 0;
    loop {
        check_freeze(heartbeat)?;
        let turn = adapter
            .send(
                session,
                Turn {
                    prompt: prompt.clone(),
                },
            )
            .await?;
        journal.record(
            "turn_finished",
            &format!(
                "invocation {} exit {:?}",
                turn.invocation_id, turn.exit_code
            ),
        );
        let proposal = latest_proposal(adapter, session).await?;
        if let Some(refusal) = pre_apply_refusal(capsule, &proposal) {
            journal.record(refusal.stage, &refusal.detail);
            spend_repair_round(&mut rounds, config)?;
            prompt = refusal.prompt;
            continue;
        }
        check_freeze(heartbeat)?;
        let applied = match gitd.apply_change(&proposal.changes).await {
            Ok(count) => count,
            Err(err) => {
                let Some(detail) = err.path_absent_detail().map(String::from) else {
                    return Err(err);
                };
                journal.record("path_absent", &detail);
                spend_repair_round(&mut rounds, config)?;
                prompt = capsule.path_absent_prompt(&detail);
                continue;
            }
        };
        journal.record("patch_applied", &format!("{applied} paths"));
        let gate = run_gate(&ws.repo_dir, &config.gate_command, config.gate_timeout).await?;
        journal.record(
            "gate_result",
            &format!("exit {:?} timed_out {}", gate.exit_code, gate.timed_out),
        );
        if gate.passed() && proposal.done {
            return Ok((gate, rounds));
        }
        spend_repair_round(&mut rounds, config)?;
        prompt = capsule.gate_feedback_prompt(&gate);
    }
}

/// Consume one bounded repair round; typed `CAPS_EXHAUSTED` when spent.
fn spend_repair_round(rounds: &mut u32, config: &AttemptConfig) -> Result<(), RunnerError> {
    *rounds += 1;
    if *rounds > config.max_repair_rounds {
        return Err(RunnerError::CapsExhausted { rounds: *rounds });
    }
    Ok(())
}

struct Refusal {
    stage: &'static str,
    detail: String,
    prompt: String,
}

/// Typed refusal the loop feeds back BEFORE any apply: an out-of-scope
/// path. Delete entries are scope-checked exactly like writes; a delete of
/// a missing file is refused by the daemon at apply as `PATH_ABSENT`.
fn pre_apply_refusal(capsule: &Capsule, proposal: &PatchProposal) -> Option<Refusal> {
    if let Err(RunnerError::ScopeDenied { path }) =
        scope::validate_proposal(&capsule.scope_prefixes, proposal)
    {
        return Some(Refusal {
            stage: "scope_denied",
            detail: path.clone(),
            prompt: capsule.scope_denied_prompt(&path),
        });
    }
    None
}

async fn latest_proposal(
    adapter: &dyn HarnessAdapter,
    session: &SessionHandle,
) -> Result<PatchProposal, RunnerError> {
    let events: Vec<_> = adapter.events(session).collect().await;
    let mut last: Option<(AgentEventKind, Value)> = None;
    for event in events {
        if matches!(
            event.kind,
            AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed
        ) {
            last = Some((event.kind, event.payload));
        }
    }
    let Some((kind, payload)) = last else {
        return Err(RunnerError::NoProposal("no turn close envelope".into()));
    };
    if kind == AgentEventKind::TurnFailed {
        return Err(RunnerError::NoProposal(format!("turn failed: {payload}")));
    }
    let value = payload.get("proposal").cloned().unwrap_or(Value::Null);
    if value.is_null() {
        return Err(RunnerError::NoProposal(format!(
            "turn completed without a proposal: {payload}"
        )));
    }
    PatchProposal::from_value(&value).map_err(RunnerError::from)
}

async fn cleanup_failure(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut GitdSession,
    grant: &AcquireGrant,
    journal: &dyn JournalSink,
    session: &SessionHandle,
    err: &RunnerError,
) {
    if err.is_frozen() {
        journal.record("frozen", err.reason_code());
        match gitd.checkpoint().await {
            Ok(checkpoint) => journal.record("salvage_checkpoint", &checkpoint.to_string()),
            Err(salvage_err) => journal.record("salvage_failed", &salvage_err.to_string()),
        }
        let _ = adapter.terminate(session).await;
        journal.record("terminated", err.reason_code());
        return;
    }
    let _ = adapter.terminate(session).await;
    let released = client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Failed,
            requeue: true,
        })
        .await;
    journal.record(
        "released",
        &format!("failed requeue=true ok={}", released.is_ok()),
    );
    journal.record("terminated", err.reason_code());
}
