//! The Attempt loop (ADR 0001): acquire → private clone → read-only provider
//! session → scope-checked apply → deterministic gate → bounded repair →
//! exact candidate → release. A freeze (stale authority or self-kill) stops
//! all applying, checkpoints salvage, and terminates the provider.

#[cfg(test)]
mod simulation_tests;
mod workspace;

use crate::capsule::Capsule;
use crate::clock::Clock;
use crate::error::RunnerError;
use crate::gate::{run_gate, GateRegistry, GateReport};
use crate::gitd::{
    CandidateBindings, CandidateReceipt, CheckpointBinding, GitdSession, PrepareCandidateRequest,
    SuccessorResume, WorkspaceInfo,
};
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
use workspace::WorkspaceSession;

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
    /// Ordered gate identifiers admitted by policy for this Attempt.
    pub admitted_gate_ids: Vec<String>,
    /// Bounded repair rounds after the initial turn (ADR 0001: 2).
    pub max_repair_rounds: u32,
    /// Wall-clock bound for one provider invocation.
    pub turn_timeout: Duration,
    /// Heartbeat cadence and lease TTL.
    pub heartbeat: HeartbeatConfig,
    /// Subjects the grant does not carry in gitd wire shape.
    pub bindings: CandidateBindings,
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
        admitted_gate_ids: Vec<String>,
    ) -> Self {
        Self {
            source_repo,
            base_sha,
            workspace_root,
            objective,
            scope_prefixes,
            admitted_gate_ids,
            max_repair_rounds: 2,
            turn_timeout: Duration::from_secs(600),
            heartbeat: HeartbeatConfig::default(),
            bindings: CandidateBindings::default(),
        }
    }

    fn capsule(&self, grant: &AcquireGrant, workspace: &WorkspaceInfo) -> Capsule {
        Capsule {
            objective: self.objective.clone(),
            scope_prefixes: self.scope_prefixes.clone(),
            base_sha: self.base_sha.clone(),
            producing_attempt_id: grant.attempt.id.to_string(),
            base_checkpoint_id: workspace.base_checkpoint_id.clone(),
            base_checkpoint_digest: workspace.base_checkpoint_digest.clone(),
            admitted_gate_ids: self.admitted_gate_ids.clone(),
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
    /// Passing reports for every admitted gate, in policy order.
    pub gates: Vec<GateReport>,
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
    GateRegistry::v1().validate_selection(&config.admitted_gate_ids)?;
    let grant = client.acquire(request).await?;
    journal.record(
        "lease_acquired",
        &format!("attempt {} fence {}", grant.attempt.id, grant.attempt.fence),
    );
    let mut gitd = match GitdSession::spawn(&grant.authority_token).await {
        Ok(gitd) => gitd,
        Err(error) => {
            cleanup_before_session(client.as_ref(), &grant, journal.as_ref(), &error).await;
            return Err(error);
        }
    };
    let ws = match gitd
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
    {
        Ok(workspace) => workspace,
        Err(error) => {
            cleanup_before_session(client.as_ref(), &grant, journal.as_ref(), &error).await;
            return Err(error);
        }
    };
    journal.record("workspace_cloned", &ws.repo_dir.display().to_string());
    run_cloned_attempt(
        client, adapter, journal, clock, &grant, config, &mut gitd, &ws,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_cloned_attempt(
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<dyn JournalSink>,
    clock: Arc<dyn Clock>,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    gitd: &mut dyn WorkspaceSession,
    ws: &WorkspaceInfo,
) -> Result<AttemptOutcome, RunnerError> {
    let heartbeat_call = HeartbeatCall::for_grant(grant)?;
    let heartbeat = start_heartbeat(
        client.clone(),
        heartbeat_call,
        config.heartbeat.clone(),
        clock,
    )?;
    let session = adapter.start(start_request(grant, ws, config)).await?;
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await?;
    match drive_and_finish(
        client.as_ref(),
        adapter.as_ref(),
        gitd,
        ws,
        grant,
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
                gitd,
                grant,
                config,
                journal.as_ref(),
                &session,
                &err,
            )
            .await;
            Err(err)
        }
    }
}

async fn cleanup_before_session(
    client: &dyn LeaseClient,
    grant: &AcquireGrant,
    journal: &dyn JournalSink,
    error: &RunnerError,
) {
    journal.record("workspace_refused", error.reason_code());
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
}

#[allow(clippy::too_many_arguments)]
async fn drive_and_finish(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    ws: &WorkspaceInfo,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
) -> Result<AttemptOutcome, RunnerError> {
    let capsule = config.capsule(grant, ws);
    let (gates, rounds) = session_loop(
        adapter, gitd, ws, &capsule, config, journal, heartbeat, session,
    )
    .await?;
    check_freeze(heartbeat)?;
    client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await?;
    let checkpoint = CheckpointBinding {
        id: capsule.base_checkpoint_id.clone(),
        digest: capsule.base_checkpoint_digest.clone(),
    };
    let request = PrepareCandidateRequest::from_grant(
        grant,
        ws,
        &checkpoint,
        &config.scope_prefixes,
        &config.bindings,
    )?;
    let candidate = gitd.prepare_candidate(&request).await?;
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
        gates,
    })
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    ws: &WorkspaceInfo,
    capsule: &Capsule,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
) -> Result<(Vec<GateReport>, u32), RunnerError> {
    let mut capsule = capsule.clone();
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
        if let Some(refusal) = pre_apply_refusal(&capsule, &proposal) {
            journal.record(refusal.stage, &refusal.detail);
            spend_repair_round(&mut rounds, config)?;
            prompt = refusal.prompt;
            continue;
        }
        check_freeze(heartbeat)?;
        let receipt = match gitd.apply_proposal(&proposal).await {
            Ok(receipt) => receipt,
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
        journal.record("patch_applied", &format!("{} paths", receipt.applied));
        capsule.advance_checkpoint(receipt.checkpoint.id, receipt.checkpoint.digest);
        let mut gates = Vec::with_capacity(config.admitted_gate_ids.len());
        for gate_id in &config.admitted_gate_ids {
            let report = run_gate(&ws.repo_dir, gate_id).await?;
            journal.record(
                "gate_result",
                &format!(
                    "gate {} exit {:?} timed_out {}",
                    report.gate_id, report.exit_code, report.timed_out
                ),
            );
            let passed = report.passed();
            gates.push(report);
            if !passed {
                break;
            }
        }
        if gates.len() == config.admitted_gate_ids.len() && gates.iter().all(GateReport::passed) {
            return Ok((gates, rounds));
        }
        spend_repair_round(&mut rounds, config)?;
        let report = gates
            .last()
            .ok_or_else(|| RunnerError::Protocol("admitted gate set produced no report".into()))?;
        prompt = capsule.gate_feedback_prompt(report);
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

/// Typed refusal the loop feeds back BEFORE any apply: an out-of-scope path
/// or a provider gate selection that differs from policy admission. Delete
/// entries are scope-checked exactly like writes; a delete of a missing file
/// is refused by the daemon at apply as `PATH_ABSENT`.
fn pre_apply_refusal(capsule: &Capsule, proposal: &PatchProposal) -> Option<Refusal> {
    let binding_mismatch = if proposal.producing_attempt_id != capsule.producing_attempt_id {
        Some(format!(
            "producing_attempt_id {} does not equal active {}",
            proposal.producing_attempt_id, capsule.producing_attempt_id
        ))
    } else if proposal.base_checkpoint_id != capsule.base_checkpoint_id {
        Some(format!(
            "base_checkpoint_id {} does not equal active {}",
            proposal.base_checkpoint_id, capsule.base_checkpoint_id
        ))
    } else if proposal.base_checkpoint_digest != capsule.base_checkpoint_digest {
        Some("base_checkpoint_digest does not equal the active checkpoint digest".into())
    } else {
        None
    };
    if let Some(detail) = binding_mismatch {
        return Some(Refusal {
            stage: "proposal_binding_refused",
            prompt: capsule.binding_refusal_prompt(&detail),
            detail,
        });
    }
    if let Err(RunnerError::ScopeDenied { path }) =
        scope::validate_proposal(&capsule.scope_prefixes, proposal)
    {
        return Some(Refusal {
            stage: "scope_denied",
            detail: path.clone(),
            prompt: capsule.scope_denied_prompt(&path),
        });
    }
    if let Err(error) =
        GateRegistry::v1().require_exact(&capsule.admitted_gate_ids, &proposal.gate_ids)
    {
        return Some(Refusal {
            stage: "gate_selection_refused",
            detail: error.to_string(),
            prompt: capsule.gate_selection_prompt(&error.to_string()),
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

async fn salvage_workspace(
    gitd: &mut dyn WorkspaceSession,
    grant: &AcquireGrant,
    config: &AttemptConfig,
) -> Result<SuccessorResume, RunnerError> {
    let checkpoint = gitd.checkpoint().await?;
    let destination = config
        .workspace_root
        .join("salvage")
        .join(grant.attempt.id.as_str());
    if destination.exists() {
        return Err(RunnerError::Protocol(format!(
            "salvage destination already exists: {}",
            destination.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| RunnerError::Io {
            context: "create salvage parent".into(),
            reason: error.to_string(),
        })?;
    }
    let preservation = gitd.preserve(&destination).await?;
    Ok(SuccessorResume {
        checkpoint,
        preservation,
    })
}

#[allow(clippy::too_many_arguments)]
async fn cleanup_failure(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    session: &SessionHandle,
    err: &RunnerError,
) {
    if err.is_frozen() {
        journal.record("frozen", err.reason_code());
        match salvage_workspace(gitd, grant, config).await {
            Ok(resume) => {
                journal.record(
                    "salvage_checkpoint",
                    &format!("{} {}", resume.checkpoint.id, resume.checkpoint.digest),
                );
                journal.record(
                    "salvage_preserved",
                    &format!(
                        "{} {}",
                        resume.preservation.digest,
                        resume.preservation.destination.display()
                    ),
                );
            }
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

#[cfg(test)]
mod binding_tests {
    use super::*;
    use bullet_harness_core::{PatchMutation, PatchOperation, Preimage};

    fn bound_capsule() -> Capsule {
        Capsule {
            objective: "test".into(),
            scope_prefixes: vec!["PONG.txt".into()],
            base_sha: "a".repeat(40),
            producing_attempt_id: format!("atm_{}", "2".repeat(64)),
            base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
            base_checkpoint_digest: "4".repeat(64),
            admitted_gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
        }
    }

    fn proposal() -> PatchProposal {
        let capsule = bound_capsule();
        PatchProposal {
            schema_version: 1,
            proposal_id: format!("cnt_{}", "1".repeat(64)),
            producing_attempt_id: capsule.producing_attempt_id,
            base_checkpoint_id: capsule.base_checkpoint_id,
            base_checkpoint_digest: capsule.base_checkpoint_digest,
            operations: vec![PatchOperation {
                path: "PONG.txt".into(),
                preimage: Preimage::Absent,
                mutation: PatchMutation::Write {
                    content_utf8: "PONG\n".into(),
                },
            }],
            gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
            intent_summary: String::new(),
            claims: vec![],
            uncertainties: vec![],
            done: true,
        }
    }

    #[test]
    fn stale_binding_is_refused_before_the_workspace_port() {
        let capsule = bound_capsule();
        let mut stale = proposal();
        stale.base_checkpoint_digest = "5".repeat(64);
        let refusal = pre_apply_refusal(&capsule, &stale).expect("binding refusal");
        assert_eq!(refusal.stage, "proposal_binding_refused");
        assert!(refusal.prompt.contains("Nothing was applied"));
    }

    #[test]
    fn exact_binding_and_sealed_gate_reach_the_workspace_boundary() {
        assert!(pre_apply_refusal(&bound_capsule(), &proposal()).is_none());
        let mut wrong_gate = proposal();
        wrong_gate.gate_ids = vec![format!("gat_{}", "7".repeat(64))];
        assert_eq!(
            pre_apply_refusal(&bound_capsule(), &wrong_gate)
                .expect("gate refusal")
                .stage,
            "gate_selection_refused"
        );
    }
}
