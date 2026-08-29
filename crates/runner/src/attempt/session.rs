//! Bounded provider/apply/gate repair loop.

use super::workspace::WorkspaceSession;
use super::{check_freeze, AttemptConfig};
use crate::capsule::Capsule;
use crate::error::RunnerError;
use crate::gate::{run_gate_bound_verified, GateRegistry, GateReport, GateWorkdir};
use crate::gitd::{WorkspaceGenerationGuard, WorkspaceInfo};
use crate::heartbeat::HeartbeatHandle;
use crate::journal::JournalSink;
use crate::scope;
use bullet_harness_core::{AgentEventKind, HarnessAdapter, PatchProposal, SessionHandle, Turn};
use futures::StreamExt;
use serde_json::Value;

#[allow(clippy::too_many_arguments)]
pub(super) async fn session_loop(
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    ws: &mut WorkspaceInfo,
    authority: &bullet_domain::AuthorityToken,
    capsule: &Capsule,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
    generation_guard: &mut WorkspaceGenerationGuard,
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
        let generation = ws.validate_successor(&receipt, authority)?;
        let gate_workdir = GateWorkdir::from_file(generation_guard.open_generation(generation)?)?;
        let expected_git_tree = receipt
            .active_generation
            .checkpoint
            .git_tree
            .as_deref()
            .ok_or_else(|| RunnerError::Protocol("generation checkpoint lacks Git tree".into()))?;
        gate_workdir.verify_git_tree(expected_git_tree).await?;
        ws.commit_successor(&receipt);
        capsule.advance_checkpoint(receipt.checkpoint.id, receipt.checkpoint.digest);
        let mut gates = Vec::with_capacity(config.admitted_gate_ids.len());
        for gate_id in &config.admitted_gate_ids {
            let report = run_gate_bound_verified(&gate_workdir, gate_id, expected_git_tree).await?;
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
            gate_workdir.verify_git_tree(expected_git_tree).await?;
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

pub(super) struct Refusal {
    pub(super) stage: &'static str,
    detail: String,
    pub(super) prompt: String,
}

/// Typed refusal the loop feeds back BEFORE any apply: an out-of-scope path
/// or a provider gate selection that differs from policy admission. Delete
/// entries are scope-checked exactly like writes; a delete of a missing file
/// is refused by the daemon at apply as `PATH_ABSENT`.
pub(super) fn pre_apply_refusal(capsule: &Capsule, proposal: &PatchProposal) -> Option<Refusal> {
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
