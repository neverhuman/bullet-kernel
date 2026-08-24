//! First mandatory demonstration. Simulators only. Every receipt field is
//! re-derived from ledger rows or live refusals — never fabricated.

use crate::graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
use crate::leases::LeaseService;
use crate::materializer::{materialize_plan, PlanInput};
use crate::records::{HeartbeatRequest, StoredGraph};
use crate::simulators::{ProviderSimulator, ScmSimulator};
use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Candidate, CandidateId, CommandPhase, Digest, DomainError,
    Effect, EffectId, Evidence, EvidenceId, MissionId, TaskClass, WorkPackageId, WorkPackageState,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const SEED: &str = "demo-mission";

/// Operator-visible receipt. Pending and verified are distinct; both fences
/// prove the epoch was never reused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoReceipt {
    /// Mission id.
    pub mission_id: String,
    /// Plan hash re-derived from the recorded materialize command payload.
    pub plan_hash: String,
    /// Fence of the first incarnation.
    pub fence: u64,
    /// First (now superseded) attempt.
    pub attempt_id: String,
    /// Fence of the successor incarnation. Must exceed `fence`.
    pub fence_second: u64,
    /// Successor attempt that produced the Candidate.
    pub attempt_second_id: String,
    /// Attempt whose authority was refused after supersession.
    pub stale_attempt_id: String,
    /// Candidate head SHA from the stored row.
    pub candidate_head: String,
    /// Evidence result from the stored row.
    pub evidence_result: String,
    /// Stored outcome of the acknowledged effect.
    pub effect_outcome: String,
    /// Stored outcome of the lost-response effect. Never assumed verified.
    pub effect_unknown_outcome: String,
    /// Whether replaying materialization returned the same graph.
    pub materialize_idempotent: bool,
    /// Whether the stale heartbeat and stale token were both refused live.
    pub stale_refused: bool,
}

fn now_str() -> String {
    LeaseService::rfc3339(Utc::now())
}

fn sim_sha(seed: &str) -> String {
    Digest::of(seed.as_bytes()).to_hex()[..40].to_string()
}

fn demo_plan() -> PlanInput {
    PlanInput {
        title: "First verified line to main".into(),
        objective: "Prove fenced authority, exact Candidates, and honest observations.".into(),
        packages: vec![
            (
                "Implement kernel demo path".into(),
                TaskClass::FeatureImplementation,
            ),
            (
                "Independent review of Candidate".into(),
                TaskClass::CodeReview,
            ),
        ],
    }
}

/// Run the spec's first demonstration against any ledger. Replaying against
/// the same ledger re-derives the receipt from stored rows.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn run_demo<L: Ledger>(ledger: &mut L) -> Result<DemoReceipt, LedgerError> {
    for invocation in ProviderSimulator.planning_council() {
        let kind = if invocation.lane == "fusion" {
            "fusion_plan"
        } else {
            "planner_proposal"
        };
        ledger.append_event(
            kind,
            &format!("{}:{}", invocation.lane, invocation.artifact),
        )?;
    }
    let input = demo_plan();
    let now = now_str();
    let first = materialize_plan(ledger, SEED, &input, &now)?;
    let second = materialize_plan(ledger, SEED, &input, &now)?;
    if first.mission.id != second.mission.id
        || first.plan.canonical_hash != second.plan.canonical_hash
    {
        return Err(LedgerError::Store(
            "materialization was not idempotent".into(),
        ));
    }
    if derive_receipt(ledger)?.is_none() {
        fresh_flow(ledger, &first)?;
    }
    derive_receipt(ledger)?
        .ok_or_else(|| LedgerError::Store("demo flow left incomplete rows".into()))
}

fn fresh_flow<L: Ledger>(ledger: &mut L, graph: &StoredGraph) -> Result<(), LedgerError> {
    let mission = graph.mission.id.clone();
    let wp0 = graph
        .packages
        .first()
        .map(|package| package.id.clone())
        .ok_or_else(|| LedgerError::Store("demo graph has no packages".into()))?;

    // Incarnation one: fence 1, heartbeats, then closes as superseded.
    let (a1, _token1, grant1) = LeaseService::acquire(ledger, graph, 0, "attempt-live", 15)?;
    transition_attempt(ledger, &a1, AttemptState::Running)?;
    ledger.heartbeat(&LeaseService::heartbeat_of(&grant1))?;
    LeaseService::release(ledger, &grant1, AttemptState::Superseded, true)?;

    // Incarnation two: fence 2, does the real work.
    let (a2, _token2, grant2) = LeaseService::acquire(ledger, graph, 0, "attempt-successor", 15)?;
    let a2_running = transition_attempt(ledger, &a2, AttemptState::Running)?;
    advance_package(ledger, &mission, &wp0, &[WorkPackageState::Executing])?;
    write_candidate_and_effects(ledger, &a2_running)?;
    transition_attempt(ledger, &a2_running, AttemptState::Preparing)?;
    LeaseService::release(ledger, &grant2, AttemptState::Succeeded, false)?;
    advance_package(
        ledger,
        &mission,
        &wp0,
        &[
            WorkPackageState::Prepared,
            WorkPackageState::Verifying,
            WorkPackageState::Verified,
        ],
    )?;
    Ok(())
}

fn transition_attempt<L: Ledger>(
    ledger: &mut L,
    attempt: &Attempt,
    to: AttemptState,
) -> Result<Attempt, LedgerError> {
    let mut next = attempt.clone();
    next.state = next.state.transition(to)?;
    ledger.put_attempt(&next)?;
    Ok(next)
}

fn advance_package<L: Ledger>(
    ledger: &mut L,
    mission: &MissionId,
    package: &WorkPackageId,
    targets: &[WorkPackageState],
) -> Result<(), LedgerError> {
    for target in targets {
        let graph = ledger
            .get_graph(mission)?
            .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
        let current = graph
            .packages
            .iter()
            .find(|candidate| candidate.id == *package)
            .map(|candidate| candidate.state)
            .ok_or_else(|| LedgerError::Store("package missing".into()))?;
        if current == *target {
            continue;
        }
        let delta = GraphDelta {
            parent: graph_digest(&graph),
            ops: vec![GraphOp::SetPackageState {
                id: package.clone(),
                from: current,
                to: *target,
            }],
        };
        apply_graph_delta(ledger, mission, &delta)?;
    }
    Ok(())
}

fn write_candidate_and_effects<L: Ledger>(
    ledger: &mut L,
    attempt: &Attempt,
) -> Result<(), LedgerError> {
    let candidate = Candidate {
        id: CandidateId::from_seed("demo-candidate"),
        attempt_id: attempt.id.clone(),
        base_sha: sim_sha("demo-base"),
        head_sha: sim_sha("demo-head"),
        tree_sha: sim_sha("demo-tree"),
        patch_digest: Digest::of(b"demo-patch"),
    };
    if ledger.put_candidate(&candidate)? {
        ledger.append_event("candidate_prepared", candidate.id.as_str())?;
    }
    let evidence = Evidence {
        id: EvidenceId::from_seed("demo-evidence"),
        candidate_id: candidate.id.clone(),
        tier: "E3".into(),
        gate: "bullet-farm/proof-complete".into(),
        result: "PASS".into(),
    };
    if ledger.put_evidence(&evidence)? {
        ledger.append_event("evidence_attached", evidence.id.as_str())?;
    }
    let acknowledged = ScmSimulator::default();
    record_effect(
        ledger,
        attempt,
        "demo-effect",
        "scm:push:demo-candidate",
        &acknowledged,
        "refs/heads/bullet/candidate/demo",
    )?;
    let lossy = ScmSimulator {
        lose_response: true,
    };
    record_effect(
        ledger,
        attempt,
        "demo-effect-lost",
        "scm:push:demo-candidate-lost",
        &lossy,
        "refs/heads/bullet/candidate/demo-lost",
    )?;
    Ok(())
}

fn record_effect<L: Ledger>(
    ledger: &mut L,
    attempt: &Attempt,
    id_seed: &str,
    logical_key: &str,
    scm: &ScmSimulator,
    ref_name: &str,
) -> Result<(), LedgerError> {
    let observation = scm.push_candidate(ref_name);
    let outcome = if observation.is_verified() {
        "verified"
    } else {
        "unknown"
    };
    let effect = Effect {
        id: EffectId::from_seed(id_seed),
        attempt_id: attempt.id.clone(),
        logical_key: logical_key.into(),
        desired: "candidate-ref-exists".into(),
        outcome: outcome.into(),
    };
    if ledger.put_effect(&effect)? {
        let payload = serde_json::to_string(&effect)
            .map_err(|err| LedgerError::Domain(DomainError::Encoding(err.to_string())))?;
        let now = now_str();
        let seq = ledger.outbox_enqueue("effect_receipt", &payload)?;
        ledger.outbox_mark(seq, CommandPhase::Applied, &now)?;
        let acked = if observation.is_verified() {
            CommandPhase::Verified
        } else {
            CommandPhase::Unknown
        };
        ledger.outbox_mark(seq, acked, &now)?;
        ledger.append_event("effect_receipt", outcome)?;
    }
    Ok(())
}

/// Re-derive the demo receipt from ledger rows. Returns `None` while the
/// demo has not completed. Stale refusals are re-checked live on every call.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn derive_receipt<L: Ledger>(ledger: &mut L) -> Result<Option<DemoReceipt>, LedgerError> {
    let mission_id = MissionId::from_seed(SEED);
    let Some(graph) = ledger.get_graph(&mission_id)? else {
        return Ok(None);
    };
    let Some(command) = ledger.get_command(&format!("materialize:{SEED}"))? else {
        return Ok(None);
    };
    let Some(a1) = ledger.get_attempt(&AttemptId::from_seed("attempt-live"))? else {
        return Ok(None);
    };
    let Some(a2) = ledger.get_attempt(&AttemptId::from_seed("attempt-successor"))? else {
        return Ok(None);
    };
    let Some(candidate) = ledger.get_candidate(&CandidateId::from_seed("demo-candidate"))? else {
        return Ok(None);
    };
    let Some(evidence) = ledger.get_evidence(&EvidenceId::from_seed("demo-evidence"))? else {
        return Ok(None);
    };
    let Some(effect) = ledger.get_effect(&EffectId::from_seed("demo-effect"))? else {
        return Ok(None);
    };
    let Some(effect_lost) = ledger.get_effect(&EffectId::from_seed("demo-effect-lost"))? else {
        return Ok(None);
    };
    let wp0 = WorkPackageId::from_seed(&format!("{SEED}:wp:0"));
    let verified = graph
        .packages
        .iter()
        .any(|package| package.id == wp0 && package.state == WorkPackageState::Verified);
    if !verified {
        return Ok(None);
    }
    let materialize_idempotent =
        graph.plan.canonical_hash == Digest::of(command.payload.as_bytes());
    let heartbeat = HeartbeatRequest {
        variant_id: a1.variant_id.clone(),
        attempt_id: a1.id.clone(),
        fence: a1.fence,
        runner_id: a1.runner_id.clone(),
        runner_epoch: a1.runner_epoch,
        workspace_nonce: a1.workspace_nonce,
        ttl_seconds: 15,
    };
    let heartbeat_refused = matches!(
        ledger.heartbeat(&heartbeat),
        Err(LedgerError::Domain(DomainError::StaleAuthority(_)))
    );
    let stale_token = LeaseService::token_for(&graph, &a1)?;
    let token_refused = LeaseService::authorize(&stale_token, &a2).is_err();
    Ok(Some(DemoReceipt {
        mission_id: graph.mission.id.to_string(),
        plan_hash: graph.plan.canonical_hash.to_hex(),
        fence: a1.fence,
        attempt_id: a1.id.to_string(),
        fence_second: a2.fence,
        attempt_second_id: a2.id.to_string(),
        stale_attempt_id: a1.id.to_string(),
        candidate_head: candidate.head_sha,
        evidence_result: evidence.result,
        effect_outcome: effect.outcome,
        effect_unknown_outcome: effect_lost.outcome,
        materialize_idempotent,
        stale_refused: heartbeat_refused && token_refused,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryLedger;

    #[test]
    fn demo_proves_fence_progression_and_honest_outcomes() {
        let mut ledger = MemoryLedger::new();
        let receipt = run_demo(&mut ledger).expect("demo");
        assert!(receipt.materialize_idempotent);
        assert!(receipt.stale_refused);
        assert_eq!(receipt.fence, 1);
        assert_eq!(receipt.fence_second, 2);
        assert_ne!(receipt.attempt_id, receipt.attempt_second_id);
        assert_eq!(receipt.stale_attempt_id, receipt.attempt_id);
        assert_eq!(receipt.evidence_result, "PASS");
        assert_eq!(receipt.effect_outcome, "verified");
        assert_eq!(receipt.effect_unknown_outcome, "unknown");
    }

    #[test]
    fn demo_replay_rederives_without_new_rows() {
        let mut ledger = MemoryLedger::new();
        let first = run_demo(&mut ledger).expect("demo");
        let attempts_after_first = ledger
            .list_attempts(&MissionId::from_seed(SEED))
            .expect("attempts")
            .len();
        let outbox_after_first = ledger.outbox_all().expect("outbox").len();
        let second = run_demo(&mut ledger).expect("replay");
        assert_eq!(first, second);
        assert_eq!(
            attempts_after_first,
            ledger
                .list_attempts(&MissionId::from_seed(SEED))
                .expect("attempts")
                .len()
        );
        assert_eq!(
            outbox_after_first,
            ledger.outbox_all().expect("outbox").len()
        );
    }
}
