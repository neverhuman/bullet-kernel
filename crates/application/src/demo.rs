//! Component-only ledger demonstration. It proves replay and fencing without
//! fabricating a Candidate, Evidence, Effect, or transaction receipt.

use crate::graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
use crate::leases::LeaseService;
use crate::materializer::{materialize_plan, PlanInput};
use crate::records::StoredGraph;
use crate::simulators::ProviderSimulator;
use crate::store::{Ledger, LedgerError, ProjectionReader};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Digest, DomainError, MissionId, TaskClass, WorkPackageId,
    WorkPackageState,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const SEED: &str = "demo-mission";
const STALE_REFUSAL_EVENT: &str = "demo_stale_authority_refused";
const CANDIDATE_NOT_PRODUCED: &str = "NOT_PRODUCED";
const EVIDENCE_NOT_RUN: &str = "NOT_RUN";
const EFFECT_NOT_DISPATCHED: &str = "NOT_DISPATCHED";

/// Operator-visible component receipt. Its negative subject fields make the
/// missing production transaction explicit; both fences prove only that the
/// local epoch was never reused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoReceipt {
    /// Mission id.
    pub mission_id: String,
    /// Plan hash re-derived from the recorded materialize command payload.
    pub plan_hash: String,
    /// Fence of the first incarnation.
    pub fence_first: u64,
    /// First (now superseded) attempt.
    pub attempt_id: String,
    /// Fence of the successor incarnation. Must exceed `fence_first`.
    pub fence_second: u64,
    /// Successor attempt that completed the local component sequence.
    pub attempt_second_id: String,
    /// Attempt whose authority was refused after supersession.
    pub stale_attempt_id: String,
    /// Always `NOT_PRODUCED`: this simulator never creates a Candidate.
    pub candidate_head: String,
    /// Always `NOT_RUN`: no independent verifier participates.
    pub evidence_result: String,
    /// Always `NOT_DISPATCHED`: no effect adapter participates.
    pub effect_outcome: String,
    /// Always `NOT_DISPATCHED`: ambiguity recovery belongs to the transaction demo.
    pub effect_unknown_outcome: String,
    /// Whether replaying materialization returned the same graph.
    pub materialize_idempotent: bool,
    /// Whether the stale heartbeat and stale token were both refused live.
    pub stale_refused: bool,
}

fn now_str() -> String {
    LeaseService::rfc3339(Utc::now())
}

fn demo_plan() -> PlanInput {
    PlanInput {
        title: "Local replay and fence component proof".into(),
        objective: "Prove idempotent materialization and stale-authority refusal only.".into(),
        packages: vec![
            (
                "Exercise kernel component path".into(),
                TaskClass::FeatureImplementation,
            ),
            (
                "Record the missing production transaction boundary".into(),
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
pub fn run_demo<L: Ledger + ProjectionReader>(ledger: &mut L) -> Result<DemoReceipt, LedgerError> {
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
    let (a1, token1, grant1) = LeaseService::acquire(ledger, graph, 0, "attempt-live", 15)?;
    transition_attempt(ledger, &a1, AttemptState::Running)?;
    ledger.heartbeat(&LeaseService::heartbeat_of(&grant1))?;
    LeaseService::release(ledger, &grant1, AttemptState::Superseded, true)?;

    // Incarnation two: fence 2, completes only the local component sequence.
    let (a2, _token2, grant2) = LeaseService::acquire(ledger, graph, 0, "attempt-successor", 15)?;
    let heartbeat_refused = match ledger.heartbeat(&LeaseService::heartbeat_of(&grant1)) {
        Err(LedgerError::Domain(DomainError::StaleAuthority(_))) => true,
        Err(err) => return Err(err),
        Ok(()) => false,
    };
    let token_refused = match LeaseService::authorize_patch_application(&token1, &a2) {
        Err(LedgerError::Domain(DomainError::StaleAuthority(_))) => true,
        Err(err) => return Err(err),
        Ok(()) => false,
    };
    if !heartbeat_refused || !token_refused {
        return Err(LedgerError::Store(
            "superseded demo authority was not refused".into(),
        ));
    }
    ledger.append_event(STALE_REFUSAL_EVENT, a1.id.as_str())?;
    let a2_running = transition_attempt(ledger, &a2, AttemptState::Running)?;
    advance_package(ledger, &mission, &wp0, &[WorkPackageState::Executing])?;
    transition_attempt(ledger, &a2_running, AttemptState::Preparing)?;
    LeaseService::release(ledger, &grant2, AttemptState::Succeeded, false)?;
    advance_package(ledger, &mission, &wp0, &[WorkPackageState::Prepared])?;
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

/// Re-derive the demo receipt from ledger rows. Returns `None` while the
/// demo has not completed. This projection is read-only; stale-refusal truth
/// must already exist as a durable event written by the live demo flow.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn derive_receipt<L: Ledger + ProjectionReader>(
    ledger: &L,
) -> Result<Option<DemoReceipt>, LedgerError> {
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
    if !ledger.list_candidates()?.is_empty()
        || !ledger.list_evidence()?.is_empty()
        || !ledger.list_effects()?.is_empty()
    {
        return Err(LedgerError::Store(
            "UNSUPPORTED_SCHEMA: legacy simulator authority rows detected; export any needed data, remove the demo data directory, and rerun the component demo".into(),
        ));
    }
    let wp0 = WorkPackageId::from_seed(&format!("{SEED}:wp:0"));
    let prepared = graph
        .packages
        .iter()
        .any(|package| package.id == wp0 && package.state == WorkPackageState::Prepared);
    if !prepared {
        return Ok(None);
    }
    let materialize_idempotent =
        graph.plan.canonical_hash == Digest::of(command.payload.as_bytes());
    let stale_refused = ledger
        .list_events()?
        .iter()
        .any(|event| event.kind == STALE_REFUSAL_EVENT && event.body == a1.id.as_str());
    if !stale_refused {
        return Ok(None);
    }
    Ok(Some(DemoReceipt {
        mission_id: graph.mission.id.to_string(),
        plan_hash: graph.plan.canonical_hash.to_hex(),
        fence_first: a1.fence,
        attempt_id: a1.id.to_string(),
        fence_second: a2.fence,
        attempt_second_id: a2.id.to_string(),
        stale_attempt_id: a1.id.to_string(),
        candidate_head: CANDIDATE_NOT_PRODUCED.into(),
        evidence_result: EVIDENCE_NOT_RUN.into(),
        effect_outcome: EFFECT_NOT_DISPATCHED.into(),
        effect_unknown_outcome: EFFECT_NOT_DISPATCHED.into(),
        materialize_idempotent,
        stale_refused,
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
        assert_eq!(receipt.fence_first, 1);
        assert_eq!(receipt.fence_second, 2);
        assert_ne!(receipt.attempt_id, receipt.attempt_second_id);
        assert_eq!(receipt.stale_attempt_id, receipt.attempt_id);
        assert_eq!(receipt.candidate_head, CANDIDATE_NOT_PRODUCED);
        assert_eq!(receipt.evidence_result, EVIDENCE_NOT_RUN);
        assert_eq!(receipt.effect_outcome, EFFECT_NOT_DISPATCHED);
        assert_eq!(receipt.effect_unknown_outcome, EFFECT_NOT_DISPATCHED);
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

    #[test]
    fn legacy_simulator_authority_rows_fail_closed() {
        let mut ledger = MemoryLedger::new();
        run_demo(&mut ledger).expect("component demo");
        let candidate = bullet_domain::Candidate {
            id: bullet_domain::CandidateId::from_seed("legacy-demo-candidate"),
            attempt_id: AttemptId::from_seed("attempt-successor"),
            base_sha: "a".repeat(40),
            head_sha: "b".repeat(40),
            tree_sha: "c".repeat(40),
            patch_digest: Digest::of(b"legacy-demo-patch"),
        };
        ledger.put_candidate(&candidate).expect("legacy row");

        let err = derive_receipt(&ledger).expect_err("legacy rows must refuse");
        assert!(err.to_string().contains("UNSUPPORTED_SCHEMA"));
    }
}
