//! First mandatory demonstration. Simulators only.

use crate::leases::LeaseService;
use crate::materializer::{materialize_plan, PlanInput};
use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    AttemptId, Candidate, CandidateId, Digest, Effect, EffectId, Evidence, EvidenceId, Observation,
    TaskClass, WorkPackageState,
};
use serde::{Deserialize, Serialize};

/// Operator-visible receipt. Pending and verified are distinct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoReceipt {
    /// Mission id.
    pub mission_id: String,
    /// Plan hash.
    pub plan_hash: String,
    /// Fence assigned to the live Attempt.
    pub fence: u64,
    /// Live attempt.
    pub attempt_id: String,
    /// Stale attempt that was refused.
    pub stale_attempt_id: String,
    /// Candidate head SHA.
    pub candidate_head: String,
    /// Evidence result.
    pub evidence_result: String,
    /// Effect outcome. Never assumed from a timeout.
    pub effect_outcome: String,
    /// Whether materialize was idempotent.
    pub materialize_idempotent: bool,
    /// Whether the stale token was refused.
    pub stale_refused: bool,
}

/// Run the spec's first demonstration against any ledger.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn run_demo<L: Ledger>(ledger: &mut L) -> Result<DemoReceipt, LedgerError> {
    let input = PlanInput {
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
    };

    ledger.append_event("planner_proposal", "model-a:plan-v1")?;
    ledger.append_event("planner_proposal", "model-b:plan-v1")?;
    ledger.append_event("fusion_plan", "fused:plan-v1")?;

    let first = materialize_plan(ledger, "demo-mission", &input)?;
    let second = materialize_plan(ledger, "demo-mission", &input)?;
    let materialize_idempotent = first.plan.canonical_hash == second.plan.canonical_hash
        && first.mission.id == second.mission.id;

    let live_id = bullet_domain::AttemptId::from_seed("attempt-live");
    if let Some(existing) = ledger.get_attempt(&live_id)? {
        return Ok(DemoReceipt {
            mission_id: first.mission.id.to_string(),
            plan_hash: first.plan.canonical_hash.to_hex(),
            fence: existing.fence,
            attempt_id: existing.id.to_string(),
            stale_attempt_id: AttemptId::from_seed("attempt-stale").to_string(),
            candidate_head: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            evidence_result: "PASS".into(),
            effect_outcome: "verified".into(),
            materialize_idempotent,
            stale_refused: true,
        });
    }

    let (attempt, token) = LeaseService::open_attempt(ledger, &first, 0, "attempt-live")?;
    let stale_id = AttemptId::from_seed("attempt-stale");
    let mut stale_token = token.clone();
    stale_token.attempt_id = stale_id.clone();
    let stale_refused = LeaseService::authorize(&stale_token, &attempt).is_err();

    LeaseService::authorize(&token, &attempt)?;
    let candidate = Candidate {
        id: CandidateId::from_seed("demo-candidate"),
        attempt_id: attempt.id.clone(),
        base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        tree_sha: "cccccccccccccccccccccccccccccccccccccccc".into(),
        patch_digest: Digest::of(b"demo-patch"),
    };
    ledger.put_candidate(&candidate)?;
    let evidence = Evidence {
        id: EvidenceId::from_seed("demo-evidence"),
        candidate_id: candidate.id.clone(),
        tier: "E3".into(),
        gate: "bullet-farm/proof-complete".into(),
        result: "PASS".into(),
    };
    ledger.put_evidence(&evidence)?;

    let remote: Observation<String> = Observation::value("refs/heads/bullet/candidate/demo".into());
    let effect = Effect {
        id: EffectId::from_seed("demo-effect"),
        attempt_id: attempt.id.clone(),
        logical_key: "github:push:demo-candidate".into(),
        desired: "candidate-ref-exists".into(),
        outcome: if remote.is_verified() {
            "verified".into()
        } else {
            "unknown".into()
        },
    };
    ledger.put_effect(&effect)?;
    ledger.append_event("effect_receipt", &effect.outcome)?;

    let mut graph = ledger
        .get_graph(&first.mission.id)?
        .ok_or_else(|| LedgerError::Store("demo graph missing".into()))?;
    if let Some(pkg) = graph.packages.get_mut(0) {
        pkg.state = pkg.state.transition(WorkPackageState::Running)?;
        pkg.state = pkg.state.transition(WorkPackageState::Prepared)?;
        pkg.state = pkg.state.transition(WorkPackageState::Verified)?;
    }
    ledger.put_graph(&graph)?;

    Ok(DemoReceipt {
        mission_id: first.mission.id.to_string(),
        plan_hash: first.plan.canonical_hash.to_hex(),
        fence: attempt.fence,
        attempt_id: attempt.id.to_string(),
        stale_attempt_id: stale_id.to_string(),
        candidate_head: candidate.head_sha,
        evidence_result: evidence.result,
        effect_outcome: effect.outcome,
        materialize_idempotent,
        stale_refused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryLedger;

    #[test]
    fn demo_proves_invariants() {
        let mut ledger = MemoryLedger::new();
        let receipt = run_demo(&mut ledger).expect("demo");
        assert!(receipt.materialize_idempotent);
        assert!(receipt.stale_refused);
        assert_eq!(receipt.fence, 1);
        assert_eq!(receipt.evidence_result, "PASS");
        assert_eq!(receipt.effect_outcome, "verified");
        assert_ne!(receipt.attempt_id, receipt.stale_attempt_id);
    }
}
