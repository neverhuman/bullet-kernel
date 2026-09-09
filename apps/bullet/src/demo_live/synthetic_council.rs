//! Deterministic simulator council for non-gating integration scaffolding.

use crate::demo_synthetic::plan_types::{
    fused_digest, provenance_counts, validate_fused, FusedItem, FusedPlan, PlanProposal,
    PlannerRecord,
};
use crate::demo_synthetic::SharedLedger;
use bullet_application::Ledger;
use serde_json::json;

/// Simulator council output used by the scaffold.
#[derive(Clone, Debug)]
pub struct CouncilOutcome {
    /// Both deterministic planner records.
    pub planners: Vec<PlannerRecord>,
    /// Deterministically fused plan.
    pub fused: FusedPlan,
    /// Always `sim`.
    pub fused_by: String,
    /// Synthetic session identifier.
    pub fused_session: Option<String>,
    /// Always unknown because no paid provider ran.
    pub fused_cost_usd: Option<f64>,
    /// Deterministic simulator wall time.
    pub fused_wall_ms: u64,
    /// Always false for the built-in fixture.
    pub degraded: bool,
    /// Local scaffold failures.
    pub failures: Vec<String>,
    /// Content digest of the fused plan.
    pub fused_digest: String,
}

/// Build and record the deterministic simulator council.
pub fn run_council(ledger: &SharedLedger) -> Result<CouncilOutcome, String> {
    let outcome = build()?;
    record_events(ledger, &outcome)?;
    Ok(outcome)
}

fn build() -> Result<CouncilOutcome, String> {
    let plan_a = PlanProposal {
        steps: vec![
            "Create PONG.txt with the exact content PONG".into(),
            "Run the gate script to confirm".into(),
        ],
        risks: vec!["Trailing whitespace would fail the exact-match gate".into()],
    };
    let plan_b = PlanProposal {
        steps: vec![
            "Write the single line PONG into PONG.txt".into(),
            "Echo the admitted full-width gate ID".into(),
        ],
        risks: vec!["Scope is limited to PONG.txt".into()],
    };
    let fused = fused_plan();
    validate_fused(&fused, &["A", "B"]).map_err(|error| format!("sim fusion invalid: {error}"))?;
    let planner = |label: &str, plan: PlanProposal| PlannerRecord {
        provider: "sim".into(),
        label: label.into(),
        session: Some(format!("sim-planner-{}", label.to_lowercase())),
        cost_usd: None,
        wall_ms: 0,
        plan: Some(plan),
        failure: None,
    };
    let digest = fused_digest(&fused)?;
    Ok(CouncilOutcome {
        planners: vec![planner("A", plan_a), planner("B", plan_b)],
        fused,
        fused_by: "sim".into(),
        fused_session: Some("sim-fusion".into()),
        fused_cost_usd: None,
        fused_wall_ms: 0,
        degraded: false,
        failures: Vec::new(),
        fused_digest: digest,
    })
}

fn fused_plan() -> FusedPlan {
    FusedPlan {
        mode: "FUSED".into(),
        steps: vec![
            FusedItem {
                text: "Create PONG.txt containing exactly PONG".into(),
                from: "both".into(),
            },
            FusedItem {
                text: "Request the admitted full-width gate".into(),
                from: "B".into(),
            },
        ],
        risks: vec![FusedItem {
            text: "Exact-match gate: no extra whitespace".into(),
            from: "A".into(),
        }],
        rationale: "deterministic simulator fusion".into(),
    }
}

fn record_events(ledger: &SharedLedger, outcome: &CouncilOutcome) -> Result<(), String> {
    let mut guard = ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_string())?;
    for planner in &outcome.planners {
        let body = json!({
            "provider": planner.provider,
            "label": planner.label,
            "session": planner.session,
            "wall_ms": planner.wall_ms,
            "cost_usd": planner.cost_usd,
            "plan": planner.plan,
        });
        guard
            .append_event("synthetic_planner_proposal", &body.to_string())
            .map_err(|error| format!("record synthetic planner: {error}"))?;
    }
    let body = json!({
        "fused_by": outcome.fused_by,
        "mode": outcome.fused.mode,
        "provenance": provenance_counts(&outcome.fused),
        "degraded": outcome.degraded,
        "failures": outcome.failures,
        "session": outcome.fused_session,
        "digest": outcome.fused_digest,
        "plan": outcome.fused,
    });
    guard
        .append_event("synthetic_fusion_plan", &body.to_string())
        .map_err(|error| format!("record synthetic fusion: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn council_is_deterministic_and_simulator_only() {
        let first = build().expect("first");
        let second = build().expect("second");
        assert_eq!(first.fused_by, "sim");
        assert_eq!(first.fused_digest, second.fused_digest);
        assert!(first
            .planners
            .iter()
            .all(|planner| planner.provider == "sim"));
        assert!(first.fused_cost_usd.is_none());
    }
}
