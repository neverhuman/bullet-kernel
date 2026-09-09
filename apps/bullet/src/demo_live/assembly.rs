//! Receipt assembly for the simulator-only integration scaffold.

use std::path::Path;

use bullet_application::Ledger;

use super::{plan_types, receipt, runner, Materialized, SharedLedger};
use receipt::{compute_scaffold_failures, EffectOut, SyntheticIntegrationReceipt, UsageRow};

#[derive(Default)]
pub(super) struct Assembly {
    provider: String,
    classification: String,
    mission_id: Option<String>,
    plan_hash: Option<String>,
    fused_plan_digest: Option<String>,
    mission_materialized_once: bool,
    pub(super) fence_first: Option<u64>,
    fence_second: Option<u64>,
    pub(super) stale_refused: bool,
    pub(super) attempt_first_id: Option<String>,
    attempt_second_id: Option<String>,
    planning: Option<receipt::PlanningReceipt>,
    candidate: Option<receipt::CandidateOut>,
    gate: Option<receipt::GateOut>,
    pub(super) evidence: Option<receipt::EvidenceOut>,
    pub(super) local_effect: Option<receipt::LocalEffectOut>,
    pub(super) jeryu: Option<receipt::JeryuOut>,
    provider_usage: Vec<UsageRow>,
    pub(super) step_failure: Option<String>,
}

impl Assembly {
    pub(super) fn new() -> Self {
        Self {
            provider: "sim".to_string(),
            classification: "SYNTHETIC_INTEGRATION_SCAFFOLD".to_string(),
            ..Self::default()
        }
    }

    pub(super) fn absorb_council(&mut self, council: &super::synthetic_council::CouncilOutcome) {
        self.fused_plan_digest = Some(council.fused_digest.clone());
        let providers = council
            .planners
            .iter()
            .map(|planner| receipt::PlannerSummary {
                provider: planner.provider.clone(),
                label: planner.label.clone(),
                session: planner.session.clone(),
                ok: planner.plan.is_some(),
                failure: planner.failure.clone(),
            })
            .collect();
        self.planning = Some(receipt::PlanningReceipt {
            providers,
            fused_by: council.fused_by.clone(),
            mode: council.fused.mode.clone(),
            provenance: plan_types::provenance_counts(&council.fused),
            degraded: council.degraded,
            failures: council.failures.clone(),
        });
        for planner in &council.planners {
            self.provider_usage.push(UsageRow {
                provider: planner.provider.clone(),
                role: format!("planner-{}", planner.label),
                session: planner.session.clone(),
                cost_usd: planner.cost_usd,
                wall_ms: planner.wall_ms,
            });
        }
        self.provider_usage.push(UsageRow {
            provider: council.fused_by.clone(),
            role: "fusion".into(),
            session: council.fused_session.clone(),
            cost_usd: council.fused_cost_usd,
            wall_ms: council.fused_wall_ms,
        });
    }

    pub(super) fn absorb_materialized(&mut self, materialized: &Materialized) {
        self.mission_id = Some(materialized.graph.mission.id.to_string());
        self.plan_hash = Some(materialized.plan_hash.clone());
        self.mission_materialized_once = materialized.once;
    }

    pub(super) fn absorb_runner(&mut self, phase: &runner::RunnerPhase) {
        let outcome = &phase.outcome;
        self.fence_second = Some(outcome.fence);
        self.attempt_second_id = Some(outcome.attempt_id.to_string());
        self.candidate = Some(receipt::CandidateOut {
            id: outcome.candidate.id.clone(),
            base: outcome.candidate.base_commit.clone(),
            head: outcome.candidate.head_commit.clone(),
            tree: outcome.candidate.tree_hash.clone(),
            patch_digest: outcome.candidate.patch_hash.clone(),
            actual_scope: outcome.candidate.actual_scope.clone(),
        });
        let all_passed =
            !outcome.gates.is_empty() && outcome.gates.iter().all(|gate| gate.passed());
        self.gate = Some(receipt::GateOut {
            writer_outcome: if all_passed { "PASS" } else { "FAIL" }.to_string(),
            gate_ids: outcome
                .gates
                .iter()
                .map(|gate| gate.gate_id.clone())
                .collect(),
            argv: outcome.gates.iter().map(|gate| gate.argv.clone()).collect(),
            exit_codes: outcome.gates.iter().map(|gate| gate.exit_code).collect(),
            repair_rounds: outcome.repair_rounds,
        });
        self.provider_usage.push(UsageRow {
            provider: "sim".to_string(),
            role: "runner".into(),
            session: phase.session.clone(),
            cost_usd: phase.cost_usd,
            wall_ms: phase.wall_ms,
        });
    }

    fn into_receipt(self) -> SyntheticIntegrationReceipt {
        let mut receipt = SyntheticIntegrationReceipt {
            classification: self.classification,
            transaction_gate_eligible: false,
            provider: self.provider,
            mission_id: self.mission_id,
            plan_hash: self.plan_hash,
            fused_plan_digest: self.fused_plan_digest,
            mission_materialized_once: self.mission_materialized_once,
            fence_first: self.fence_first,
            fence_second: self.fence_second,
            stale_refused: self.stale_refused,
            attempt_first_id: self.attempt_first_id,
            attempt_second_id: self.attempt_second_id,
            planning: self.planning,
            candidate: self.candidate,
            gate: self.gate,
            evidence: self.evidence,
            effect: EffectOut {
                local: self.local_effect,
                jeryu: self.jeryu,
            },
            provider_usage: self.provider_usage,
            scaffold_failures: vec![],
        };
        let mut failures = compute_scaffold_failures(&receipt);
        if let Some(step) = self.step_failure {
            failures.insert(0, format!("STEP_FAILED:{step}"));
        }
        receipt.scaffold_failures = failures;
        receipt
    }
}

pub(super) fn finish(
    ledger: &SharedLedger,
    data_dir: &Path,
    assembly: Assembly,
) -> Result<(), String> {
    let receipt = assembly.into_receipt();
    let json =
        serde_json::to_string_pretty(&receipt).map_err(|err| format!("encode receipt: {err}"))?;
    let path = data_dir.join("synthetic-integration-receipt.json");
    std::fs::write(&path, &json).map_err(|err| format!("write receipts: {err}"))?;
    if let Ok(mut guard) = ledger.lock() {
        let _ = guard.append_event("synthetic_integration_receipt", &json);
    }
    println!("{json}");
    println!("receipts: {}", path.display());
    if receipt.scaffold_failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            receipt.classification,
            receipt.scaffold_failures.join(", ")
        ))
    }
}
