//! The LIVE planning council (`demo-live`): claude and codex each get one
//! bounded structured turn, then cursor fuses the proposals preserving
//! per-item provenance. Every artifact and failure lands as a ledger event;
//! a failed provider degrades the council honestly — the kernel never
//! fabricates a provider's plan. Every spawn stays subject to the
//! harness-core live-admission gate.

use crate::demo_live::fixture::{Fixture, OBJECTIVE};
use crate::demo_live::live_adapters::adapter_for;
use crate::demo_live::plan_types::{
    council_failures, extract_json_object, fused_digest, kernel_fused, parse_plan,
    provenance_counts, validate_fused, FusedPlan, PlanProposal, PlannerRecord,
};
use crate::demo_live::synthetic_council::CouncilOutcome;
use crate::demo_live::turns::one_turn;
use crate::demo_live::SharedLedger;
use bullet_application::Ledger;
use bullet_harness_core::HarnessAdapter;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Wall bound for one council turn (ADR 0001: at most 240s).
const COUNCIL_TURN_WALL: Duration = Duration::from_secs(240);
/// Attempts per provider before degrading.
const COUNCIL_ATTEMPTS: u32 = 2;

struct FusionTurn {
    plan: Option<FusedPlan>,
    session: Option<String>,
    cost: Option<f64>,
    wall: u64,
    failure: Option<String>,
}

/// Run the live council and record its ledger events.
pub async fn run_live_council(
    ledger: &SharedLedger,
    fixture: &Fixture,
    data_dir: &Path,
) -> Result<CouncilOutcome, String> {
    let outcome = live_council(fixture, data_dir).await?;
    record_events(ledger, &outcome)?;
    Ok(outcome)
}

fn fixture_readme(fixture: &Fixture) -> String {
    std::fs::read_to_string(fixture.origin.join("README.md")).unwrap_or_default()
}

fn council_workdir(data_dir: &Path, provider: &str, fixture: &Fixture) -> Result<PathBuf, String> {
    let dir = data_dir.join("council").join(provider);
    std::fs::create_dir_all(&dir).map_err(|err| format!("create council dir: {err}"))?;
    std::fs::write(dir.join("README.md"), fixture_readme(fixture))
        .map_err(|err| format!("write council README: {err}"))?;
    std::fs::write(
        dir.join("OBJECTIVE.txt"),
        format!("{OBJECTIVE}\nGate: {}\n", fixture.gate_command),
    )
    .map_err(|err| format!("write objective: {err}"))?;
    Ok(dir)
}

fn planner_prompt(fixture: &Fixture) -> String {
    format!(
        "You are one of two INDEPENDENT planners for a Bullet Farm mission. Do not write \
         files; reply with text only.\nObjective: {OBJECTIVE}\nGate command: {}\nRepository \
         README:\n{}\nRespond with EXACTLY one JSON object and nothing else, shaped as:\n\
         {{\"steps\": [\"...\"], \"risks\": [\"...\"]}}\nUse 2 to 6 short imperative steps \
         describing how a separate executor should reach the objective, and 0 to 4 risks.",
        fixture.gate_command,
        fixture_readme(fixture)
    )
}

fn fusion_prompt(available: &[(&str, &str, &PlanProposal)]) -> String {
    let mut text = String::from(
        "You fuse independent plan proposals for a Bullet Farm mission into ONE plan while \
         PRESERVING PROVENANCE. Do not write files; reply with text only.\n",
    );
    text.push_str(&format!("Objective: {OBJECTIVE}\n"));
    for (label, provider, plan) in available {
        text.push_str(&format!(
            "Proposal {label} (from {provider}): {}\n",
            serde_json::to_string(plan).unwrap_or_default()
        ));
    }
    let labels: Vec<&str> = available.iter().map(|(label, _, _)| *label).collect();
    let both = if labels.len() >= 2 { ", \"both\"" } else { "" };
    text.push_str(&format!(
        "Respond with EXACTLY one JSON object and nothing else:\n{{\"mode\": \"FUSED\" or \
         \"SELECTED\", \"steps\": [{{\"text\": \"...\", \"from\": \"...\"}}], \"risks\": \
         [{{\"text\": \"...\", \"from\": \"...\"}}], \"rationale\": \"...\"}}\nEvery \
         \"from\" must name where the item came from: one of {labels:?}{both}, or \
         \"fuser\" for glue you added. If you cannot honestly fuse, set mode to \
         \"SELECTED\", copy one proposal's steps with its label, and say so in rationale."
    ));
    text
}

async fn plan_with_retry(
    adapter: &dyn HarnessAdapter,
    provider: &str,
    label: &str,
    workdir: &Path,
    artifacts: &Path,
    prompt: &str,
) -> PlannerRecord {
    let mut record = PlannerRecord {
        provider: provider.into(),
        label: label.into(),
        session: None,
        cost_usd: None,
        wall_ms: 0,
        plan: None,
        failure: None,
    };
    for round in 1..=COUNCIL_ATTEMPTS {
        let seed = format!("plan-{provider}-{round}");
        let turn = one_turn(
            adapter,
            &seed,
            workdir,
            artifacts,
            prompt,
            COUNCIL_TURN_WALL,
        )
        .await;
        record.wall_ms += turn.wall_ms;
        if let Some(cost) = turn.cost_usd {
            record.cost_usd = Some(record.cost_usd.unwrap_or(0.0) + cost);
        }
        if turn.session.is_some() {
            record.session = turn.session.clone();
        }
        match (turn.failure, turn.text) {
            (Some(failure), _) => record.failure = Some(failure),
            (None, Some(text)) => match parse_plan(&text) {
                Ok(plan) => {
                    record.plan = Some(plan);
                    record.failure = None;
                    return record;
                }
                Err(err) => record.failure = Some(format!("NO_PLAN_JSON: {err}")),
            },
            (None, None) => record.failure = Some("EMPTY_TURN_TEXT".into()),
        }
    }
    record
}

async fn fuse_with_retry(
    adapter: &dyn HarnessAdapter,
    provider: &str,
    workdir: &Path,
    artifacts: &Path,
    available: &[(&str, &str, &PlanProposal)],
) -> FusionTurn {
    let prompt = fusion_prompt(available);
    let labels: Vec<&str> = available.iter().map(|(label, _, _)| *label).collect();
    let mut result = FusionTurn {
        plan: None,
        session: None,
        cost: None,
        wall: 0,
        failure: None,
    };
    for round in 1..=COUNCIL_ATTEMPTS {
        let seed = format!("fuse-{provider}-{round}");
        let turn = one_turn(
            adapter,
            &seed,
            workdir,
            artifacts,
            &prompt,
            COUNCIL_TURN_WALL,
        )
        .await;
        result.wall += turn.wall_ms;
        if let Some(cost) = turn.cost_usd {
            result.cost = Some(result.cost.unwrap_or(0.0) + cost);
        }
        if turn.session.is_some() {
            result.session = turn.session.clone();
        }
        match (turn.failure, turn.text) {
            (Some(failure), _) => result.failure = Some(failure),
            (None, Some(text)) => match parse_fused(&text, &labels) {
                Ok(plan) => {
                    result.plan = Some(plan);
                    result.failure = None;
                    return result;
                }
                Err(err) => result.failure = Some(format!("NO_FUSION_JSON: {err}")),
            },
            (None, None) => result.failure = Some("EMPTY_TURN_TEXT".into()),
        }
    }
    result
}

fn parse_fused(text: &str, labels: &[&str]) -> Result<FusedPlan, String> {
    let value = extract_json_object(text).ok_or("no JSON object in turn text")?;
    let plan: FusedPlan =
        serde_json::from_value(value).map_err(|err| format!("fused shape: {err}"))?;
    validate_fused(&plan, labels)?;
    Ok(plan)
}

async fn live_council(fixture: &Fixture, data_dir: &Path) -> Result<CouncilOutcome, String> {
    let artifacts = data_dir.join("artifacts").join("council");
    let claude = adapter_for("claude").ok_or("claude adapter missing")?;
    let codex = adapter_for("codex").ok_or("codex adapter missing")?;
    let cursor = adapter_for("cursor").ok_or("cursor adapter missing")?;
    let prompt = planner_prompt(fixture);
    let workdir_a = council_workdir(data_dir, "claude", fixture)?;
    let a = plan_with_retry(
        claude.as_ref(),
        "claude",
        "A",
        &workdir_a,
        &artifacts,
        &prompt,
    )
    .await;
    let workdir_b = council_workdir(data_dir, "codex", fixture)?;
    let b = plan_with_retry(
        codex.as_ref(),
        "codex",
        "B",
        &workdir_b,
        &artifacts,
        &prompt,
    )
    .await;
    let planners = vec![a, b];
    let available: Vec<(&str, &str, &PlanProposal)> = planners
        .iter()
        .filter_map(|planner| {
            planner
                .plan
                .as_ref()
                .map(|plan| (planner.label.as_str(), planner.provider.as_str(), plan))
        })
        .collect();
    let (fused, fused_by, fusion) = if available.is_empty() {
        let fusion = FusionTurn {
            plan: None,
            session: None,
            cost: None,
            wall: 0,
            failure: Some("NO_PROPOSALS".into()),
        };
        (kernel_fused(&planners), "kernel".to_string(), fusion)
    } else {
        let workdir_f = council_workdir(data_dir, "cursor", fixture)?;
        let fusion = fuse_with_retry(
            cursor.as_ref(),
            "cursor",
            &workdir_f,
            &artifacts,
            &available,
        )
        .await;
        match fusion.plan.clone() {
            Some(plan) => (plan, "cursor".to_string(), fusion),
            None => (kernel_fused(&planners), "kernel".to_string(), fusion),
        }
    };
    finish_outcome(planners, fused, fused_by, fusion)
}

fn finish_outcome(
    planners: Vec<PlannerRecord>,
    fused: FusedPlan,
    fused_by: String,
    fusion: FusionTurn,
) -> Result<CouncilOutcome, String> {
    let failures = council_failures(&planners, fusion.failure.as_deref());
    let degraded = !failures.is_empty();
    let digest = fused_digest(&fused)?;
    Ok(CouncilOutcome {
        planners,
        fused,
        fused_by,
        fused_session: fusion.session,
        fused_cost_usd: fusion.cost,
        fused_wall_ms: fusion.wall,
        degraded,
        failures,
        fused_digest: digest,
    })
}

fn record_events(ledger: &SharedLedger, outcome: &CouncilOutcome) -> Result<(), String> {
    let mut guard = ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_string())?;
    for planner in &outcome.planners {
        let (kind, body) = match &planner.plan {
            Some(plan) => (
                "planner_proposal",
                json!({
                    "provider": planner.provider, "label": planner.label,
                    "session": planner.session, "wall_ms": planner.wall_ms,
                    "cost_usd": planner.cost_usd, "plan": plan,
                }),
            ),
            None => (
                "planner_failed",
                json!({
                    "provider": planner.provider, "label": planner.label,
                    "failure": planner.failure,
                }),
            ),
        };
        guard
            .append_event(kind, &body.to_string())
            .map_err(|err| format!("record {kind}: {err}"))?;
    }
    let body = json!({
        "fused_by": outcome.fused_by, "mode": outcome.fused.mode,
        "provenance": provenance_counts(&outcome.fused), "degraded": outcome.degraded,
        "failures": outcome.failures, "session": outcome.fused_session,
        "digest": outcome.fused_digest, "plan": outcome.fused,
    });
    guard
        .append_event("fusion_plan", &body.to_string())
        .map_err(|err| format!("record fusion_plan: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fused_parse_rejects_foreign_provenance_and_bad_modes() {
        let bad = r#"{"mode":"FUSED","steps":[{"text":"x","from":"Z"}]}"#;
        assert!(parse_fused(bad, &["A", "B"]).is_err());
        let good = r#"{"mode":"SELECTED","steps":[{"text":"x","from":"A"}],"rationale":"only A"}"#;
        assert_eq!(
            parse_fused(good, &["A"]).expect("selected").mode,
            "SELECTED"
        );
        let merged = r#"{"mode":"MERGED","steps":[{"text":"x","from":"A"}]}"#;
        assert!(parse_fused(merged, &["A", "B"]).is_err());
    }
}
