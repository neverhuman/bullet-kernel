//! Council plan artifacts and their validation: independent proposals, the
//! provenance-preserving fused plan, and the honest degradation rules.

use crate::demo_live::fixture::OBJECTIVE;
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// One independent plan proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanProposal {
    /// Ordered steps.
    pub steps: Vec<String>,
    /// Known risks.
    #[serde(default)]
    pub risks: Vec<String>,
}

/// One fused item with provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusedItem {
    /// Item text.
    pub text: String,
    /// Source: a planner label, `both`, `fuser`, or `kernel`.
    pub from: String,
}

/// The fused plan with provenance per item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusedPlan {
    /// `FUSED`, `SELECTED`, `SELECTED_BY_KERNEL`, or `KERNEL_FALLBACK`.
    pub mode: String,
    /// Fused steps.
    pub steps: Vec<FusedItem>,
    /// Fused risks.
    #[serde(default)]
    pub risks: Vec<FusedItem>,
    /// Why this mode/selection.
    #[serde(default)]
    pub rationale: String,
}

/// One planner's recorded outcome.
#[derive(Clone, Debug)]
pub struct PlannerRecord {
    /// Provider label.
    pub provider: String,
    /// Council label (`A` or `B`).
    pub label: String,
    /// Provider-native session id when reported.
    pub session: Option<String>,
    /// Reported spend; `None` is honest not-reported.
    pub cost_usd: Option<f64>,
    /// Wall time across every attempt.
    pub wall_ms: u64,
    /// The parsed proposal, when one survived.
    pub plan: Option<PlanProposal>,
    /// Typed failure when it did not.
    pub failure: Option<String>,
}

/// Extract one JSON object from provider text: the whole text, a ```json
/// fence, or the outermost brace span, in that order.
#[must_use]
pub fn extract_json_object(text: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        if value.is_object() {
            return Some(value);
        }
    }
    if let Some(start) = text.find("```json") {
        let rest = &text[start + 7..];
        if let Some(end) = rest.find("```") {
            if let Ok(value) = serde_json::from_str::<Value>(rest[..end].trim()) {
                if value.is_object() {
                    return Some(value);
                }
            }
        }
    }
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
        if start < end {
            if let Ok(value) = serde_json::from_str::<Value>(&text[start..=end]) {
                if value.is_object() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Parse and validate one plan proposal from provider text.
pub fn parse_plan(text: &str) -> Result<PlanProposal, String> {
    let value = extract_json_object(text).ok_or("no JSON object in turn text")?;
    let plan: PlanProposal =
        serde_json::from_value(value).map_err(|err| format!("plan shape: {err}"))?;
    if plan.steps.is_empty() || plan.steps.len() > 12 {
        return Err(format!(
            "plan must carry 1..=12 steps, got {}",
            plan.steps.len()
        ));
    }
    if plan.steps.iter().any(|step| step.trim().is_empty()) {
        return Err("plan carries an empty step".into());
    }
    Ok(plan)
}

/// Validate a provider-produced fused plan against the available labels.
pub fn validate_fused(plan: &FusedPlan, labels: &[&str]) -> Result<(), String> {
    if plan.mode != "FUSED" && plan.mode != "SELECTED" {
        return Err(format!("mode must be FUSED or SELECTED, got {}", plan.mode));
    }
    if plan.steps.is_empty() {
        return Err("fused plan has no steps".into());
    }
    let both_ok = labels.len() >= 2;
    for item in plan.steps.iter().chain(plan.risks.iter()) {
        let ok = labels.contains(&item.from.as_str())
            || item.from == "fuser"
            || (both_ok && item.from == "both");
        if !ok {
            return Err(format!(
                "provenance source {:?} is not in the council",
                item.from
            ));
        }
    }
    Ok(())
}

/// Kernel fallback when the fuser (or the whole council) failed: SELECT the
/// first surviving proposal verbatim, or keep only the bare objective. The
/// kernel never invents plan content.
#[must_use]
pub fn kernel_fused(planners: &[PlannerRecord]) -> FusedPlan {
    if let Some(planner) = planners.iter().find(|p| p.plan.is_some()) {
        if let Some(plan) = planner.plan.clone() {
            let tag = |text: String| FusedItem {
                text,
                from: planner.label.clone(),
            };
            return FusedPlan {
                mode: "SELECTED_BY_KERNEL".into(),
                steps: plan.steps.into_iter().map(tag).collect(),
                risks: plan.risks.into_iter().map(tag).collect(),
                rationale: format!(
                    "fusion unavailable; kernel selected proposal {} ({}) verbatim",
                    planner.label, planner.provider
                ),
            };
        }
    }
    FusedPlan {
        mode: "KERNEL_FALLBACK".into(),
        steps: vec![FusedItem {
            text: OBJECTIVE.to_string(),
            from: "kernel".into(),
        }],
        risks: vec![],
        rationale: "no planner proposal survived; only the bare objective remains".into(),
    }
}

/// Provenance counts by source.
#[must_use]
pub fn provenance_counts(plan: &FusedPlan) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for item in plan.steps.iter().chain(plan.risks.iter()) {
        *counts.entry(item.from.clone()).or_insert(0) += 1;
    }
    counts
}

/// Content digest of the fused plan (hex).
pub fn fused_digest(plan: &FusedPlan) -> Result<String, String> {
    Digest::of_json(plan)
        .map(Digest::to_hex)
        .map_err(|err| format!("fused digest: {err}"))
}

/// Council failure codes: planner failures plus a fusion failure. An honest
/// provider `SELECTED` is not a failure.
#[must_use]
pub fn council_failures(planners: &[PlannerRecord], fusion_failure: Option<&str>) -> Vec<String> {
    let mut failures = Vec::new();
    for planner in planners {
        if planner.plan.is_none() {
            failures.push(format!(
                "PLANNER_FAILED:{}:{}",
                planner.label, planner.provider
            ));
        }
    }
    if let Some(reason) = fusion_failure {
        failures.push(format!("FUSION_FAILED:{reason}"));
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planner(label: &str, plan: Option<PlanProposal>) -> PlannerRecord {
        PlannerRecord {
            provider: "test".into(),
            label: label.into(),
            session: None,
            cost_usd: None,
            wall_ms: 0,
            plan,
            failure: plan_failure(),
        }
    }

    fn plan_failure() -> Option<String> {
        None
    }

    #[test]
    fn extraction_handles_fences_and_prose() {
        let fenced = "Here you go:\n```json\n{\"steps\": [\"a\"]}\n```\nthanks";
        assert!(parse_plan(fenced).is_ok());
        let prose = "I think the plan is {\"steps\": [\"a\"], \"risks\": []} overall.";
        assert_eq!(parse_plan(prose).expect("prose").steps, vec!["a"]);
        assert!(parse_plan("no json here").is_err());
        assert!(parse_plan("{\"steps\": []}").is_err());
    }

    #[test]
    fn fused_validation_enforces_provenance_and_mode() {
        let good = FusedPlan {
            mode: "FUSED".into(),
            steps: vec![FusedItem {
                text: "x".into(),
                from: "both".into(),
            }],
            risks: vec![],
            rationale: String::new(),
        };
        validate_fused(&good, &["A", "B"]).expect("valid");
        assert!(validate_fused(&good, &["A"]).is_err(), "both needs two");
        let bad_mode = FusedPlan {
            mode: "MERGED".into(),
            ..good.clone()
        };
        assert!(validate_fused(&bad_mode, &["A", "B"]).is_err());
        let bad_source = FusedPlan {
            steps: vec![FusedItem {
                text: "x".into(),
                from: "C".into(),
            }],
            ..good
        };
        assert!(validate_fused(&bad_source, &["A", "B"]).is_err());
    }

    #[test]
    fn kernel_fallback_selects_verbatim_or_keeps_objective() {
        let plan = PlanProposal {
            steps: vec!["one".into()],
            risks: vec!["r".into()],
        };
        let selected = kernel_fused(&[planner("B", Some(plan))]);
        assert_eq!(selected.mode, "SELECTED_BY_KERNEL");
        assert_eq!(selected.steps[0].from, "B");
        assert_eq!(selected.risks[0].from, "B");
        let bare = kernel_fused(&[planner("A", None)]);
        assert_eq!(bare.mode, "KERNEL_FALLBACK");
        assert_eq!(bare.steps[0].from, "kernel");
    }

    #[test]
    fn degradation_is_recorded_not_hidden() {
        let ok = planner(
            "A",
            Some(PlanProposal {
                steps: vec!["s".into()],
                risks: vec![],
            }),
        );
        let dead = planner("B", None);
        let failures = council_failures(&[ok.clone(), dead], Some("NO_FUSION_JSON"));
        assert_eq!(failures.len(), 2);
        assert!(failures[0].contains("PLANNER_FAILED:B"));
        assert!(failures[1].contains("FUSION_FAILED"));
        assert!(council_failures(&[ok], None).is_empty());
    }

    #[test]
    fn fused_digest_is_stable_hex() {
        let plan = kernel_fused(&[]);
        let first = fused_digest(&plan).expect("digest");
        assert_eq!(first.len(), 64);
        assert_eq!(first, fused_digest(&plan).expect("digest"));
    }
}
