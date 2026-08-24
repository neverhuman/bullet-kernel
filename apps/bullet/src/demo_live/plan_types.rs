//! Council plan artifacts and their validation: independent proposals, the
//! provenance-preserving fused plan, and the honest degradation rules.

use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fused_digest_is_stable_hex() {
        let plan = FusedPlan {
            mode: "FUSED".into(),
            steps: vec![FusedItem {
                text: "one".into(),
                from: "A".into(),
            }],
            risks: vec![],
            rationale: "test".into(),
        };
        let first = fused_digest(&plan).expect("digest");
        assert_eq!(first.len(), 64);
        assert_eq!(first, fused_digest(&plan).expect("digest"));
    }
}
