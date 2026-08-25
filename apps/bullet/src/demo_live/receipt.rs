//! A simulator-only integration-scaffold receipt. It is explicit about its
//! non-gating classification and cannot stand in for `GateReceiptV1`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One planner's summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlannerSummary {
    /// Provider label.
    pub provider: String,
    /// Council label.
    pub label: String,
    /// Provider-native session id.
    pub session: Option<String>,
    /// Whether a proposal survived.
    pub ok: bool,
    /// Typed failure otherwise.
    pub failure: Option<String>,
}

/// Planning-phase receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanningReceipt {
    /// Both planners.
    pub providers: Vec<PlannerSummary>,
    /// Who fused.
    pub fused_by: String,
    /// Fusion mode.
    pub mode: String,
    /// Item counts per provenance source.
    pub provenance: BTreeMap<String, u64>,
    /// True when the council degraded.
    pub degraded: bool,
    /// Typed degradation codes.
    pub failures: Vec<String>,
}

/// Candidate identity exactly as prepared by bullet-gitd.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateOut {
    /// Content-derived candidate id.
    pub id: String,
    /// Base commit SHA.
    pub base: String,
    /// Head commit SHA.
    pub head: String,
    /// Tree SHA.
    pub tree: String,
    /// BLAKE3 patch digest (hex).
    pub patch_digest: String,
    /// Paths actually written.
    pub actual_scope: Vec<String>,
}

/// The writer-side deterministic gate result (E1 class).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateOut {
    /// `PASS` only on a clean zero exit.
    pub writer_outcome: String,
    /// Ordered IDs resolved by the writer's fixed registry.
    pub gate_ids: Vec<String>,
    /// Exact fixed argv resolved for each gate ID.
    pub argv: Vec<Vec<String>>,
    /// Gate exit codes in the same order.
    pub exit_codes: Vec<Option<i32>>,
    /// Repair rounds consumed.
    pub repair_rounds: u32,
}

/// Independent verifier evidence summary (E2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceOut {
    /// Typed gate outcome.
    pub verifier_outcome: String,
    /// Evidence tier.
    pub tier: String,
    /// Gate label.
    pub gate: String,
    /// Producer identity.
    pub produced_by: String,
}

/// Local forge effect receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalEffectOut {
    /// Target ref.
    pub ref_name: String,
    /// Expected old OID (all zeros = create).
    pub old_oid: String,
    /// New OID.
    pub new_oid: String,
    /// True only after the independent read-back matched.
    pub read_back_verified: bool,
    /// Settled effect state.
    pub state: String,
}

/// Jeryu probe line: an honest typed observation, never painted green.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JeryuOut {
    /// Typed status (e.g. `FORGE_UNAUTHENTICATED`).
    pub status: String,
    /// Whether an operator token was present.
    pub authenticated: bool,
    /// Operator-facing note.
    pub note: String,
}

/// Effect-phase receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectOut {
    /// Local bare forge delivery.
    pub local: Option<LocalEffectOut>,
    /// Jeryu observation.
    pub jeryu: Option<JeryuOut>,
}

/// One provider invocation's usage row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRow {
    /// Provider label.
    pub provider: String,
    /// Role in the run.
    pub role: String,
    /// Provider-native session id.
    pub session: Option<String>,
    /// Reported spend; `None` is honest not-reported.
    pub cost_usd: Option<f64>,
    /// Wall time.
    pub wall_ms: u64,
}

/// The operator-visible synthetic integration receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyntheticIntegrationReceipt {
    /// Stable non-production classification.
    pub classification: String,
    /// Always false; only a signed `GateReceiptV1` may satisfy a transaction gate.
    pub transaction_gate_eligible: bool,
    /// Runner provider.
    pub provider: String,
    /// Mission id.
    pub mission_id: Option<String>,
    /// Plan canonical hash.
    pub plan_hash: Option<String>,
    /// Fused plan digest.
    pub fused_plan_digest: Option<String>,
    /// Whether replaying materialization returned the same graph.
    pub mission_materialized_once: bool,
    /// Fence of the first incarnation.
    pub fence_first: Option<u64>,
    /// Fence of the runner incarnation.
    pub fence_second: Option<u64>,
    /// Whether the stale heartbeat and stale token were refused by the ledger.
    pub stale_refused: bool,
    /// First (superseded) attempt.
    pub attempt_first_id: Option<String>,
    /// Runner attempt.
    pub attempt_second_id: Option<String>,
    /// Planning council receipt.
    pub planning: Option<PlanningReceipt>,
    /// Exact candidate.
    pub candidate: Option<CandidateOut>,
    /// Writer gate.
    pub gate: Option<GateOut>,
    /// Independent evidence.
    pub evidence: Option<EvidenceOut>,
    /// Effects.
    pub effect: EffectOut,
    /// Per-provider usage.
    pub provider_usage: Vec<UsageRow>,
    /// Failed local scaffold checks. Empty is not transaction proof.
    pub scaffold_failures: Vec<String>,
}

fn is_full_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn candidate_failures(candidate: &CandidateOut, failures: &mut Vec<String>) {
    if !is_full_sha(&candidate.base)
        || !is_full_sha(&candidate.head)
        || !is_full_sha(&candidate.tree)
    {
        failures.push("CANDIDATE_SHA_INVALID".into());
    }
    if candidate.head == candidate.base {
        failures.push("CANDIDATE_HEAD_EQUALS_BASE".into());
    }
    if candidate.patch_digest.len() != 64 {
        failures.push("CANDIDATE_PATCH_DIGEST_INVALID".into());
    }
    if candidate.actual_scope != vec!["PONG.txt".to_string()] {
        failures.push("CANDIDATE_SCOPE_VIOLATION".into());
    }
}

/// The REQUIRED-step and honesty checks. Any entry fails the run.
#[must_use]
pub fn compute_scaffold_failures(receipt: &SyntheticIntegrationReceipt) -> Vec<String> {
    let mut failures = Vec::new();
    let classification_ok = receipt.classification == "SYNTHETIC_INTEGRATION_SCAFFOLD";
    if !classification_ok || receipt.transaction_gate_eligible {
        failures.push("SYNTHETIC_CLASSIFICATION_INVALID".into());
    }
    if receipt.mission_id.is_none() {
        failures.push("MATERIALIZE_MISSING".into());
    } else if !receipt.mission_materialized_once {
        failures.push("MATERIALIZE_NOT_IDEMPOTENT".into());
    }
    match (receipt.fence_first, receipt.fence_second) {
        (Some(first), Some(second)) if second == first + 1 => {}
        (Some(_), Some(_)) => failures.push("FENCE_NOT_INCREMENTED".into()),
        _ => failures.push("FENCE_CYCLE_MISSING".into()),
    }
    if !receipt.stale_refused {
        failures.push("STALE_NOT_REFUSED".into());
    }
    if receipt.planning.is_none() {
        failures.push("PLANNING_MISSING".into());
    }
    match &receipt.candidate {
        None => failures.push("CANDIDATE_MISSING".into()),
        Some(candidate) => candidate_failures(candidate, &mut failures),
    }
    match &receipt.gate {
        None => failures.push("WRITER_GATE_MISSING".into()),
        Some(gate) if gate.writer_outcome != "PASS" => {
            failures.push("WRITER_GATE_NOT_PASS".into());
        }
        Some(_) => {}
    }
    match &receipt.evidence {
        None => failures.push("EVIDENCE_MISSING".into()),
        Some(evidence) => {
            if evidence.verifier_outcome != "PASS" {
                failures.push("VERIFIER_NOT_PASS".into());
            }
            if evidence.tier != "E2" {
                failures.push("VERIFIER_NOT_E2".into());
            }
        }
    }
    match &receipt.effect.local {
        None => failures.push("LOCAL_EFFECT_MISSING".into()),
        Some(local) => {
            if !local.read_back_verified {
                failures.push("EFFECT_READ_BACK_UNVERIFIED".into());
            }
            if local.state != "COMMITTED" {
                failures.push(format!("EFFECT_NOT_COMMITTED:{}", local.state));
            }
        }
    }
    if receipt.effect.jeryu.is_none() {
        failures.push("JERYU_PROBE_MISSING".into());
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> SyntheticIntegrationReceipt {
        SyntheticIntegrationReceipt {
            classification: "SYNTHETIC_INTEGRATION_SCAFFOLD".into(),
            transaction_gate_eligible: false,
            provider: "sim".into(),
            mission_id: Some("mis_x".into()),
            plan_hash: Some("h".into()),
            fused_plan_digest: Some("d".repeat(64)),
            mission_materialized_once: true,
            fence_first: Some(1),
            fence_second: Some(2),
            stale_refused: true,
            attempt_first_id: Some("atm_a".into()),
            attempt_second_id: Some("atm_b".into()),
            planning: Some(PlanningReceipt {
                providers: vec![],
                fused_by: "sim".into(),
                mode: "FUSED".into(),
                provenance: BTreeMap::new(),
                degraded: false,
                failures: vec![],
            }),
            candidate: Some(CandidateOut {
                id: "can_x".into(),
                base: "a".repeat(40),
                head: "b".repeat(40),
                tree: "c".repeat(40),
                patch_digest: "d".repeat(64),
                actual_scope: vec!["PONG.txt".into()],
            }),
            gate: Some(GateOut {
                writer_outcome: "PASS".into(),
                gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.into()],
                argv: vec![vec![
                    "/usr/bin/grep".into(),
                    "-qx".into(),
                    "PONG".into(),
                    "PONG.txt".into(),
                ]],
                exit_codes: vec![Some(0)],
                repair_rounds: 0,
            }),
            evidence: Some(EvidenceOut {
                verifier_outcome: "PASS".into(),
                tier: "E2".into(),
                gate: "/usr/bin/grep -qx PONG PONG.txt".into(),
                produced_by: "bullet-verifier".into(),
            }),
            effect: EffectOut {
                local: Some(LocalEffectOut {
                    ref_name: "refs/heads/bullet/candidate/can_x".into(),
                    old_oid: "0".repeat(40),
                    new_oid: "b".repeat(40),
                    read_back_verified: true,
                    state: "COMMITTED".into(),
                }),
                jeryu: Some(JeryuOut {
                    status: "FORGE_UNAUTHENTICATED".into(),
                    authenticated: false,
                    note: "blocked on operator re-auth".into(),
                }),
            },
            provider_usage: vec![],
            scaffold_failures: vec![],
        }
    }

    #[test]
    fn a_complete_receipt_has_no_failures() {
        assert!(compute_scaffold_failures(&good()).is_empty());
    }

    #[test]
    fn every_required_step_is_checked() {
        let mut fence = good();
        fence.fence_second = Some(5);
        assert!(compute_scaffold_failures(&fence).contains(&"FENCE_NOT_INCREMENTED".to_string()));

        let mut stale = good();
        stale.stale_refused = false;
        assert!(compute_scaffold_failures(&stale).contains(&"STALE_NOT_REFUSED".to_string()));

        let mut verifier = good();
        verifier.evidence = Some(EvidenceOut {
            verifier_outcome: "NOT_RUN".into(),
            tier: "E2".into(),
            gate: "g".into(),
            produced_by: "v".into(),
        });
        assert!(compute_scaffold_failures(&verifier).contains(&"VERIFIER_NOT_PASS".to_string()));

        let mut effect = good();
        effect.effect.local = None;
        assert!(compute_scaffold_failures(&effect).contains(&"LOCAL_EFFECT_MISSING".to_string()));

        let mut scope = good();
        if let Some(candidate) = scope.candidate.as_mut() {
            candidate.actual_scope = vec!["PONG.txt".into(), "other.txt".into()];
        }
        assert!(
            compute_scaffold_failures(&scope).contains(&"CANDIDATE_SCOPE_VIOLATION".to_string())
        );

        let mut missing = good();
        missing.candidate = None;
        missing.gate = None;
        let failures = compute_scaffold_failures(&missing);
        assert!(failures.contains(&"CANDIDATE_MISSING".to_string()));
        assert!(failures.contains(&"WRITER_GATE_MISSING".to_string()));
    }

    #[test]
    fn a_degraded_council_is_honest_not_failing() {
        let mut degraded = good();
        if let Some(planning) = degraded.planning.as_mut() {
            planning.degraded = true;
            planning.failures = vec!["PLANNER_FAILED:B:codex".into()];
        }
        assert!(compute_scaffold_failures(&degraded).is_empty());

        let mut mislabeled = good();
        mislabeled.transaction_gate_eligible = true;
        assert!(compute_scaffold_failures(&mislabeled)
            .contains(&"SYNTHETIC_CLASSIFICATION_INVALID".to_string()));
    }
}
