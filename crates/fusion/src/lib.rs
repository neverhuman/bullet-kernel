//! Offline, non-gating struggle and fusion scaffold. No runtime consumes its
//! output as authority, and no caller-supplied score participates in selection.

use bullet_domain::Digest;
use serde::{Deserialize, Serialize};

/// One independent cognitive artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Producer lane.
    pub provider: String,
    /// Canonical body digest.
    pub digest: String,
}

/// Progress facts used to compute struggle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Failed attempts on this package.
    pub failures: u32,
    /// Distinct artifact hashes seen.
    pub unique_hashes: u32,
    /// Turns since last meaningful progress.
    pub stalled_turns: u32,
}

/// Escalation decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Escalation {
    /// From lane.
    pub from_provider: String,
    /// To lane.
    pub to_provider: String,
    /// Struggle score that triggered it.
    pub score: u8,
    /// Always false while this remains disconnected scaffolding.
    pub transaction_gate_eligible: bool,
}

/// Fusion of independent artifacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionResult {
    /// Protocol used.
    pub protocol: String,
    /// Winning artifact.
    pub selected: Artifact,
    /// New variant id the winner must land on.
    pub new_variant_id: String,
    /// Selection is synthetic and cannot satisfy a transaction gate.
    pub transaction_gate_eligible: bool,
}

/// Struggle in 0..=100. Identical failures raise the score; new hashes lower it.
#[must_use]
pub fn struggle_score(progress: &Progress) -> u8 {
    let repeat = progress.failures.saturating_sub(progress.unique_hashes);
    let raw = progress.failures.saturating_mul(12)
        + progress.stalled_turns.saturating_mul(8)
        + repeat.saturating_mul(16);
    u8::try_from(raw.min(100)).unwrap_or(100)
}

/// Escalate after a hard floor. Thrash limit is 3 escalations (caller counts).
#[must_use]
pub fn escalate(progress: &Progress, from_provider: &str, already: u32) -> Option<Escalation> {
    if already >= 3 {
        return None;
    }
    let score = struggle_score(progress);
    if score < 40 {
        return None;
    }
    let to_provider = match from_provider {
        "t0" => "offline-challenger-a",
        "offline-challenger-a" => "offline-challenger-b",
        _ => "t0",
    };
    Some(Escalation {
        from_provider: from_provider.to_string(),
        to_provider: to_provider.to_string(),
        score,
        transaction_gate_eligible: false,
    })
}

/// Deterministic synthetic selection. Digest order is only a replay fixture;
/// it is not a quality score and cannot authorize applying the result.
#[must_use]
pub fn fuse(artifacts: &[Artifact], attempt_seed: &str) -> Option<FusionResult> {
    let selected = artifacts
        .iter()
        .min_by_key(|item| (&item.digest, &item.provider))?
        .clone();
    let new_variant_id = Digest::of(format!("fuse:{attempt_seed}:{}", selected.digest).as_bytes())
        .to_hex()[..16]
        .to_string();
    Some(FusionResult {
        protocol: "offline-digest-order-scaffold".into(),
        selected,
        new_variant_id,
        transaction_gate_eligible: false,
    })
}

/// Build an artifact from a body.
#[must_use]
pub fn artifact(provider: &str, body: &str) -> Artifact {
    Artifact {
        provider: provider.to_string(),
        digest: Digest::of(body.as_bytes()).to_hex(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_work_escalates_without_a_human() {
        let progress = Progress {
            failures: 4,
            unique_hashes: 1,
            stalled_turns: 3,
        };
        assert!(struggle_score(&progress) >= 40);
        let step = escalate(&progress, "t0", 0).expect("escalate");
        assert_eq!(step.to_provider, "offline-challenger-a");
        assert!(!step.transaction_gate_eligible);
        assert!(escalate(&progress, "t0", 3).is_none());
    }

    #[test]
    fn fusion_opens_a_new_variant() {
        let a = artifact("planner-a", "fn a() {}");
        let b = artifact("planner-b", "fn b() {}");
        let result = fuse(&[a.clone(), b.clone()], "att-1").expect("fuse");
        let expected = [&a, &b]
            .into_iter()
            .min_by_key(|item| (&item.digest, &item.provider))
            .expect("artifact");
        assert_eq!(&result.selected, expected);
        assert_ne!(result.new_variant_id, a.digest);
        assert!(!result.transaction_gate_eligible);
        let again = fuse(
            &[
                artifact("planner-a", "fn a() {}"),
                artifact("planner-b", "fn b() {}"),
            ],
            "att-1",
        );
        assert_eq!(again.unwrap().new_variant_id, result.new_variant_id);
    }
}
