//! Typed evidence emitted by the clean-room verifier, plus custody rules:
//! writer evidence can never satisfy an independent requirement, and
//! evidence whose subject changed is invalidated.

use bullet_domain::{EvidenceTier, GateId, GateOutcome};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact Candidate identity a gate ran against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSubject {
    /// Base commit SHA.
    pub base_sha: String,
    /// Head commit SHA.
    pub head_sha: String,
    /// Tree SHA.
    pub tree_sha: String,
}

/// Custody of an evidence record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCustody {
    /// Produced inside the writer Attempt.
    Writer,
    /// Produced by a clean independent reconstruction.
    Independent,
}

/// The record the verifier binary emits on stdout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierEvidence {
    /// Trust tier. The clean-room verifier produces `E2`.
    pub tier: EvidenceTier,
    /// Exact Kernel-catalog gate.
    pub gate_id: GateId,
    /// Typed outcome. Only `PASS` satisfies a requirement.
    pub outcome: GateOutcome,
    /// Stable reason code refining the outcome, e.g. `ZERO_TESTS`.
    pub reason: Option<String>,
    /// Human-oriented detail for operators; never parsed by machines.
    pub detail: Option<String>,
    /// Exact catalog-owned executable and arguments.
    pub argv: Vec<String>,
    /// Catalog-owned wall-clock timeout.
    pub timeout_secs: u64,
    /// Gate exit code, when the gate produced one.
    pub exit_code: Option<i32>,
    /// Wall time of the whole reconstruction and gate run.
    pub duration_ms: u64,
    /// Exact subject.
    pub subject: CandidateSubject,
    /// Best-effort environment manifest (`rustc`, `git`).
    pub environment: BTreeMap<String, String>,
    /// Producer identity.
    pub produced_by: String,
    /// Attempt that authored the Candidate.
    pub author_attempt_id: String,
}

/// One custody-annotated evidence claim used for requirement checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    /// Exact subject.
    pub subject: CandidateSubject,
    /// Who produced it.
    pub custody: EvidenceCustody,
    /// Trust tier.
    pub tier: EvidenceTier,
    /// Gate label.
    pub gate: String,
    /// Typed outcome.
    pub outcome: GateOutcome,
}

/// Whether an independent requirement at `floor` is satisfied for
/// `required`: an independent record on the exact subject, at or above the
/// tier floor, with a typed `PASS`. Writer custody never satisfies.
#[must_use]
pub fn independent_requirement_satisfied(
    required: &CandidateSubject,
    floor: EvidenceTier,
    records: &[CustodyRecord],
) -> bool {
    records.iter().any(|record| {
        record.custody == EvidenceCustody::Independent
            && record.tier >= floor
            && record.subject == *required
            && record.outcome.satisfies_requirement()
    })
}

/// Invalidate records whose subject is no longer the live Candidate.
#[must_use]
pub fn invalidate_on_subject_change(
    live: &CandidateSubject,
    records: &[CustodyRecord],
) -> Vec<CustodyRecord> {
    records
        .iter()
        .map(|record| {
            if record.subject == *live {
                record.clone()
            } else {
                let mut next = record.clone();
                next.outcome = GateOutcome::Invalidated;
                next
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(label: char) -> CandidateSubject {
        CandidateSubject {
            base_sha: "a".repeat(40),
            head_sha: label.to_string().repeat(40),
            tree_sha: "c".repeat(40),
        }
    }

    fn rec(
        subject: CandidateSubject,
        custody: EvidenceCustody,
        tier: EvidenceTier,
        outcome: GateOutcome,
    ) -> CustodyRecord {
        CustodyRecord {
            subject,
            custody,
            tier,
            gate: "bullet-farm/proof-complete".into(),
            outcome,
        }
    }

    #[test]
    fn writer_pass_never_satisfies_independent_requirement() {
        let live = subject('b');
        let writer = rec(
            live.clone(),
            EvidenceCustody::Writer,
            EvidenceTier::E2,
            GateOutcome::Pass,
        );
        assert!(!independent_requirement_satisfied(
            &live,
            EvidenceTier::E2,
            &[writer]
        ));
    }

    #[test]
    fn independent_pass_below_floor_or_off_subject_does_not_satisfy() {
        let live = subject('b');
        let low = rec(
            live.clone(),
            EvidenceCustody::Independent,
            EvidenceTier::E1,
            GateOutcome::Pass,
        );
        let off = rec(
            subject('d'),
            EvidenceCustody::Independent,
            EvidenceTier::E2,
            GateOutcome::Pass,
        );
        assert!(!independent_requirement_satisfied(
            &live,
            EvidenceTier::E2,
            &[low, off]
        ));
    }

    #[test]
    fn exact_subject_independent_pass_satisfies() {
        let live = subject('b');
        let ok = rec(
            live.clone(),
            EvidenceCustody::Independent,
            EvidenceTier::E2,
            GateOutcome::Pass,
        );
        assert!(independent_requirement_satisfied(
            &live,
            EvidenceTier::E2,
            &[ok]
        ));
    }

    #[test]
    fn subject_change_invalidates_prior_pass() {
        let old = subject('d');
        let live = subject('b');
        let prior = rec(
            old,
            EvidenceCustody::Independent,
            EvidenceTier::E2,
            GateOutcome::Pass,
        );
        let next = invalidate_on_subject_change(&live, &[prior]);
        assert_eq!(next[0].outcome, GateOutcome::Invalidated);
        assert!(!independent_requirement_satisfied(
            &live,
            EvidenceTier::E2,
            &next
        ));
    }
}
