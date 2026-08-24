//! E3: independent evidence on the exact Candidate. Writer PASS is not enough.

use crate::gate::GateOutcome;
use crate::subject::{CandidateSubject, EvidenceCustody, EvidenceRecord};

/// Decide whether E3 is satisfied for `required`.
#[must_use]
pub fn e3_satisfied(required: &CandidateSubject, records: &[EvidenceRecord]) -> bool {
    records.iter().any(|record| {
        record.custody == EvidenceCustody::Independent
            && record.tier == "E3"
            && record.subject == *required
            && record.outcome == GateOutcome::Pass
    })
}

/// Invalidate records whose subject is no longer the live Candidate.
#[must_use]
pub fn invalidate_on_subject_change(
    live: &CandidateSubject,
    records: &[EvidenceRecord],
) -> Vec<EvidenceRecord> {
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

    fn sha(label: u8) -> CandidateSubject {
        CandidateSubject::new(format!("{label:x}").repeat(40))
    }

    fn rec(
        subject: CandidateSubject,
        custody: EvidenceCustody,
        outcome: GateOutcome,
    ) -> EvidenceRecord {
        EvidenceRecord {
            subject,
            custody,
            tier: "E3".into(),
            gate: "bullet-farm/proof-complete".into(),
            outcome,
        }
    }

    #[test]
    fn writer_pass_does_not_satisfy_e3() {
        let live = sha(0xb);
        let writer = rec(live.clone(), EvidenceCustody::Writer, GateOutcome::Pass);
        assert!(!e3_satisfied(&live, &[writer]));
    }

    #[test]
    fn independent_pass_on_other_sha_does_not_satisfy() {
        let live = sha(0xb);
        let other = rec(sha(0xa), EvidenceCustody::Independent, GateOutcome::Pass);
        assert!(!e3_satisfied(&live, &[other]));
    }

    #[test]
    fn independent_pass_on_live_sha_satisfies() {
        let live = sha(0xb);
        let ok = rec(
            live.clone(),
            EvidenceCustody::Independent,
            GateOutcome::Pass,
        );
        assert!(e3_satisfied(&live, &[ok]));
    }

    #[test]
    fn subject_change_invalidates() {
        let old = sha(0xa);
        let live = sha(0xb);
        let prior = rec(old, EvidenceCustody::Independent, GateOutcome::Pass);
        let next = invalidate_on_subject_change(&live, &[prior]);
        assert_eq!(next[0].outcome, GateOutcome::Invalidated);
        assert!(!e3_satisfied(&live, &next));
    }
}
