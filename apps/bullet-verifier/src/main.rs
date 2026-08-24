//! Independent verifier process. Writer evidence cannot satisfy this plane.

use bullet_verifier_core::{
    e3_satisfied, CandidateSubject, EvidenceCustody, EvidenceRecord, GateOutcome,
};

fn main() {
    let live = CandidateSubject::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let writer = EvidenceRecord {
        subject: live.clone(),
        custody: EvidenceCustody::Writer,
        tier: "E3".into(),
        gate: "bullet-farm/proof-complete".into(),
        outcome: GateOutcome::Pass,
    };
    let independent = EvidenceRecord {
        subject: live.clone(),
        custody: EvidenceCustody::Independent,
        tier: "E3".into(),
        gate: "bullet-farm/proof-complete".into(),
        outcome: GateOutcome::Pass,
    };
    let writer_only = e3_satisfied(&live, &[writer]);
    let both = e3_satisfied(&live, &[independent]);
    println!("bullet-verifier: writer_e3={writer_only} independent_e3={both}");
    if writer_only || !both {
        std::process::exit(1);
    }
}
