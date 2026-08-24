//! Independent verification plane. Writer evidence cannot satisfy this crate.

pub mod e3;
pub mod gate;
pub mod subject;

pub use e3::{e3_satisfied, invalidate_on_subject_change};
pub use gate::GateOutcome;
pub use subject::{
    cleanup_workspace, CandidateSubject, CleanWorkspace, EvidenceCustody, EvidenceRecord,
    PreservationReceipt,
};
