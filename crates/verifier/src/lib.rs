//! Independent verification plane (spec section 22): a clean hostile-env
//! reconstruction of the exact Candidate, typed gate outcomes, and custody
//! rules under which writer evidence can never satisfy an independent
//! requirement.

pub mod error;
pub mod evidence;
pub mod gate;
pub mod request;
pub mod run;
pub mod safe_git;
pub mod workspace;

pub use bullet_domain::{EvidenceTier, GateId, GateOutcome, REASON_ZERO_TESTS};
pub use error::VerifierError;
pub use evidence::{
    independent_requirement_satisfied, invalidate_on_subject_change, CandidateSubject,
    CustodyRecord, EvidenceCustody, VerifierEvidence,
};
pub use gate::GateRun;
pub use request::VerifierRequest;
pub use run::execute;
pub use safe_git::HostileGit;
pub use workspace::{cleanup_workspace, CleanWorkspace, PreservationReceipt};
