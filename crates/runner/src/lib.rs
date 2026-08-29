//! Attempt runner loop: lease, private clone via bullet-gitd, provider
//! session, scope check, apply, gate, candidate (ADR 0001: providers run
//! read-only; the kernel applies `PatchProposal`s through the workspace
//! daemon, the sole writer).

pub mod attempt;
pub mod candidate_authority;
pub mod capsule;
pub mod clock;
pub mod error;
pub mod gate;
pub mod gitd;
pub mod heartbeat;
pub mod http;
pub mod http_lease;
pub mod journal;
mod kernel_authority;
pub mod lease;
pub mod scope;
#[cfg(feature = "test-seams")]
pub mod signed_lease;
pub mod signed_lease_rpc;

pub use attempt::{run_attempt, AttemptConfig, AttemptOutcome, CandidatePreservation};
pub use candidate_authority::CandidatePreparationAdmission;
pub use capsule::Capsule;
pub use clock::{Clock, ManualClock, MonotonicClock, SelfKillDeadline};
pub use error::RunnerError;
pub use gate::{run_gate, GateRegistry, GateReport, REPOSITORY_GATE_ID};
pub use gitd::{
    gitd_binary, gitd_fixture_binary, AdmittedGitdBinary, CandidateProvenanceRequest,
    CandidateReceipt, ChangeRequest, GitdSession, PrepareCandidateRequest, PreservationReceipt,
    SuccessorResume, WorkspaceInfo,
};
pub use heartbeat::{start_heartbeat, FreezeReason, HeartbeatConfig, HeartbeatHandle};
pub use http::HttpJson;
pub use http_lease::HttpLeaseClient;
pub use journal::{JournalSink, MemoryJournal};
pub use lease::{
    AcquireGrant, AcquireRequest, DirectLeaseClient, HeartbeatCall, LeaseClient, ReadyView,
    ReleaseCall,
};
#[cfg(feature = "test-seams")]
pub use signed_lease::SignedLeaseClient;
pub use signed_lease_rpc::{
    CandidatePreparationGrant, CandidatePreparationRpcClient, ExpectedLeaseServer,
    SignedLeaseRpcClient,
};
