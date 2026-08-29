//! Client for the `bullet-gitd` workspace daemon (line-delimited JSON over
//! stdio; protocol in bullet-git/docs/architecture.md). The daemon is the
//! sole writer of the private clone; it pins attempt/fence/nonce from the
//! initial clone token and refuses every stale call.

mod binary;
mod candidate;
mod records;
mod session;
mod workspace_binding;

pub use binary::{gitd_binary, gitd_fixture_binary, AdmittedGitdBinary};
pub use records::{
    ApplyProposalReceipt, CandidateProvenanceRequest, CandidateReceipt, ChangeRequest,
    CheckpointBinding, PrepareCandidateRequest, PreservationReceipt, SuccessorResume,
    WorkspaceInfo,
};
pub use session::GitdSession;
pub use workspace_binding::{
    ActiveGenerationBinding, GenerationCheckpointBinding, GenerationParentBinding,
};
pub(crate) use workspace_binding::{WorkspaceGenerationGuard, WorkspaceRootGuard};

#[cfg(test)]
mod protocol_tests;
