//! Private workspace port; production has exactly one implementation.

use crate::error::RunnerError;
use crate::gitd::{
    ApplyProposalReceipt, CandidateReceipt, CheckpointBinding, GitdSession,
    PrepareCandidateRequest, PreservationReceipt,
};
use bullet_harness_core::PatchProposal;
use std::path::Path;

#[async_trait::async_trait]
pub(super) trait WorkspaceSession: Send {
    async fn apply_proposal(
        &mut self,
        proposal: &PatchProposal,
    ) -> Result<ApplyProposalReceipt, RunnerError>;

    async fn checkpoint(&mut self) -> Result<CheckpointBinding, RunnerError>;

    async fn prepare_candidate(
        &mut self,
        request: &PrepareCandidateRequest,
    ) -> Result<CandidateReceipt, RunnerError>;

    async fn preserve(&mut self, destination: &Path) -> Result<PreservationReceipt, RunnerError>;
}

#[async_trait::async_trait]
impl WorkspaceSession for GitdSession {
    async fn apply_proposal(
        &mut self,
        proposal: &PatchProposal,
    ) -> Result<ApplyProposalReceipt, RunnerError> {
        GitdSession::apply_proposal(self, proposal).await
    }

    async fn checkpoint(&mut self) -> Result<CheckpointBinding, RunnerError> {
        GitdSession::checkpoint(self).await
    }

    async fn prepare_candidate(
        &mut self,
        request: &PrepareCandidateRequest,
    ) -> Result<CandidateReceipt, RunnerError> {
        GitdSession::prepare_candidate(self, request).await
    }

    async fn preserve(&mut self, destination: &Path) -> Result<PreservationReceipt, RunnerError> {
        GitdSession::preserve(self, destination).await
    }
}
