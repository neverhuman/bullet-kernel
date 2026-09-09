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

    async fn cleanup(
        &mut self,
        receipt: &PreservationReceipt,
        deleted_at: &str,
    ) -> Result<(), RunnerError>;
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

    async fn cleanup(
        &mut self,
        receipt: &PreservationReceipt,
        deleted_at: &str,
    ) -> Result<(), RunnerError> {
        let response = GitdSession::cleanup(self, receipt, deleted_at).await?;
        let verified = response
            .get("verified")
            .and_then(serde_json::Value::as_bool);
        let digest = response
            .get("preservation_receipt_digest")
            .and_then(serde_json::Value::as_str);
        let tombstone = response
            .get("tombstone")
            .and_then(serde_json::Value::as_str)
            .map(Path::new);
        if response.as_object().map(serde_json::Map::len) != Some(3)
            || verified != Some(true)
            || digest != Some(receipt.digest.as_str())
            || !tombstone.is_some_and(Path::is_file)
        {
            return Err(RunnerError::Protocol(
                "cleanup response does not bind the sealed preservation receipt".into(),
            ));
        }
        Ok(())
    }
}
