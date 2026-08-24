//! Private workspace port; production has exactly one implementation.

use crate::error::RunnerError;
use crate::gitd::{CandidateReceipt, GitdSession};
use bullet_harness_core::FileChange;
use serde_json::Value;

#[async_trait::async_trait]
pub(super) trait WorkspaceSession: Send {
    async fn apply_change(&mut self, changes: &[FileChange]) -> Result<u64, RunnerError>;

    async fn checkpoint(&mut self) -> Result<Value, RunnerError>;

    async fn prepare_candidate(
        &mut self,
        change_seed: &str,
        mission: &str,
    ) -> Result<CandidateReceipt, RunnerError>;
}

#[async_trait::async_trait]
impl WorkspaceSession for GitdSession {
    async fn apply_change(&mut self, changes: &[FileChange]) -> Result<u64, RunnerError> {
        GitdSession::apply_change(self, changes).await
    }

    async fn checkpoint(&mut self) -> Result<Value, RunnerError> {
        GitdSession::checkpoint(self).await
    }

    async fn prepare_candidate(
        &mut self,
        change_seed: &str,
        mission: &str,
    ) -> Result<CandidateReceipt, RunnerError> {
        GitdSession::prepare_candidate(self, change_seed, mission).await
    }
}
