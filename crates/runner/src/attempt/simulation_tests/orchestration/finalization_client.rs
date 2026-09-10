//! Release observation and response-loss injection at the real orchestration port.

use super::*;
use crate::signed_lease_rpc::CandidatePreparationRpcClient;

pub(super) struct ObservedClient {
    pub(super) inner: TestClient,
    pub(super) adapter: Arc<ScriptedSim>,
    pub(super) releases: Mutex<Vec<crate::ReleaseCall>>,
    pub(super) lose_release_response: bool,
}

#[async_trait::async_trait]
impl LeaseClient for ObservedClient {
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        self.inner.candidate_preparation_rpc()
    }

    async fn acquire(
        &self,
        request: &crate::AcquireRequest,
    ) -> Result<crate::AcquireGrant, crate::RunnerError> {
        self.inner.acquire(request).await
    }

    async fn heartbeat(&self, call: &crate::HeartbeatCall) -> Result<(), crate::RunnerError> {
        self.inner.heartbeat(call).await
    }

    async fn advance(&self, id: &AttemptId, state: AttemptState) -> Result<(), crate::RunnerError> {
        self.inner.advance(id, state).await
    }

    async fn release(&self, call: &crate::ReleaseCall) -> Result<(), crate::RunnerError> {
        assert!(
            self.adapter.was_terminated(),
            "release precedes termination acknowledgement"
        );
        self.releases
            .lock()
            .expect("release trace")
            .push(call.clone());
        self.inner.release(call).await?;
        if self.lose_release_response {
            return Err(crate::RunnerError::ReleaseOutcomeUnknown {
                message: "test response lost after commit".into(),
            });
        }
        Ok(())
    }

    async fn next_ready(&self) -> Result<Option<crate::ReadyView>, crate::RunnerError> {
        self.inner.next_ready().await
    }
}

pub(super) struct FailingJournal {
    pub(super) memory: MemoryJournal,
    pub(super) fail_stage: &'static str,
    pub(super) fail_recovery: bool,
}

impl JournalSink for FailingJournal {
    fn record(&self, stage: &str, detail: &str) {
        self.memory.record(stage, detail);
    }

    fn try_record(&self, stage: &str, detail: &str) -> Result<(), String> {
        if stage == self.fail_stage || (stage == "finalization_unresolved" && self.fail_recovery) {
            return Err(format!("injected durable journal failure: {stage}"));
        }
        self.memory.record(stage, detail);
        Ok(())
    }
}
