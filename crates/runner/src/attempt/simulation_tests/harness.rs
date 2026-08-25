//! Scripted provider wrapper available only to the private test simulator.

use bullet_harness_core::{
    Ack, AgentEventKind, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter,
    HarnessDescriptor, HarnessError, HarnessEventStream, HarnessResult, ModelSnapshot,
    PermissionDecision, PlanDecision, ProbeResult, ProfileRef, QuotaObservation, ResumeSession,
    SessionCheckpoint, SessionHandle, StartSession, SteeringMessage, Turn, TurnHandle,
};
use bullet_harness_sim::SimAdapter;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub(super) struct ScriptedSim {
    inner: SimAdapter,
    overrides: Mutex<HashMap<usize, Value>>,
    prompts: Mutex<Vec<String>>,
    send_delay: Mutex<Option<Duration>>,
    start_failure: Mutex<Option<String>>,
    terminated: AtomicBool,
}

impl ScriptedSim {
    pub(super) fn new() -> Self {
        Self {
            inner: SimAdapter::new(),
            overrides: Mutex::new(HashMap::new()),
            prompts: Mutex::new(Vec::new()),
            send_delay: Mutex::new(None),
            start_failure: Mutex::new(None),
            terminated: AtomicBool::new(false),
        }
    }

    pub(super) fn override_proposal(&self, turn: usize, proposal: Value) {
        self.overrides
            .lock()
            .expect("overrides")
            .insert(turn, proposal);
    }

    pub(super) fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompts").clone()
    }

    pub(super) fn delay_send(&self, delay: Duration) {
        *self.send_delay.lock().expect("send delay") = Some(delay);
    }

    pub(super) fn fail_start(&self, reason: &str) {
        *self.start_failure.lock().expect("start failure") = Some(reason.to_string());
    }

    pub(super) fn was_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for ScriptedSim {
    fn descriptor(&self) -> HarnessDescriptor {
        self.inner.descriptor()
    }

    async fn probe(&self, profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        self.inner.probe(profile).await
    }

    async fn list_models(&self, profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>> {
        self.inner.list_models(profile).await
    }

    async fn observe_quota(&self, profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>> {
        self.inner.observe_quota(profile).await
    }

    async fn begin_login(&self, profile: &ProfileRef) -> HarnessResult<AuthChallenge> {
        self.inner.begin_login(profile).await
    }

    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle> {
        if let Some(reason) = self.start_failure.lock().expect("start failure").clone() {
            return Err(HarnessError::Protocol {
                provider: "test-simulator".into(),
                reason,
            });
        }
        self.inner.start(request).await
    }

    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        self.inner.resume(request).await
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        self.prompts
            .lock()
            .expect("prompts")
            .push(turn.prompt.clone());
        let delay = *self.send_delay.lock().expect("send delay");
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.inner.send(session, turn).await
    }

    async fn steer(&self, session: &SessionHandle, message: SteeringMessage) -> HarnessResult<Ack> {
        self.inner.steer(session, message).await
    }

    async fn approve_local_plan(
        &self,
        session: &SessionHandle,
        decision: PlanDecision,
    ) -> HarnessResult<Ack> {
        self.inner.approve_local_plan(session, decision).await
    }

    async fn respond_permission(
        &self,
        session: &SessionHandle,
        decision: PermissionDecision,
    ) -> HarnessResult<Ack> {
        self.inner.respond_permission(session, decision).await
    }

    async fn compact(
        &self,
        session: &SessionHandle,
        request: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        self.inner.compact(session, request).await
    }

    async fn checkpoint(&self, session: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        self.inner.checkpoint(session).await
    }

    async fn interrupt(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        self.inner.interrupt(session).await
    }

    async fn terminate(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        let result = self.inner.terminate(session).await;
        if result.is_ok() {
            self.terminated.store(true, Ordering::SeqCst);
        }
        result
    }

    fn events(&self, session: &SessionHandle) -> HarnessEventStream {
        let overrides = self.overrides.lock().expect("overrides").clone();
        Box::pin(
            self.inner
                .events(session)
                .scan(0usize, move |completed, mut event| {
                    if event.kind == AgentEventKind::TurnCompleted {
                        if let Some(proposal) = overrides.get(completed) {
                            let mut proposal = proposal.clone();
                            for field in [
                                "schema_version",
                                "proposal_id",
                                "producing_attempt_id",
                                "base_checkpoint_id",
                                "base_checkpoint_digest",
                            ] {
                                proposal[field] = event.payload["proposal"][field].clone();
                            }
                            event.payload["proposal"] = proposal;
                        }
                        *completed += 1;
                    }
                    futures::future::ready(Some(event))
                }),
        )
    }
}
