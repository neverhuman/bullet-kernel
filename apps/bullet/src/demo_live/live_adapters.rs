//! Live provider adapter selection for the admitted `demo-live` path, plus
//! the spend-cap wrapper (ADR 0001). Selection here grants nothing: every
//! spawn is still checked by the harness-core live-admission gate and
//! refuses with `LIVE_ADMISSION_UNAVAILABLE` without the operator token.

use bullet_harness_core::{
    Ack, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter, HarnessDescriptor,
    HarnessEventStream, HarnessResult, ModelSnapshot, PermissionDecision, PlanDecision,
    ProbeResult, ProfileRef, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle,
    StartSession, SteeringMessage, Turn, TurnHandle,
};
use std::sync::Arc;

/// Per-invocation budget cap in USD (ADR 0001 live-spend rule).
pub const TURN_BUDGET_USD: f64 = 1.0;

/// Resolve one provider label to its adapter, wrapped with the budget cap.
#[must_use]
pub fn adapter_for(provider: &str) -> Option<Arc<dyn HarnessAdapter>> {
    let inner: Arc<dyn HarnessAdapter> = match provider {
        "sim" => Arc::new(bullet_harness_sim::SimAdapter::new()),
        "claude" => Arc::new(bullet_harness_claude::ClaudeAdapter::new()),
        "codex" => Arc::new(bullet_harness_codex::CodexAdapter::new()),
        "cursor" => Arc::new(bullet_harness_cursor::CursorAdapter::new()),
        _ => return None,
    };
    Some(Arc::new(CappedAdapter::new(inner, TURN_BUDGET_USD)))
}

/// Wrapper injecting the spend cap into every session start unless the
/// caller already set one. Providers without a budget flag ignore it.
pub struct CappedAdapter {
    inner: Arc<dyn HarnessAdapter>,
    max_budget_usd: f64,
}

impl CappedAdapter {
    /// Wrap an adapter with a per-invocation budget cap.
    #[must_use]
    pub fn new(inner: Arc<dyn HarnessAdapter>, max_budget_usd: f64) -> Self {
        Self {
            inner,
            max_budget_usd,
        }
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for CappedAdapter {
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

    async fn start(&self, mut request: StartSession) -> HarnessResult<SessionHandle> {
        if request.max_budget_usd.is_none() {
            request.max_budget_usd = Some(self.max_budget_usd);
        }
        self.inner.start(request).await
    }

    async fn resume(&self, mut request: ResumeSession) -> HarnessResult<SessionHandle> {
        if request.max_budget_usd.is_none() {
            request.max_budget_usd = Some(self.max_budget_usd);
        }
        self.inner.resume(request).await
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
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
        self.inner.terminate(session).await
    }

    fn events(&self, session: &SessionHandle) -> HarnessEventStream {
        self.inner.events(session)
    }
}
