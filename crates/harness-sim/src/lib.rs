//! Deterministic provider simulator implementing `HarnessAdapter`
//! (spec s33.2). Driven by the in-code scenario table in [`scenario`];
//! the default CI lane runs the full conformance suite against this adapter.

pub mod scenario;
mod support;

use bullet_domain::Observation;
use bullet_harness_core::{
    synthetic_uuid, unsupported, Ack, AgentEventKind, ArtifactRef, AuthChallenge, CompactRequest,
    ContextTransition, EventNormalizer, HarnessAdapter, HarnessDescriptor, HarnessError,
    HarnessEventStream, HarnessResult, InvocationBudget, InvocationId, ModelSnapshot,
    PermissionDecision, PlanDecision, ProbeResult, ProfileIdentity, ProfileRef, PromotionStage,
    QuotaObservation, ResumeSession, SessionCheckpoint, SessionEntry, SessionHandle, SessionState,
    SessionStore, StartSession, SteeringMessage, Turn, TurnHandle,
};
use chrono::Utc;
use scenario::SimCondition;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use support::capabilities;

/// The simulator's own version string.
pub const SIM_VERSION: &str = "sim-1.0.0";

pub(crate) const PROVIDER: &str = "sim";

/// Deterministic simulator adapter.
pub struct SimAdapter {
    store: SessionStore,
    normalizers: Mutex<HashMap<String, EventNormalizer>>,
    natives: Mutex<HashMap<String, String>>,
    budget: InvocationBudget,
}

impl Default for SimAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SimAdapter {
    /// Fresh simulator with a generous invocation budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: SessionStore::new(),
            normalizers: Mutex::new(HashMap::new()),
            natives: Mutex::new(HashMap::new()),
            budget: InvocationBudget::new(256),
        }
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for SimAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: "bullet-sim".to_string(),
            version: Observation::value(SIM_VERSION.to_string()),
            stage: PromotionStage::ContractPass,
            capabilities: capabilities(),
        }
    }

    async fn probe(&self, _profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        Ok(ProbeResult {
            profile: Observation::value(ProfileIdentity {
                provider: PROVIDER.to_string(),
                email: Some("sim@bullet.farm".to_string()),
                account_id: Some("sim-account-1".to_string()),
                subscription: Some("sim".to_string()),
                auth_method: Some("static".to_string()),
            }),
            version: SIM_VERSION.to_string(),
        })
    }

    async fn list_models(&self, _profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>> {
        Ok(vec![ModelSnapshot {
            provider_model_id: "sim-economy".to_string(),
            display_name: "Sim Economy".to_string(),
            context_window: Some(200_000),
            observed_at: Utc::now(),
        }])
    }

    async fn observe_quota(&self, _profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>> {
        Ok(vec![QuotaObservation {
            dimension: "requests".to_string(),
            remaining: Observation::value("500".to_string()),
            source: "sim quota table".to_string(),
            observed_at: Utc::now(),
        }])
    }

    async fn begin_login(&self, _profile: &ProfileRef) -> HarnessResult<AuthChallenge> {
        Err(unsupported(PROVIDER, "begin_login"))
    }

    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle> {
        let session_id = request.session_id.as_str().to_string();
        let native = format!("sim-native-{session_id}");
        let handle = SessionHandle {
            session_id: request.session_id.clone(),
            provider: PROVIDER.to_string(),
            native_session_id: Some(native.clone()),
        };
        std::fs::create_dir_all(&request.artifact_dir).map_err(|err| HarnessError::Io {
            context: format!("artifact dir {}", request.artifact_dir.display()),
            reason: err.to_string(),
        })?;
        let artifact_path = request.artifact_dir.join(format!("{session_id}.raw.jsonl"));
        let mut entry = SessionEntry::new(handle.clone(), request.workdir, artifact_path.clone());
        for state in [
            SessionState::Starting,
            SessionState::IdentityProbing,
            SessionState::ContextLoading,
            SessionState::Ready,
        ] {
            entry.state = entry.state.transition(state)?;
        }
        entry.model.clone_from(&request.model);
        self.store.insert(entry);
        let mut normalizer = EventNormalizer::new(request.session_id, PROVIDER);
        normalizer.set_native_session(native.clone());
        if let Some(model) = request.model {
            normalizer.set_model(model);
        }
        normalizer.set_raw_artifact(ArtifactRef::new(artifact_path.display().to_string()));
        if let Ok(mut map) = self.normalizers.lock() {
            map.insert(session_id.clone(), normalizer);
        }
        if let Ok(mut map) = self.natives.lock() {
            map.insert(native, session_id.clone());
        }
        self.emit(
            &session_id,
            AgentEventKind::SessionStarted,
            json!({ "binary_version": SIM_VERSION }),
        )?;
        self.emit(
            &session_id,
            AgentEventKind::SessionIdentity,
            json!({ "email": "sim@bullet.farm" }),
        )?;
        self.emit(&session_id, AgentEventKind::SessionReady, json!({}))?;
        Ok(handle)
    }

    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        let session_id = {
            let map = self.natives.lock().map_err(|_| HarnessError::Io {
                context: "native map lock".into(),
                reason: "poisoned".into(),
            })?;
            map.get(&request.native_session_id).cloned()
        }
        .ok_or_else(|| HarnessError::SessionUnknown {
            session: request.native_session_id.clone(),
        })?;
        let handle = self.store.with_entry(&session_id, |e| e.handle.clone())?;
        self.emit(
            &session_id,
            AgentEventKind::SessionStarted,
            json!({ "resumed": true }),
        )?;
        Ok(handle)
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let session_id = session.session_id.as_str().to_string();
        self.budget.try_acquire()?;
        self.store.with_entry(&session_id, |e| e.invocations += 1)?;
        let invocation_id = InvocationId::new(synthetic_uuid("sim-invocation"));
        self.with_normalizer(&session_id, |n| n.set_invocation(invocation_id.clone()))?;
        let condition = SimCondition::from_prompt(&turn.prompt);
        if condition == SimCondition::LongTurn {
            return self.run_long_turn(&session_id, invocation_id).await;
        }
        self.ingest(&session_id, &scenario::script(condition, &turn.prompt))?;
        match condition {
            SimCondition::AuthExpiry => Err(HarnessError::AuthRequired {
                provider: PROVIDER.to_string(),
                reason: "token expired".to_string(),
            }),
            SimCondition::ProcessCrash => Err(HarnessError::ProviderFailure {
                provider: PROVIDER.to_string(),
                exit: Some(9),
                reason: "process crashed".to_string(),
            }),
            SimCondition::HttpErrors | SimCondition::ContextLimit => Ok(TurnHandle {
                invocation_id,
                exit_code: Some(1),
                timed_out: false,
            }),
            _ => Ok(TurnHandle {
                invocation_id,
                exit_code: Some(0),
                timed_out: false,
            }),
        }
    }

    async fn steer(&self, session: &SessionHandle, message: SteeringMessage) -> HarnessResult<Ack> {
        self.emit(
            session.session_id.as_str(),
            AgentEventKind::SteeringAcknowledged,
            json!({ "text": message.text }),
        )?;
        Ok(Ack { acknowledged: true })
    }

    async fn approve_local_plan(
        &self,
        session: &SessionHandle,
        decision: PlanDecision,
    ) -> HarnessResult<Ack> {
        self.close_waiting_turn(session.session_id.as_str(), decision.approved)
    }

    async fn respond_permission(
        &self,
        session: &SessionHandle,
        decision: PermissionDecision,
    ) -> HarnessResult<Ack> {
        self.close_waiting_turn(session.session_id.as_str(), decision.allow)
    }

    async fn compact(
        &self,
        session: &SessionHandle,
        _request: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        self.emit(
            session.session_id.as_str(),
            AgentEventKind::SessionCompacted,
            json!({ "dropped_tokens": 5000 }),
        )?;
        Ok(ContextTransition {
            summary: "compacted synthetic context".to_string(),
        })
    }

    async fn checkpoint(&self, session: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        let session_id = session.session_id.as_str();
        let checkpoint = self.store.with_entry(session_id, |e| SessionCheckpoint {
            session_id: e.handle.session_id.clone(),
            state: e.state,
            native_session_id: e.handle.native_session_id.clone(),
            event_count: e.events.len() as u64,
        })?;
        self.emit(session_id, AgentEventKind::CheckpointCompleted, json!({}))?;
        Ok(checkpoint)
    }

    async fn interrupt(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        let session_id = session.session_id.as_str();
        self.store
            .with_entry(session_id, |e| e.interrupted = true)?;
        self.emit(session_id, AgentEventKind::InterruptAcknowledged, json!({}))?;
        Ok(Ack { acknowledged: true })
    }

    async fn terminate(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        let session_id = session.session_id.as_str();
        self.store.kill_live_process(session_id)?;
        self.store.with_entry(session_id, |e| {
            e.state = SessionState::Terminated;
        })?;
        self.emit(session_id, AgentEventKind::SessionTerminated, json!({}))?;
        Ok(Ack { acknowledged: true })
    }

    fn events(&self, session: &SessionHandle) -> HarnessEventStream {
        Box::pin(tokio_stream::iter(
            self.store.events_snapshot(session.session_id.as_str()),
        ))
    }
}
