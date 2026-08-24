//! Cursor Agent headless adapter: one-shot `cursor-agent -p` turns in plan
//! mode with stream-json events. No enforced output schema exists, so the
//! prompt instructs JSON-only output and the proposal parse is best-effort
//! but still validated (ADR 0001).

mod parse;

use bullet_domain::Observation;
use bullet_harness_core::{
    synthetic_uuid, unsupported, Ack, AgentEventKind, AgentSessionId, ArgvBuilder, ArtifactRef,
    AuthChallenge, Capability, CapabilityMatrix, CapabilityState, CompactRequest,
    ContextTransition, EventNormalizer, HarnessAdapter, HarnessDescriptor, HarnessError,
    HarnessEventStream, HarnessResult, InvocationBudget, InvocationId, ModelSnapshot, NativeMeta,
    PermissionDecision, PlanDecision, ProbeResult, ProfileRef, PromotionStage, QuotaObservation,
    ResumeSession, SessionCheckpoint, SessionEntry, SessionHandle, SessionState, SessionStore,
    StartSession, SteeringMessage, Turn, TurnHandle,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Provider name.
pub const PROVIDER: &str = "cursor";
/// Executable.
pub const BINARY: &str = "cursor-agent";

#[derive(Clone, Debug)]
struct SessionConfig {
    model: Option<String>,
    wall_timeout: Duration,
    chat_id: Option<String>,
}

/// Cursor Agent adapter.
pub struct CursorAdapter {
    store: SessionStore,
    normalizers: Mutex<HashMap<String, EventNormalizer>>,
    configs: Mutex<HashMap<String, SessionConfig>>,
    budget: InvocationBudget,
}

impl Default for CursorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorAdapter {
    /// Fresh adapter with a small per-run invocation budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: SessionStore::new(),
            normalizers: Mutex::new(HashMap::new()),
            configs: Mutex::new(HashMap::new()),
            budget: InvocationBudget::new(8),
        }
    }

    fn with_normalizer<R>(
        &self,
        session_id: &str,
        f: impl FnOnce(&mut EventNormalizer) -> R,
    ) -> HarnessResult<R> {
        let mut map = self.normalizers.lock().map_err(|_| HarnessError::Io {
            context: "normalizer lock".into(),
            reason: "poisoned".into(),
        })?;
        map.get_mut(session_id)
            .map(f)
            .ok_or_else(|| HarnessError::SessionUnknown {
                session: session_id.to_string(),
            })
    }

    fn config(&self, session_id: &str) -> HarnessResult<SessionConfig> {
        let map = self.configs.lock().map_err(|_| HarnessError::Io {
            context: "config lock".into(),
            reason: "poisoned".into(),
        })?;
        map.get(session_id)
            .cloned()
            .ok_or_else(|| HarnessError::SessionUnknown {
                session: session_id.to_string(),
            })
    }

    fn emit(&self, session_id: &str, kind: AgentEventKind, payload: Value) -> HarnessResult<()> {
        let event =
            self.with_normalizer(session_id, |n| n.accept(kind, payload, &NativeMeta::none()))?;
        self.store.push_events(session_id, vec![event])
    }

    async fn mint_chat_id(&self, workdir: &PathBuf) -> HarnessResult<String> {
        let prep = ArgvBuilder::new(BINARY, workdir)
            .arg("create-chat")
            .timeout(Duration::from_secs(60))
            .build()?;
        let outcome = bullet_harness_core::run_to_completion(&prep, None).await?;
        let chat_id = outcome
            .stdout_lines
            .iter()
            .rev()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .map(str::to_string);
        chat_id.ok_or_else(|| HarnessError::ProviderFailure {
            provider: PROVIDER.to_string(),
            exit: outcome.exit_code,
            reason: format!("create-chat produced no id; stderr: {}", outcome.stderr),
        })
    }

    fn register(
        &self,
        session_id: &str,
        workdir: PathBuf,
        artifact_dir: &PathBuf,
        config: SessionConfig,
    ) -> HarnessResult<SessionHandle> {
        std::fs::create_dir_all(artifact_dir).map_err(|err| HarnessError::Io {
            context: format!("artifact dir {}", artifact_dir.display()),
            reason: err.to_string(),
        })?;
        let artifact_path = artifact_dir.join(format!("{session_id}.raw.jsonl"));
        let handle = SessionHandle {
            session_id: AgentSessionId::new(session_id),
            provider: PROVIDER.to_string(),
            native_session_id: config.chat_id.clone(),
        };
        let mut entry = SessionEntry::new(handle.clone(), workdir, artifact_path.clone());
        for state in [
            SessionState::Starting,
            SessionState::IdentityProbing,
            SessionState::ContextLoading,
            SessionState::Ready,
        ] {
            entry.state = entry.state.transition(state)?;
        }
        entry.model.clone_from(&config.model);
        self.store.insert(entry);
        let mut normalizer = EventNormalizer::new(AgentSessionId::new(session_id), PROVIDER);
        if let Some(chat) = &config.chat_id {
            normalizer.set_native_session(chat.clone());
        }
        if let Some(model) = &config.model {
            normalizer.set_model(model.clone());
        }
        normalizer.set_raw_artifact(ArtifactRef::new(artifact_path.display().to_string()));
        if let Ok(mut map) = self.normalizers.lock() {
            map.insert(session_id.to_string(), normalizer);
        }
        if let Ok(mut map) = self.configs.lock() {
            map.insert(session_id.to_string(), config);
        }
        self.emit(
            session_id,
            AgentEventKind::SessionStarted,
            json!({ "mode": "one_shot", "spawned": false }),
        )?;
        Ok(handle)
    }

    fn build_turn_argv(
        &self,
        config: &SessionConfig,
        workdir: &PathBuf,
        prompt: &str,
    ) -> HarnessResult<bullet_harness_core::PreparedInvocation> {
        let workdir_text = workdir.display().to_string();
        let mut builder = ArgvBuilder::new(BINARY, workdir)
            .timeout(config.wall_timeout)
            .args([
                "-p",
                prompt,
                "--workspace",
                &workdir_text,
                "--mode",
                "plan",
                "--output-format",
                "stream-json",
                "--trust",
            ]);
        if let Some(model) = &config.model {
            builder = builder.args(["--model", model]);
        }
        if let Some(chat) = &config.chat_id {
            builder = builder.args(["--resume", chat]);
        }
        builder.build()
    }

    fn append_raw(&self, path: &PathBuf, outcome: &bullet_harness_core::RunOutcome) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            for line in &outcome.stdout_lines {
                let _ = writeln!(file, "{line}");
            }
            if !outcome.stderr.is_empty() {
                let _ = writeln!(file, "{}", json!({ "stderr": outcome.stderr }));
            }
        }
    }
}

fn capabilities() -> CapabilityMatrix {
    CapabilityMatrix::new()
        .with(Capability::StructuredEvents, CapabilityState::Supported)
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(
            Capability::PlanModeControl,
            CapabilityState::SupportedWithLimitations,
        )
        .with(Capability::NativeResume, CapabilityState::Experimental)
        .with(Capability::ModelSelection, CapabilityState::Experimental)
        .with(Capability::TurnInterrupt, CapabilityState::Experimental)
}

#[async_trait::async_trait]
impl HarnessAdapter for CursorAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: BINARY.to_string(),
            version: Observation::Unknown {
                source: "descriptor".to_string(),
                reason: "probe reports the installed version".to_string(),
            },
            stage: PromotionStage::ContractPass,
            capabilities: capabilities(),
        }
    }

    async fn probe(&self, _profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        let tmp = std::env::temp_dir();
        let version = ArgvBuilder::new(BINARY, &tmp)
            .arg("--version")
            .timeout(Duration::from_secs(30))
            .build()?;
        let version_out = bullet_harness_core::run_to_completion(&version, None).await?;
        let version = version_out
            .stdout_lines
            .first()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if version.is_empty() {
            return Err(HarnessError::ProviderFailure {
                provider: PROVIDER.to_string(),
                exit: version_out.exit_code,
                reason: "no version output".to_string(),
            });
        }
        let status = ArgvBuilder::new(BINARY, &tmp)
            .arg("status")
            .timeout(Duration::from_secs(60))
            .build()?;
        let status_out = bullet_harness_core::run_to_completion(&status, None).await?;
        let profile = parse::parse_status(&status_out.stdout_lines.join("\n"));
        Ok(ProbeResult { profile, version })
    }

    async fn list_models(&self, _profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>> {
        Err(unsupported(PROVIDER, "list_models"))
    }

    async fn observe_quota(&self, _profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>> {
        Err(unsupported(PROVIDER, "observe_quota"))
    }

    async fn begin_login(&self, _profile: &ProfileRef) -> HarnessResult<AuthChallenge> {
        Err(unsupported(PROVIDER, "begin_login"))
    }

    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle> {
        let session_id = request.session_id.as_str().to_string();
        let chat_id = self.mint_chat_id(&request.workdir).await.ok();
        let config = SessionConfig {
            model: request.model,
            wall_timeout: request.wall_timeout,
            chat_id,
        };
        self.register(&session_id, request.workdir, &request.artifact_dir, config)
    }

    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        let session_id = request.session_id.as_str().to_string();
        let config = SessionConfig {
            model: None,
            wall_timeout: request.wall_timeout,
            chat_id: Some(request.native_session_id),
        };
        self.register(&session_id, request.workdir, &request.artifact_dir, config)
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let session_id = session.session_id.as_str().to_string();
        self.budget.try_acquire()?;
        let invocation_id = InvocationId::new(synthetic_uuid("cursor-invocation"));
        let (workdir, pid_slot, artifact_path) = self.store.with_entry(&session_id, |e| {
            e.invocations += 1;
            (
                e.workdir.clone(),
                e.pid_slot.clone(),
                e.artifact_path.clone(),
            )
        })?;
        let config = self.config(&session_id)?;
        let prep = self.build_turn_argv(&config, &workdir, &turn.prompt)?;
        self.with_normalizer(&session_id, |n| n.set_invocation(invocation_id.clone()))?;
        self.emit(
            &session_id,
            AgentEventKind::TurnStarted,
            json!({ "prompt_chars": turn.prompt.len() }),
        )?;
        let outcome = bullet_harness_core::run_to_completion(&prep, Some(pid_slot)).await?;
        self.append_raw(&artifact_path, &outcome);
        let events =
            self.with_normalizer(&session_id, |n| parse::normalize_outcome(n, &outcome))?;
        self.store.push_events(&session_id, events)?;
        Ok(TurnHandle {
            invocation_id,
            exit_code: outcome.exit_code,
            timed_out: outcome.timed_out,
        })
    }

    async fn steer(&self, _s: &SessionHandle, _m: SteeringMessage) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "steer"))
    }

    async fn approve_local_plan(&self, _s: &SessionHandle, _d: PlanDecision) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "approve_local_plan"))
    }

    async fn respond_permission(
        &self,
        _s: &SessionHandle,
        _d: PermissionDecision,
    ) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "respond_permission"))
    }

    async fn compact(
        &self,
        _s: &SessionHandle,
        _r: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        Err(unsupported(PROVIDER, "compact"))
    }

    async fn checkpoint(&self, _s: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        Err(unsupported(PROVIDER, "checkpoint"))
    }

    async fn interrupt(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        let session_id = session.session_id.as_str();
        let killed = self.store.kill_live_process(session_id)?;
        self.emit(
            session_id,
            AgentEventKind::InterruptAcknowledged,
            json!({ "killed_live_process": killed }),
        )?;
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
