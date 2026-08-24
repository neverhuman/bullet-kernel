//! Codex CLI adapter: one-shot `codex exec` turns in a read-only sandbox
//! with NDJSON events, an output schema file, and a last-message file the
//! PatchProposal is read from (ADR 0001).

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
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Provider name.
pub const PROVIDER: &str = "codex";
/// Executable.
pub const BINARY: &str = "codex";

#[derive(Clone, Debug)]
struct SessionConfig {
    schema_path: Option<PathBuf>,
    last_message_path: PathBuf,
    wall_timeout: Duration,
    resume_native: Option<String>,
}

/// Codex exec adapter.
pub struct CodexAdapter {
    store: SessionStore,
    normalizers: Mutex<HashMap<String, EventNormalizer>>,
    configs: Mutex<HashMap<String, SessionConfig>>,
    budget: InvocationBudget,
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexAdapter {
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
            native_session_id: config.resume_native.clone(),
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
        self.store.insert(entry);
        let mut normalizer = EventNormalizer::new(AgentSessionId::new(session_id), PROVIDER);
        if let Some(native) = &config.resume_native {
            normalizer.set_native_session(native.clone());
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
        let mut builder = ArgvBuilder::new(BINARY, workdir).timeout(config.wall_timeout);
        builder = builder.arg("exec");
        if let Some(native) = &config.resume_native {
            builder = builder.args(["resume", native]);
        }
        let workdir_text = workdir.display().to_string();
        let last_text = config.last_message_path.display().to_string();
        // codex exec 0.149 is non-interactive by construction; there is no
        // --ask-for-approval flag (verified via `codex exec --help`), so the
        // read-only sandbox is the sole execution control.
        builder = builder.args([
            "-C",
            &workdir_text,
            "--sandbox",
            "read-only",
            "--json",
            "--skip-git-repo-check",
            "-o",
            &last_text,
        ]);
        if let Some(schema_path) = &config.schema_path {
            let schema_text = schema_path.display().to_string();
            builder = builder.args(["--output-schema", &schema_text]);
        }
        builder.arg(prompt).build()
    }
}

fn capabilities() -> CapabilityMatrix {
    CapabilityMatrix::new()
        .with(Capability::StructuredEvents, CapabilityState::Supported)
        .with(
            Capability::StructuredOutputSchema,
            CapabilityState::Supported,
        )
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(
            Capability::PlanModeControl,
            CapabilityState::SupportedWithLimitations,
        )
        .with(Capability::UsageEvents, CapabilityState::Supported)
        .with(Capability::NativeResume, CapabilityState::Experimental)
        .with(Capability::TurnInterrupt, CapabilityState::Experimental)
}

#[async_trait::async_trait]
impl HarnessAdapter for CodexAdapter {
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
        let auth_path = std::env::var("HOME")
            .map(|home| PathBuf::from(home).join(".codex/auth.json"))
            .map_err(|err| HarnessError::Io {
                context: "HOME".to_string(),
                reason: err.to_string(),
            })?;
        let profile = match std::fs::read_to_string(&auth_path) {
            Ok(text) => parse::parse_auth_json(&text),
            Err(err) => Observation::Unknown {
                source: auth_path.display().to_string(),
                reason: err.to_string(),
            },
        };
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
        if request.model.is_some() {
            return Err(HarnessError::CapabilityUnsupported {
                capability: Capability::ModelSelection.as_str().to_string(),
            });
        }
        let session_id = request.session_id.as_str().to_string();
        let schema_path = match &request.structured_schema {
            Some(schema) => {
                std::fs::create_dir_all(&request.artifact_dir).map_err(|err| HarnessError::Io {
                    context: format!("artifact dir {}", request.artifact_dir.display()),
                    reason: err.to_string(),
                })?;
                let path = request
                    .artifact_dir
                    .join(format!("{session_id}.schema.json"));
                std::fs::write(&path, schema.to_string()).map_err(|err| HarnessError::Io {
                    context: format!("schema file {}", path.display()),
                    reason: err.to_string(),
                })?;
                Some(path)
            }
            None => None,
        };
        let config = SessionConfig {
            schema_path,
            last_message_path: request.artifact_dir.join(format!("{session_id}.last.txt")),
            wall_timeout: request.wall_timeout,
            resume_native: None,
        };
        self.register(&session_id, request.workdir, &request.artifact_dir, config)
    }

    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        let session_id = request.session_id.as_str().to_string();
        let config = SessionConfig {
            schema_path: None,
            last_message_path: request.artifact_dir.join(format!("{session_id}.last.txt")),
            wall_timeout: request.wall_timeout,
            resume_native: Some(request.native_session_id),
        };
        self.register(&session_id, request.workdir, &request.artifact_dir, config)
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let session_id = session.session_id.as_str().to_string();
        self.budget.try_acquire()?;
        let invocation_id = InvocationId::new(synthetic_uuid("codex-invocation"));
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
        parse::append_raw(&artifact_path, &outcome);
        let last_message = std::fs::read_to_string(&config.last_message_path).ok();
        let events = self.with_normalizer(&session_id, |n| {
            parse::normalize_outcome(n, &outcome, last_message.as_deref())
        })?;
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
