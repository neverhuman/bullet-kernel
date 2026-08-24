//! Claude Code headless adapter: one-shot `claude -p` turns in plan mode
//! (read-only tools), stream-json events, and an enforced PatchProposal
//! schema (ADR 0001). The kernel applies patches; this process never writes.

mod parse;

use bullet_domain::Observation;
use bullet_harness_core::{
    stable_uuid, synthetic_uuid, unsupported, Ack, AgentEventKind, ArgvBuilder, ArtifactRef,
    AuthChallenge, Capability, CapabilityMatrix, CapabilityState, CompactRequest,
    ContextTransition, EventNormalizer, HarnessAdapter, HarnessDescriptor, HarnessError,
    HarnessEventStream, HarnessResult, InvocationBudget, InvocationId, ModelSnapshot,
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
pub const PROVIDER: &str = "claude";
/// Executable.
pub const BINARY: &str = "claude";

#[derive(Clone, Debug)]
struct SessionConfig {
    schema: Option<Value>,
    max_budget_usd: Option<f64>,
    wall_timeout: Duration,
    resume_native: Option<String>,
}

/// Claude Code adapter.
pub struct ClaudeAdapter {
    store: SessionStore,
    normalizers: Mutex<HashMap<String, EventNormalizer>>,
    configs: Mutex<HashMap<String, SessionConfig>>,
    budget: InvocationBudget,
}

impl Default for ClaudeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeAdapter {
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
        let event = self.with_normalizer(session_id, |n| {
            n.accept(kind, payload, &bullet_harness_core::NativeMeta::none())
        })?;
        self.store.push_events(session_id, vec![event])
    }

    fn register(
        &self,
        session_id: &str,
        workdir: PathBuf,
        artifact_dir: &PathBuf,
        config: SessionConfig,
        native: Option<String>,
    ) -> HarnessResult<SessionHandle> {
        std::fs::create_dir_all(artifact_dir).map_err(|err| HarnessError::Io {
            context: format!("artifact dir {}", artifact_dir.display()),
            reason: err.to_string(),
        })?;
        let artifact_path = artifact_dir.join(format!("{session_id}.raw.jsonl"));
        let handle = SessionHandle {
            session_id: bullet_harness_core::AgentSessionId::new(session_id),
            provider: PROVIDER.to_string(),
            native_session_id: native.clone(),
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
        let mut normalizer = EventNormalizer::new(
            bullet_harness_core::AgentSessionId::new(session_id),
            PROVIDER,
        );
        if let Some(native) = native {
            normalizer.set_native_session(native);
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
        session_id: &str,
        config: &SessionConfig,
        workdir: &PathBuf,
        prompt: &str,
        first_turn: bool,
    ) -> HarnessResult<bullet_harness_core::PreparedInvocation> {
        let mut builder = ArgvBuilder::new(BINARY, workdir)
            .timeout(config.wall_timeout)
            .args([
                "-p",
                prompt,
                "--output-format",
                "stream-json",
                "--verbose",
                "--permission-mode",
                "plan",
            ]);
        // claude 2.1.241 requires a canonical UUID for --session-id/--resume
        // ("Invalid session ID. Must be a valid UUID."). Callers pass labels
        // like `plan-claude-2` or `atm_...`; map any non-UUID label to a stable
        // UUID here so every caller is safe. A real UUID passes through unchanged.
        // A single --session-id may be claimed only once ("already in use"), so
        // multi-turn sessions (the runner's repair rounds) resume after the
        // first turn on the same derived UUID.
        builder = match &config.resume_native {
            Some(native) => builder.args(["--resume".to_string(), stable_uuid(native)]),
            None if first_turn => {
                builder.args(["--session-id".to_string(), stable_uuid(session_id)])
            }
            None => builder.args(["--resume".to_string(), stable_uuid(session_id)]),
        };
        if let Some(schema) = &config.schema {
            // claude 2.1.241 cannot resolve the draft 2020-12 meta-schema
            // reference, so the $schema/$id keys are stripped before passing.
            let mut schema = schema.clone();
            if let Some(object) = schema.as_object_mut() {
                object.remove("$schema");
                object.remove("$id");
            }
            builder = builder.args(["--json-schema", &schema.to_string()]);
        }
        if let Some(budget) = config.max_budget_usd {
            builder = builder.args(["--max-budget-usd", &format!("{budget}")]);
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
        .with(
            Capability::StructuredOutputSchema,
            CapabilityState::SupportedWithLimitations,
        )
        .with(Capability::UsageEvents, CapabilityState::Supported)
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(
            Capability::PlanModeControl,
            CapabilityState::SupportedWithLimitations,
        )
        .with(Capability::NativeResume, CapabilityState::Experimental)
        .with(Capability::TurnInterrupt, CapabilityState::Experimental)
}

#[async_trait::async_trait]
impl HarnessAdapter for ClaudeAdapter {
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
        let auth = ArgvBuilder::new(BINARY, &tmp)
            .args(["auth", "status"])
            .timeout(Duration::from_secs(30))
            .build()?;
        let auth_out = bullet_harness_core::run_to_completion(&auth, None).await?;
        let profile = parse::parse_auth_status(&auth_out.stdout_lines.join("\n"));
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
        let config = SessionConfig {
            schema: request.structured_schema,
            max_budget_usd: request.max_budget_usd,
            wall_timeout: request.wall_timeout,
            resume_native: None,
        };
        // The kernel keys the session by its own label (`session_id`), but the
        // provider-native id is the canonical UUID we actually pass to claude.
        // Record that derived UUID so receipts carry a real session id even
        // before the init envelope confirms it.
        self.register(
            &session_id,
            request.workdir,
            &request.artifact_dir,
            config,
            Some(stable_uuid(&session_id)),
        )
    }

    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        let session_id = request.session_id.as_str().to_string();
        let config = SessionConfig {
            schema: None,
            max_budget_usd: request.max_budget_usd,
            wall_timeout: request.wall_timeout,
            resume_native: Some(request.native_session_id.clone()),
        };
        self.register(
            &session_id,
            request.workdir,
            &request.artifact_dir,
            config,
            Some(request.native_session_id),
        )
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let session_id = session.session_id.as_str().to_string();
        self.budget.try_acquire()?;
        let invocation_id = InvocationId::new(synthetic_uuid("claude-invocation"));
        let (workdir, pid_slot, artifact_path, invocations) =
            self.store.with_entry(&session_id, |e| {
                e.invocations += 1;
                (
                    e.workdir.clone(),
                    e.pid_slot.clone(),
                    e.artifact_path.clone(),
                    e.invocations,
                )
            })?;
        let config = self.config(&session_id)?;
        let prep = self.build_turn_argv(
            &session_id,
            &config,
            &workdir,
            &turn.prompt,
            invocations <= 1,
        )?;
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
