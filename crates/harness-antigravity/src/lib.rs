//! Antigravity (`agy`) adapter: text-only headless prompts under `--sandbox`
//! (which ENABLES restrictions — inverted polarity vs other CLIs). No JSON
//! surface exists, so structured capabilities are Unsupported and a fenced
//! ```diff block is extracted best-effort; it is never a PatchProposal.

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
pub const PROVIDER: &str = "agy";
/// Executable.
pub const BINARY: &str = "agy";

#[derive(Clone, Debug)]
struct SessionConfig {
    wall_timeout: Duration,
}

/// Antigravity adapter.
pub struct AntigravityAdapter {
    store: SessionStore,
    normalizers: Mutex<HashMap<String, EventNormalizer>>,
    configs: Mutex<HashMap<String, SessionConfig>>,
    budget: InvocationBudget,
}

impl Default for AntigravityAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AntigravityAdapter {
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
                let _ = writeln!(file, "STDERR: {}", outcome.stderr);
            }
        }
    }
}

fn capabilities() -> CapabilityMatrix {
    CapabilityMatrix::new()
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(Capability::TurnInterrupt, CapabilityState::Experimental)
}

#[async_trait::async_trait]
impl HarnessAdapter for AntigravityAdapter {
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
        Ok(ProbeResult {
            profile: Observation::Unknown {
                source: "agy".to_string(),
                reason: "no identity surface in the headless cli".to_string(),
            },
            version,
        })
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
        if request.structured_schema.is_some() {
            return Err(HarnessError::CapabilityUnsupported {
                capability: Capability::StructuredOutputSchema.as_str().to_string(),
            });
        }
        let session_id = request.session_id.as_str().to_string();
        std::fs::create_dir_all(&request.artifact_dir).map_err(|err| HarnessError::Io {
            context: format!("artifact dir {}", request.artifact_dir.display()),
            reason: err.to_string(),
        })?;
        let artifact_path = request.artifact_dir.join(format!("{session_id}.raw.txt"));
        let handle = SessionHandle {
            session_id: request.session_id.clone(),
            provider: PROVIDER.to_string(),
            native_session_id: None,
        };
        let mut entry = SessionEntry::new(handle.clone(), request.workdir, artifact_path.clone());
        for state in [
            SessionState::Starting,
            SessionState::IdentityProbing,
            SessionState::ContextLoading,
            SessionState::Ready,
        ] {
            entry.state = entry.state.transition(state)?;
        }
        self.store.insert(entry);
        let mut normalizer = EventNormalizer::new(AgentSessionId::new(&session_id), PROVIDER);
        normalizer.set_raw_artifact(ArtifactRef::new(artifact_path.display().to_string()));
        if let Ok(mut map) = self.normalizers.lock() {
            map.insert(session_id.clone(), normalizer);
        }
        if let Ok(mut map) = self.configs.lock() {
            map.insert(
                session_id.clone(),
                SessionConfig {
                    wall_timeout: request.wall_timeout,
                },
            );
        }
        self.emit(
            &session_id,
            AgentEventKind::SessionStarted,
            json!({ "mode": "one_shot", "text_only": true }),
        )?;
        Ok(handle)
    }

    async fn resume(&self, _request: ResumeSession) -> HarnessResult<SessionHandle> {
        Err(unsupported(PROVIDER, "resume"))
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let session_id = session.session_id.as_str().to_string();
        self.budget.try_acquire()?;
        let invocation_id = InvocationId::new(synthetic_uuid("agy-invocation"));
        let (workdir, pid_slot, artifact_path) = self.store.with_entry(&session_id, |e| {
            e.invocations += 1;
            (
                e.workdir.clone(),
                e.pid_slot.clone(),
                e.artifact_path.clone(),
            )
        })?;
        let config = self.config(&session_id)?;
        let print_timeout = format!("{}s", config.wall_timeout.as_secs().max(1));
        let prep = ArgvBuilder::new(BINARY, &workdir)
            .timeout(config.wall_timeout)
            .args([
                "-p",
                &turn.prompt,
                "--sandbox",
                "--print-timeout",
                &print_timeout,
            ])
            .build()?;
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
