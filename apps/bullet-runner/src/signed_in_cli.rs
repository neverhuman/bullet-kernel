//! Drive one signed-in native CLI without writing enrollment files.
//!
//! Claude's enrolled compose stays in `DogfoodClaudeAdapter`. This adapter
//! execs the operator-supplied Codex, Cursor, or Antigravity binary against
//! the Runner's clone. It never constructs `SimAdapter`.

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AgentEvent, AgentEventKind, AuthChallenge, CapabilityMatrix, CompactRequest,
    ContextTransition, EventId, HarnessAdapter, HarnessDescriptor, HarnessError,
    HarnessEventStream, HarnessResult, InvocationId, ModelSnapshot, PermissionDecision,
    PlanDecision, ProbeResult, ProfileRef, PromotionStage, QuotaObservation, ResumeSession,
    SessionCheckpoint, SessionHandle, StartSession, SteeringMessage, Turn, TurnHandle,
};
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub struct SignedInCliAdapter {
    provider: String,
    executable: PathBuf,
    model: String,
    bound: Mutex<Option<PathBuf>>,
    events: Mutex<Vec<AgentEvent>>,
}

impl SignedInCliAdapter {
    pub fn new(provider: String, executable: PathBuf, model: String) -> Result<Self, String> {
        if !executable.is_absolute() {
            return Err("--signed-in-executable must be an absolute path".into());
        }
        if model.is_empty() {
            return Err("--model is required for a signed-in provider".into());
        }
        match provider.as_str() {
            "codex" | "cursor" | "agy" | "antigravity" => {}
            other => return Err(format!("signed-in adapter refuses provider {other}")),
        }
        Ok(Self {
            provider: if provider == "antigravity" {
                "agy".into()
            } else {
                provider
            },
            executable,
            model,
            bound: Mutex::new(None),
            events: Mutex::new(Vec::new()),
        })
    }

    fn argv(&self, prompt: &str) -> Vec<String> {
        match self.provider.as_str() {
            "codex" => vec![
                "exec".into(),
                "--skip-git-repo-check".into(),
                "--sandbox".into(),
                "read-only".into(),
                "-m".into(),
                self.model.clone(),
                prompt.into(),
            ],
            "cursor" => vec![
                "-p".into(),
                "--output-format".into(),
                "text".into(),
                "--mode".into(),
                "plan".into(),
                "--trust".into(),
                prompt.into(),
            ],
            _ => vec![
                "--json".into(),
                "--model".into(),
                self.model.clone(),
                prompt.into(),
            ],
        }
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for SignedInCliAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: self.provider.clone(),
            binary: self
                .executable
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("signed-in")
                .to_string(),
            version: Observation::Unknown {
                source: "signed-in-cli".into(),
                reason: "version is the operator-probed executable, not a live probe".into(),
            },
            stage: PromotionStage::Development,
            capabilities: CapabilityMatrix::default(),
        }
    }

    async fn probe(&self, _profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        Err(unsupported(&self.provider, "probe"))
    }

    async fn list_models(&self, _profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>> {
        Err(unsupported(&self.provider, "list_models"))
    }

    async fn observe_quota(&self, _profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>> {
        Err(unsupported(&self.provider, "observe_quota"))
    }

    async fn begin_login(&self, _profile: &ProfileRef) -> HarnessResult<AuthChallenge> {
        Err(unsupported(&self.provider, "begin_login"))
    }

    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle> {
        if !request.workdir.is_dir() {
            return Err(HarnessError::AdmissionRefused {
                reason: format!("SIGNED_IN_WORKDIR_ABSENT: {}", request.workdir.display()),
            });
        }
        *self
            .bound
            .lock()
            .map_err(|_| HarnessError::AdmissionRefused {
                reason: "SIGNED_IN_SESSION_POISONED: start".into(),
            })? = Some(request.workdir.clone());
        Ok(SessionHandle {
            session_id: request.session_id,
            provider: self.provider.clone(),
            native_session_id: None,
        })
    }

    async fn resume(&self, _request: ResumeSession) -> HarnessResult<SessionHandle> {
        Err(unsupported(&self.provider, "resume"))
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let workdir = self
            .bound
            .lock()
            .map_err(|_| HarnessError::AdmissionRefused {
                reason: "SIGNED_IN_SESSION_POISONED: send".into(),
            })?
            .clone()
            .ok_or_else(|| HarnessError::AdmissionRefused {
                reason: "SIGNED_IN_SESSION_UNBOUND: send before start".into(),
            })?;
        let executable = self.executable.clone();
        let args = self.argv(&turn.prompt);
        let output = tokio::task::spawn_blocking(move || {
            Command::new(&executable)
                .args(&args)
                .current_dir(&workdir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
        })
        .await
        .map_err(|error| HarnessError::AdmissionRefused {
            reason: format!("SIGNED_IN_DISPATCH_LOST: {error}"),
        })?
        .map_err(|error| HarnessError::AdmissionRefused {
            reason: format!("SIGNED_IN_SPAWN_FAILED: {error}"),
        })?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let invocation = InvocationId::new(session.session_id.as_str());
        *self
            .events
            .lock()
            .map_err(|_| HarnessError::AdmissionRefused {
                reason: "SIGNED_IN_SESSION_POISONED: events".into(),
            })? = vec![AgentEvent {
            event_id: EventId::new(session.session_id.as_str()),
            session_id: session.session_id.clone(),
            invocation_id: Some(invocation.clone()),
            native_session_id: None,
            provider: self.provider.clone(),
            model: Some(self.model.clone()),
            kind: AgentEventKind::TurnCompleted,
            timestamp: Utc::now(),
            sequence: 0,
            causation_id: None,
            payload: json!({ "stdout": stdout, "exit": output.status.code() }),
            raw_artifact: None,
        }];
        Ok(TurnHandle {
            invocation_id: InvocationId::new(session.session_id.as_str()),
            exit_code: output.status.code(),
            timed_out: false,
        })
    }

    async fn steer(&self, _s: &SessionHandle, _m: SteeringMessage) -> HarnessResult<Ack> {
        Err(unsupported(&self.provider, "steer"))
    }

    async fn approve_local_plan(&self, _s: &SessionHandle, _d: PlanDecision) -> HarnessResult<Ack> {
        Err(unsupported(&self.provider, "approve_local_plan"))
    }

    async fn respond_permission(
        &self,
        _s: &SessionHandle,
        _d: PermissionDecision,
    ) -> HarnessResult<Ack> {
        Err(unsupported(&self.provider, "respond_permission"))
    }

    async fn compact(
        &self,
        _s: &SessionHandle,
        _r: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        Err(unsupported(&self.provider, "compact"))
    }

    async fn checkpoint(&self, _s: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        Err(unsupported(&self.provider, "checkpoint"))
    }

    async fn interrupt(&self, _s: &SessionHandle) -> HarnessResult<Ack> {
        Err(unsupported(&self.provider, "interrupt"))
    }

    async fn terminate(&self, _s: &SessionHandle) -> HarnessResult<Ack> {
        Err(unsupported(&self.provider, "terminate"))
    }

    fn events(&self, _session: &SessionHandle) -> HarnessEventStream {
        let events = self
            .events
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        Box::pin(futures::stream::iter(events))
    }
}
