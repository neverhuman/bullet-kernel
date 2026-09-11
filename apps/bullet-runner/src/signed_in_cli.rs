//! Drive one signed-in native CLI without writing enrollment files.
//!
//! Claude's enrolled compose stays in `DogfoodClaudeAdapter`. This adapter
//! execs the operator-supplied Codex, Cursor, or Antigravity binary against
//! the Runner's clone. It never constructs `SimAdapter`.

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AgentEvent, AgentEventKind, AuthChallenge, CapabilityMatrix, CompactRequest,
    ContextTransition, EventId, HarnessAdapter, HarnessDescriptor, HarnessError,
    HarnessEventStream, HarnessResult, InvocationId, ModelSnapshot, PatchProposal,
    PermissionDecision, PlanDecision, ProbeResult, ProfileRef, PromotionStage, QuotaObservation,
    ResumeSession, SessionCheckpoint, SessionHandle, StartSession, SteeringMessage, Turn,
    TurnHandle,
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
                "-m".into(),
                self.model.clone(),
                prompt.into(),
            ],
            "cursor" => vec![
                "-p".into(),
                "--output-format".into(),
                "stream-json".into(),
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
        let mut payload = json!({ "exit": output.status.code() });
        match PatchProposal::extract_from_text(&stdout) {
            Ok(proposal) => {
                if let Ok(value) = proposal.authoritative_value() {
                    payload["proposal"] = value;
                }
            }
            Err(_) if self.provider == "cursor" => {
                return Err(HarnessError::AdmissionRefused {
                    reason: "CURSOR_ACP_EVENTS_EMPTY: stream-json without a PatchProposal is not a structured turn".into(),
                });
            }
            Err(_) => {}
        }
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
            payload,
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

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_harness_core::AgentSessionId;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    fn proposal_json() -> String {
        format!(
            r#"{{"schema_version":1,"proposal_id":"cnt_{a}","producing_attempt_id":"atm_{b}","base_checkpoint_id":"ckp_{c}","base_checkpoint_digest":"{d}","operations":[{{"path":"PONG.txt","preimage":{{"kind":"absent"}},"mutation":{{"kind":"write","content_utf8":"PONG\n"}}}}],"gate_ids":["gat_{g}"]}}"#,
            a = "1".repeat(64),
            b = "2".repeat(64),
            c = "3".repeat(64),
            d = "4".repeat(64),
            g = "8".repeat(64),
        )
    }

    #[test]
    fn codex_argv_can_emit_a_patch_and_cursor_argv_is_not_plan_mode() {
        let adapter =
            SignedInCliAdapter::new("codex".into(), "/usr/bin/true".into(), "gpt-5".into())
                .unwrap();
        let argv = adapter.argv("implement");
        assert!(argv.starts_with(&["exec".into(), "--skip-git-repo-check".into()]));
        assert!(!argv.iter().any(|a| a == "read-only"));
        assert!(!argv.contains(&"--sandbox".into()));
        let cursor =
            SignedInCliAdapter::new("cursor".into(), "/usr/bin/true".into(), "composer-2".into())
                .unwrap();
        let argv = cursor.argv("implement");
        assert!(argv.contains(&"stream-json".into()));
        assert!(!argv.iter().any(|a| a == "plan" || a == "text"));
    }

    #[tokio::test]
    async fn stub_stdout_proposal_is_accepted_and_cursor_garbage_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub");
        let script = format!("#!/bin/sh\nprintf '%s\\n' '{}'\nexit 1\n", proposal_json());
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o700)
            .open(&stub)
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let adapter =
            SignedInCliAdapter::new("codex".into(), stub.clone(), "gpt-5".into()).unwrap();
        adapter
            .start(StartSession {
                session_id: AgentSessionId::new("signed-in-stub"),
                workdir: dir.path().to_path_buf(),
                artifact_dir: dir.path().to_path_buf(),
                model: None,
                structured_schema: None,
                max_budget_usd: None,
                wall_timeout: Duration::from_secs(5),
            })
            .await
            .unwrap();
        let handle = adapter
            .send(
                &SessionHandle {
                    session_id: AgentSessionId::new("signed-in-stub"),
                    provider: "codex".into(),
                    native_session_id: None,
                },
                Turn {
                    prompt: "implement".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(handle.exit_code, Some(1));
        let events: Vec<_> = futures::StreamExt::collect(adapter.events(&SessionHandle {
            session_id: AgentSessionId::new("signed-in-stub"),
            provider: "codex".into(),
            native_session_id: None,
        }))
        .await;
        assert!(events[0].payload.get("proposal").is_some());
        assert!(!events[0].payload.to_string().contains("sim"));

        let garbage = dir.path().join("garbage");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o700)
            .open(&garbage)
            .unwrap()
            .write_all(b"#!/bin/sh\necho no-proposal\n")
            .unwrap();
        let cursor =
            SignedInCliAdapter::new("cursor".into(), garbage, "composer-2".into()).unwrap();
        cursor
            .start(StartSession {
                session_id: AgentSessionId::new("signed-in-cursor-empty"),
                workdir: dir.path().to_path_buf(),
                artifact_dir: dir.path().to_path_buf(),
                model: None,
                structured_schema: None,
                max_budget_usd: None,
                wall_timeout: Duration::from_secs(5),
            })
            .await
            .unwrap();
        let error = cursor
            .send(
                &SessionHandle {
                    session_id: AgentSessionId::new("signed-in-cursor-empty"),
                    provider: "cursor".into(),
                    native_session_id: None,
                },
                Turn {
                    prompt: "implement".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("CURSOR_ACP_EVENTS_EMPTY"),
            "{error}"
        );
    }
}
