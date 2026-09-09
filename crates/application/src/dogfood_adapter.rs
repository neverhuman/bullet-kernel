//! A `HarnessAdapter` that drives a REAL contained provider turn.
//!
//! The Runner has only ever accepted `--provider sim`, so the transaction loop
//! has only ever been fed a simulator's canned proposal. The real dogfood turn
//! existed as a free function that no adapter could reach, which is the only
//! reason the two halves never met. This is that seam: the same admission the
//! `bullet dogfood read-only` CLI uses, behind the four methods the Runner
//! actually calls.
//!
//! It cannot silently degrade to a simulator. Every dogfood admission input is
//! required at construction, and `start` refuses with the existing typed codes
//! when one is missing.

use crate::dogfood_run::{
    dispatch_dogfood_compose, ComposedTurn, DogfoodReadOnlyOptions, DogfoodRunError,
};
use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AgentEvent, AuthChallenge, CapabilityMatrix, CompactRequest,
    ContextTransition, HarnessAdapter, HarnessDescriptor, HarnessError, HarnessEventStream,
    HarnessResult, InvocationId, ModelSnapshot, PermissionDecision, PlanDecision, ProbeResult,
    ProfileRef, PromotionStage, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle,
    StartSession, SteeringMessage, Turn, TurnHandle,
};
use std::sync::Mutex;

/// Provider wire name this adapter drives.
const PROVIDER: &str = "claude";

/// A poisoned lock means another turn panicked mid-flight. Refuse rather than
/// guess what state the containment was left in.
fn poisoned(method: &str) -> HarnessError {
    HarnessError::AdmissionRefused {
        reason: format!("DOGFOOD_SESSION_POISONED: {method} after a panicked turn"),
    }
}

/// Drives one real, contained, read-only Claude turn per session.
pub struct DogfoodClaudeAdapter {
    options: DogfoodReadOnlyOptions,
    bound: Mutex<Option<BoundSession>>,
    turn: Mutex<Option<CompletedTurn>>,
}

/// What `start` learned from the Runner and `send` must honour.
///
/// The operator's `--workspace-root` is the Runner's own scratch, not the
/// tree under review. The Runner clones the source repository first and hands
/// the clone to `start`. An adapter that ignored that and used the operator's
/// path would run the provider against an empty directory and return a
/// confident proposal about nothing, so the session's workdir wins.
struct BoundSession {
    workdir: std::path::PathBuf,
    wall_timeout_secs: u64,
}

struct CompletedTurn {
    events: Vec<AgentEvent>,
}

impl DogfoodClaudeAdapter {
    /// Bind the adapter to one operator-supplied dogfood admission.
    #[must_use]
    pub fn new(options: DogfoodReadOnlyOptions) -> Self {
        Self {
            options,
            bound: Mutex::new(None),
            turn: Mutex::new(None),
        }
    }

    fn refuse(error: &DogfoodRunError) -> HarnessError {
        HarnessError::AdmissionRefused {
            reason: format!("{}: {}", error.code, error.detail),
        }
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for DogfoodClaudeAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        // Deliberately Development and Unknown: this adapter drives one real
        // read-only turn and claims no conformance stage it has not earned.
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: PROVIDER.to_string(),
            version: Observation::Unknown {
                source: "dogfood-adapter".to_string(),
                reason: "version is established by the enrollment, not by a probe".to_string(),
            },
            stage: PromotionStage::Development,
            capabilities: CapabilityMatrix::default(),
        }
    }

    async fn probe(&self, _profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        Err(unsupported(PROVIDER, "probe"))
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
        if !request.workdir.is_dir() {
            return Err(HarnessError::AdmissionRefused {
                reason: format!(
                    "DOGFOOD_WORKDIR_ABSENT: the Runner's clone {} is not a directory",
                    request.workdir.display()
                ),
            });
        }
        *self.bound.lock().map_err(|_| poisoned("start"))? = Some(BoundSession {
            workdir: request.workdir.clone(),
            wall_timeout_secs: request.wall_timeout.as_secs(),
        });
        Ok(SessionHandle {
            session_id: request.session_id,
            provider: PROVIDER.to_string(),
            native_session_id: None,
        })
    }

    async fn resume(&self, _request: ResumeSession) -> HarnessResult<SessionHandle> {
        Err(unsupported(PROVIDER, "resume"))
    }

    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let bound = self
            .bound
            .lock()
            .map_err(|_| poisoned("send"))?
            .as_ref()
            .map(|bound| (bound.workdir.clone(), bound.wall_timeout_secs))
            .ok_or_else(|| HarnessError::AdmissionRefused {
                reason: "DOGFOOD_SESSION_UNBOUND: send before start".to_owned(),
            })?;
        let mut options = self.options.clone();
        options.prompt = Some(turn.prompt);
        // The Runner's clone, never the operator's workspace root.
        options.workdir = bound.0;
        // The Runner's per-turn ceiling narrows the operator's, never widens
        // it: whichever ceiling is lower is the one that binds.
        options.wall_timeout_secs =
            Some(match options.wall_timeout_secs {
                Some(operator) if bound.1 > 0 => operator.min(bound.1),
                Some(operator) => operator,
                None if bound.1 > 0 => bound.1,
                None => return Err(HarnessError::AdmissionRefused {
                    reason:
                        "DOGFOOD_NO_WALL_CEILING: neither the operator nor the Runner stated one"
                            .to_owned(),
                }),
            });
        // The real provider runs here, inside the same containment and against
        // the same enrollment the CLI uses. `spawn_blocking`, not
        // `block_in_place`: the latter panics outright on a current-thread
        // runtime, and an adapter that panics cannot refuse.
        let composed = tokio::task::spawn_blocking(move || dispatch_dogfood_compose(&options))
            .await
            .map_err(|error| HarnessError::AdmissionRefused {
                reason: format!("DOGFOOD_DISPATCH_LOST: {error}"),
            })?
            .map_err(|error| Self::refuse(&error))?;
        let dispatched = match composed {
            ComposedTurn::Neutral { code, detail } => {
                return Err(HarnessError::AdmissionRefused {
                    reason: format!("{code}: {detail}"),
                });
            }
            ComposedTurn::Dispatched(dispatched) => dispatched,
        };
        let handle = TurnHandle {
            invocation_id: InvocationId::new(session.session_id.as_str()),
            exit_code: dispatched.outcome.live.exit_code,
            timed_out: dispatched.outcome.live.timed_out,
        };
        *self
            .turn
            .lock()
            .map_err(|_| unsupported(PROVIDER, "turn state"))? = Some(CompletedTurn {
            events: dispatched.outcome.live.events.clone(),
        });
        Ok(handle)
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

    async fn interrupt(&self, _s: &SessionHandle) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "interrupt"))
    }

    async fn terminate(&self, _s: &SessionHandle) -> HarnessResult<Ack> {
        // The compose tears its own containment down; nothing survives a turn.
        Ok(Ack { acknowledged: true })
    }

    fn events(&self, _session: &SessionHandle) -> HarnessEventStream {
        let events = self
            .turn
            .lock()
            .ok()
            .and_then(|turn| turn.as_ref().map(|turn| turn.events.clone()))
            .unwrap_or_default();
        Box::pin(futures::stream::iter(events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn start_session(workdir: PathBuf) -> StartSession {
        StartSession {
            session_id: bullet_harness_core::AgentSessionId::new(
                "00000000-0000-4000-8000-000000000001",
            ),
            workdir,
            artifact_dir: PathBuf::from("/tmp"),
            model: None,
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: std::time::Duration::from_secs(5),
        }
    }

    fn options() -> DogfoodReadOnlyOptions {
        DogfoodReadOnlyOptions {
            provider: "claude".to_owned(),
            data_dir: PathBuf::from("/tmp/absent-dogfood-data"),
            policy: PathBuf::from("/tmp/absent-policy.json"),
            binding: PathBuf::from("/tmp/absent-binding.json"),
            enrollment: PathBuf::from("/tmp/absent-enrollment.json"),
            issuer: "dogfood-local".into(),
            key_id: "dogfood-runner-1".into(),
            executable: PathBuf::from("/usr/bin/true"),
            gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.to_owned()],
            credentials: Vec::new(),
            workdir: PathBuf::from("/tmp"),
            prompt: None,
            max_budget_usd: Some(0.25),
            wall_timeout_secs: None,
            receipt: PathBuf::from("/tmp/absent-receipt.json"),
        }
    }

    #[test]
    fn the_adapter_names_a_real_provider_and_claims_no_stage_it_has_not_earned() {
        let adapter = DogfoodClaudeAdapter::new(options());
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.provider, "claude");
        assert_eq!(descriptor.stage, PromotionStage::Development);
    }

    #[tokio::test]
    async fn a_session_refuses_to_bind_to_a_clone_the_runner_never_made() {
        let adapter = DogfoodClaudeAdapter::new(options());
        let error = adapter
            .start(start_session(PathBuf::from("/nonexistent/clone")))
            .await
            .expect_err("an absent clone must refuse");
        assert!(
            error.to_string().contains("DOGFOOD_WORKDIR_ABSENT"),
            "got: {error}"
        );
    }

    #[tokio::test]
    async fn sending_before_start_refuses_rather_than_using_the_operator_workspace_root() {
        // The operator's --workspace-root is the Runner's scratch, not the
        // tree under review. Running the provider against it would produce a
        // confident proposal about an empty directory.
        let adapter = DogfoodClaudeAdapter::new(options());
        let error = adapter
            .send(
                &SessionHandle {
                    session_id: bullet_harness_core::AgentSessionId::new(
                        "00000000-0000-4000-8000-000000000002",
                    ),
                    provider: "claude".to_owned(),
                    native_session_id: None,
                },
                Turn {
                    prompt: "x".to_owned(),
                },
            )
            .await
            .expect_err("send before start must refuse");
        assert!(
            error.to_string().contains("DOGFOOD_SESSION_UNBOUND"),
            "got: {error}"
        );
    }

    #[tokio::test]
    async fn a_turn_with_incomplete_admission_refuses_and_never_degrades_to_a_simulator() {
        // The whole point of this adapter: the Runner used to accept only
        // `--provider sim`, so the transaction loop only ever saw a canned
        // proposal. A real provider whose admission is incomplete must refuse
        // by name. Silently producing a simulated proposal here would be the
        // single worst outcome the design exists to prevent.
        let adapter = DogfoodClaudeAdapter::new(options());
        let session = adapter
            .start(start_session(PathBuf::from("/tmp")))
            .await
            .expect("start binds a session without spawning");
        let error = adapter
            .send(
                &session,
                Turn {
                    prompt: "x".to_owned(),
                },
            )
            .await
            .expect_err("incomplete admission must refuse");
        let reason = error.to_string();
        assert!(
            reason.contains("DOGFOOD_") || reason.contains("POLICY"),
            "refusal must name the missing admission, got: {reason}"
        );
        assert!(
            !reason.to_ascii_lowercase().contains("sim"),
            "a real provider must never mention falling back to a simulator: {reason}"
        );
    }
}
