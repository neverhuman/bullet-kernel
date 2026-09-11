//! Explicit refusal until a signed-in coding containment profile is admitted.
//! The read-only Claude compose has a separate admission consumer.

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AuthChallenge, CapabilityMatrix, CompactRequest, ContextTransition,
    HarnessAdapter, HarnessDescriptor, HarnessError, HarnessEventStream, HarnessResult,
    ModelSnapshot, PermissionDecision, PlanDecision, ProbeResult, ProfileRef, PromotionStage,
    QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle, StartSession,
    SteeringMessage, Turn, TurnHandle,
};
use std::path::PathBuf;

pub struct SignedInCliAdapter {
    provider: String,
    executable: PathBuf,
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
        Err("SIGNED_IN_CONTAINMENT_UNAVAILABLE: admitted process, filesystem, credential and network containment is required".into())
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

    async fn start(&self, _request: StartSession) -> HarnessResult<SessionHandle> {
        Err(HarnessError::AdmissionRefused {
            reason: "SIGNED_IN_CONTAINMENT_UNAVAILABLE".into(),
        })
    }

    async fn resume(&self, _request: ResumeSession) -> HarnessResult<SessionHandle> {
        Err(unsupported(&self.provider, "resume"))
    }

    async fn send(&self, _session: &SessionHandle, _turn: Turn) -> HarnessResult<TurnHandle> {
        Err(HarnessError::AdmissionRefused {
            reason: "SIGNED_IN_CONTAINMENT_UNAVAILABLE".into(),
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
        Box::pin(futures::stream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_harness_core::AgentSessionId;

    #[tokio::test]
    async fn no_direct_start_or_send_can_bypass_containment_refusal() {
        for provider in ["codex", "cursor", "agy", "antigravity"] {
            assert!(SignedInCliAdapter::new(
                provider.into(),
                "/absent/provider".into(),
                "fixture".into()
            )
            .err()
            .unwrap()
            .contains("SIGNED_IN_CONTAINMENT_UNAVAILABLE"));
        }
        let adapter = SignedInCliAdapter {
            provider: "codex".into(),
            executable: "/absent/provider".into(),
        };
        let session_id = AgentSessionId::new("unadmitted");
        let error = adapter
            .start(StartSession {
                session_id: session_id.clone(),
                workdir: "/absent/work".into(),
                artifact_dir: "/absent/artifacts".into(),
                model: None,
                structured_schema: None,
                max_budget_usd: None,
                wall_timeout: std::time::Duration::from_secs(1),
            })
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("SIGNED_IN_CONTAINMENT_UNAVAILABLE"));
        let session = SessionHandle {
            session_id,
            provider: "codex".into(),
            native_session_id: None,
        };
        assert!(adapter
            .send(
                &session,
                Turn {
                    prompt: "unadmitted".into()
                }
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("SIGNED_IN_CONTAINMENT_UNAVAILABLE"));
        assert_eq!(futures::StreamExt::count(adapter.events(&session)).await, 0);
    }
}
