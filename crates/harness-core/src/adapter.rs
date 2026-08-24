//! The `HarnessAdapter` trait (spec s8.4 verbatim method set) and its
//! request/response types. Methods a provider cannot honestly perform return
//! a typed `Unsupported` error, never a panic.

use crate::capability::{CapabilityMatrix, PromotionStage};
use crate::error::HarnessError;
use crate::event::AgentEvent;
use crate::ids::{AgentSessionId, InvocationId};
use crate::probe::{ProbeResult, ProfileRef};
use crate::session::SessionState;
use bullet_domain::Observation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

/// Result alias for adapter calls.
pub type HarnessResult<T> = Result<T, HarnessError>;

/// Stream of normalized envelopes for one session.
pub type HarnessEventStream = Pin<Box<dyn futures::Stream<Item = AgentEvent> + Send>>;

/// Static description of one adapter build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessDescriptor {
    /// Provider name (e.g. `claude`).
    pub provider: String,
    /// Executable name.
    pub binary: String,
    /// Observed binary version; Unknown until probed.
    pub version: Observation<String>,
    /// s42 promotion stage of this adapter build.
    pub stage: PromotionStage,
    /// Complete 24-capability matrix.
    pub capabilities: CapabilityMatrix,
}

/// Reduced model snapshot (spec s8.2 identity fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSnapshot {
    /// Provider-native model id.
    pub provider_model_id: String,
    /// Display name.
    pub display_name: String,
    /// Context window when reported.
    pub context_window: Option<u64>,
    /// When this snapshot was observed.
    pub observed_at: DateTime<Utc>,
}

/// One quota dimension observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaObservation {
    /// Dimension name.
    pub dimension: String,
    /// Remaining amount; Unknown is an honest answer.
    pub remaining: Observation<String>,
    /// Probe identity.
    pub source: String,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
}

/// Structured login challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Provider name.
    pub provider: String,
    /// Operator instructions.
    pub instructions: String,
}

/// Request to start a fresh session.
#[derive(Clone, Debug)]
pub struct StartSession {
    /// Kernel session id.
    pub session_id: AgentSessionId,
    /// Child working directory (the private clone).
    pub workdir: PathBuf,
    /// Directory for raw transcripts and schema files.
    pub artifact_dir: PathBuf,
    /// Model override when supported.
    pub model: Option<String>,
    /// JSON schema to enforce on structured output.
    pub structured_schema: Option<Value>,
    /// Spend cap where the provider supports one.
    pub max_budget_usd: Option<f64>,
    /// Wall-clock bound per invocation.
    pub wall_timeout: Duration,
}

/// Request to resume a native session.
#[derive(Clone, Debug)]
pub struct ResumeSession {
    /// Kernel session id.
    pub session_id: AgentSessionId,
    /// Provider-native session id to resume.
    pub native_session_id: String,
    /// Child working directory.
    pub workdir: PathBuf,
    /// Directory for raw transcripts.
    pub artifact_dir: PathBuf,
    /// Spend cap where supported.
    pub max_budget_usd: Option<f64>,
    /// Wall-clock bound per invocation.
    pub wall_timeout: Duration,
}

/// One prompt turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Turn {
    /// Prompt text.
    pub prompt: String,
}

/// Mid-turn guidance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteeringMessage {
    /// Guidance text.
    pub text: String,
}

/// Local plan approval decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDecision {
    /// Approve or reject.
    pub approved: bool,
    /// Optional note.
    pub note: Option<String>,
}

/// Permission decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDecision {
    /// Allow or deny.
    pub allow: bool,
    /// Optional scope note.
    pub scope: Option<String>,
}

/// Compaction request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRequest {
    /// Optional compaction instructions.
    pub instructions: Option<String>,
}

/// Result of a context transition (spec s8.4 `compact` return).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextTransition {
    /// What the transition did.
    pub summary: String,
}

/// Point-in-time session checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    /// Kernel session id.
    pub session_id: AgentSessionId,
    /// State at checkpoint time.
    pub state: SessionState,
    /// Native session id when known.
    pub native_session_id: Option<String>,
    /// Envelopes recorded so far.
    pub event_count: u64,
}

/// Simple acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// True when the request took effect.
    pub acknowledged: bool,
}

/// Opaque handle to a started session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandle {
    /// Kernel session id.
    pub session_id: AgentSessionId,
    /// Provider name.
    pub provider: String,
    /// Provider-native session id when known.
    pub native_session_id: Option<String>,
}

/// Opaque handle to one executed turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnHandle {
    /// Invocation id.
    pub invocation_id: InvocationId,
    /// Provider process exit code when it finished.
    pub exit_code: Option<i32>,
    /// True when the wall-clock bound killed the invocation.
    pub timed_out: bool,
}

/// Typed refusal for an unimplemented method.
#[must_use]
pub fn unsupported(provider: &str, method: &'static str) -> HarnessError {
    HarnessError::Unsupported {
        provider: provider.to_string(),
        method,
    }
}

/// Provider adapter contract (spec s8.4 method set, verbatim names).
#[async_trait::async_trait]
pub trait HarnessAdapter: Send + Sync {
    /// Static descriptor: provider, binary, capability matrix, stage.
    fn descriptor(&self) -> HarnessDescriptor;
    /// Probe binary version and effective identity (s8.6).
    async fn probe(&self, profile: &ProfileRef) -> HarnessResult<ProbeResult>;
    /// List available models.
    async fn list_models(&self, profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>>;
    /// Observe quota dimensions.
    async fn observe_quota(&self, profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>>;
    /// Begin a login challenge.
    async fn begin_login(&self, profile: &ProfileRef) -> HarnessResult<AuthChallenge>;
    /// Start a fresh session.
    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle>;
    /// Resume a native session.
    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle>;
    /// Execute one turn.
    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle>;
    /// Inject mid-turn guidance.
    async fn steer(&self, session: &SessionHandle, message: SteeringMessage) -> HarnessResult<Ack>;
    /// Approve or reject a local plan.
    async fn approve_local_plan(
        &self,
        session: &SessionHandle,
        decision: PlanDecision,
    ) -> HarnessResult<Ack>;
    /// Answer a permission request.
    async fn respond_permission(
        &self,
        session: &SessionHandle,
        decision: PermissionDecision,
    ) -> HarnessResult<Ack>;
    /// Compact the session context.
    async fn compact(
        &self,
        session: &SessionHandle,
        request: CompactRequest,
    ) -> HarnessResult<ContextTransition>;
    /// Write a checkpoint.
    async fn checkpoint(&self, session: &SessionHandle) -> HarnessResult<SessionCheckpoint>;
    /// Interrupt the running turn; termination must be bounded.
    async fn interrupt(&self, session: &SessionHandle) -> HarnessResult<Ack>;
    /// Terminate the session; kills any live process group.
    async fn terminate(&self, session: &SessionHandle) -> HarnessResult<Ack>;
    /// Snapshot stream of the session's normalized envelopes.
    fn events(&self, session: &SessionHandle) -> HarnessEventStream;
}
