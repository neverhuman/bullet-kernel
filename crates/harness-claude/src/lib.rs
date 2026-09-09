//! Offline Claude Code bidirectional stream-JSON contract adapter.
//!
//! This crate never executes `claude` on its own authority.
//! [`ClaudeStreamTranscript`] is a pure state machine for one frozen
//! test-vector message subset. The adapter's session creation, dispatch,
//! interruption, and termination remain blocked until signed admission and
//! provider-only egress are wired; [`probe::probe_claude`] runs one granted,
//! contained `--version` probe from explicit inputs and never admits anything.

pub mod dispatch;
pub mod dogfood;
mod parse;
pub mod probe;
mod protocol;
pub mod session;

pub use probe::{
    probe_claude, probe_deadline_ms, ProbeContainment, ProbeInput, ProbeRefusal,
    MAX_PROBE_DEADLINE_MS, NO_PROMPT_FREE_HELLO, PROBE_ARGUMENT, REQUIRED_CONTAINMENT,
};
pub use protocol::{
    ClaudeStreamOutcome, ClaudeStreamTranscript, TranscriptProfile, DOGFOOD_MAX_ASSISTANT_MESSAGES,
    DOGFOOD_MAX_STREAM_JSON_FRAMES, MAX_ASSISTANT_CONTENT_ITEMS, MAX_ASSISTANT_MESSAGES,
    MAX_STREAM_JSON_FRAMES, MAX_STREAM_JSON_FRAME_BYTES, OBSERVED_CLAUDE_SCHEMA_VERSION,
    READ_ONLY_TOOL_ALLOWLIST,
};
pub use session::{
    ClaudeSession, DispatchCleared, LaunchRecord, SessionConfig, SessionError, SessionPhase,
    TurnRecord, TurnTicket,
};

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AuthChallenge, Capability, CapabilityMatrix, CapabilityState, CompactRequest,
    ContextTransition, HarnessAdapter, HarnessDescriptor, HarnessError, HarnessEventStream,
    HarnessResult, ModelSnapshot, PermissionDecision, PlanDecision, ProbeResult, ProfileRef,
    PromotionStage, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle,
    StartSession, SteeringMessage, Turn, TurnHandle,
};

/// Provider wire name.
pub const PROVIDER: &str = "claude";
/// Exact executable basename expected by future runtime admission.
pub const BINARY: &str = "claude";

/// Offline-only Claude stream-JSON contract adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeAdapter;

impl ClaudeAdapter {
    /// Construct the offline contract adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn blocked() -> HarnessError {
    HarnessError::AdmissionBlocked {
        blocker: "SIGNED_ADMISSION_UNAVAILABLE".to_string(),
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
}

#[async_trait::async_trait]
impl HarnessAdapter for ClaudeAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: BINARY.to_string(),
            version: Observation::Unknown {
                source: "runtime admission".to_string(),
                reason: format!(
                    "no executable is admitted; offline schema observation is {OBSERVED_CLAUDE_SCHEMA_VERSION}"
                ),
            },
            stage: PromotionStage::ContractPass,
            capabilities: capabilities(),
        }
    }

    async fn probe(&self, _profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        Err(blocked())
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

    async fn start(&self, _request: StartSession) -> HarnessResult<SessionHandle> {
        Err(blocked())
    }

    async fn resume(&self, _request: ResumeSession) -> HarnessResult<SessionHandle> {
        Err(unsupported(PROVIDER, "resume"))
    }

    async fn send(&self, _session: &SessionHandle, _turn: Turn) -> HarnessResult<TurnHandle> {
        Err(blocked())
    }

    async fn steer(
        &self,
        _session: &SessionHandle,
        _message: SteeringMessage,
    ) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "steer"))
    }

    async fn approve_local_plan(
        &self,
        _session: &SessionHandle,
        _decision: PlanDecision,
    ) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "approve_local_plan"))
    }

    async fn respond_permission(
        &self,
        _session: &SessionHandle,
        _decision: PermissionDecision,
    ) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "respond_permission"))
    }

    async fn compact(
        &self,
        _session: &SessionHandle,
        _request: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        Err(unsupported(PROVIDER, "compact"))
    }

    async fn checkpoint(&self, _session: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        Err(unsupported(PROVIDER, "checkpoint"))
    }

    async fn interrupt(&self, _session: &SessionHandle) -> HarnessResult<Ack> {
        Err(blocked())
    }

    async fn terminate(&self, _session: &SessionHandle) -> HarnessResult<Ack> {
        Err(blocked())
    }

    fn events(&self, _session: &SessionHandle) -> HarnessEventStream {
        Box::pin(tokio_stream::empty())
    }
}

impl bullet_harness_core::LiveDispatcher for ClaudeAdapter {
    fn provider(&self) -> &str {
        PROVIDER
    }

    fn descriptor(&self) -> HarnessDescriptor {
        <Self as HarnessAdapter>::descriptor(self)
    }

    fn observed_runtime_version(&self) -> &str {
        OBSERVED_CLAUDE_SCHEMA_VERSION
    }

    fn required_protocol(&self) -> bullet_harness_core::ProviderProtocol {
        bullet_harness_core::ProviderProtocol::ClaudeStreamJson
    }

    /// The port carries only the grant and cannot reach the enrollment
    /// record, the prepared egress-denied boundary, canaries, or a clock, so
    /// it refuses `RUNTIME_PROBE_UNAVAILABLE` without spawning. ADMIT-1 must
    /// call [`probe::probe_claude`] with a full [`ProbeInput`] instead.
    fn observe_runtime_probe(
        &self,
        grant: &bullet_harness_core::live::ProbeGrantEvidence,
    ) -> Result<
        bullet_harness_core::live::RuntimeProbeObservation,
        bullet_harness_core::live::RuntimeProbeError,
    > {
        Err(probe::port_refusal(grant))
    }

    fn dispatch_live_turn(
        &self,
        admission: &bullet_harness_core::EvaluatedAdmission,
        factory: &bullet_harness_core::CommandFactory<'_>,
        request: &bullet_harness_core::LiveTurnRequest,
    ) -> Result<bullet_harness_core::LiveTurnOutcome, HarnessError> {
        dispatch::dispatch_live_turn(admission, factory, request)
    }
}
