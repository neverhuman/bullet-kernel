//! Codex App Server contract adapter.
//!
//! This crate deliberately does not spawn `codex`. [`CodexAppServerTranscript`]
//! is a pure JSONL protocol machine used by offline conformance tests. Runtime
//! probing and dispatch remain blocked until Kernel supplies signed admission
//! and an audited provider-only egress boundary.

pub mod dispatch;
mod parse;
mod protocol;

pub use protocol::{AppServerOutcome, CodexAppServerTranscript};

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AuthChallenge, Capability, CapabilityMatrix, CapabilityState, CompactRequest,
    ContextTransition, HarnessAdapter, HarnessDescriptor, HarnessError, HarnessEventStream,
    HarnessResult, ModelSnapshot, PermissionDecision, PlanDecision, ProbeResult, ProfileRef,
    PromotionStage, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle,
    StartSession, SteeringMessage, Turn, TurnHandle,
};

/// Provider wire name.
pub const PROVIDER: &str = "codex";
/// Exact executable basename expected by runtime admission.
pub const BINARY: &str = "codex";

/// Offline-only Codex App Server contract adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAdapter;

impl CodexAdapter {
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
        .with(
            Capability::TurnInterrupt,
            CapabilityState::SupportedWithLimitations,
        )
}

#[async_trait::async_trait]
impl HarnessAdapter for CodexAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: BINARY.to_string(),
            version: Observation::Unknown {
                source: "runtime admission".to_string(),
                reason: "exact canonical binary/version has not been admitted".to_string(),
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

impl bullet_harness_core::LiveDispatcher for CodexAdapter {
    fn provider(&self) -> &str {
        PROVIDER
    }

    fn descriptor(&self) -> HarnessDescriptor {
        <Self as HarnessAdapter>::descriptor(self)
    }

    fn observed_runtime_version(&self) -> &str {
        dispatch::CODEX_OBSERVED_RUNTIME_VERSION
    }

    fn required_protocol(&self) -> bullet_harness_core::ProviderProtocol {
        bullet_harness_core::ProviderProtocol::CodexAppServerJsonl
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
