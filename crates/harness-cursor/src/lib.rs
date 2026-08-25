//! Offline Cursor ACP contract adapter.
//!
//! Cursor documents `agent acp` as ACP v1 JSON-RPC over JSONL. This crate
//! deliberately does not start that process. [`CursorAcpTranscript`] is a
//! pure protocol machine; live use remains blocked until signed admission and
//! the Bullet typed-proposal ACP extension are independently proved.

pub mod dispatch;
mod parse;
mod protocol;

pub use parse::{CursorAcpOutcome, CursorAcpTranscript};

use bullet_domain::Observation;
use bullet_harness_core::{
    unsupported, Ack, AuthChallenge, Capability, CapabilityMatrix, CapabilityState, CompactRequest,
    ContextTransition, HarnessAdapter, HarnessDescriptor, HarnessError, HarnessEventStream,
    HarnessResult, ModelSnapshot, PermissionDecision, PlanDecision, ProbeResult, ProfileRef,
    PromotionStage, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle,
    StartSession, SteeringMessage, Turn, TurnHandle,
};

/// Provider wire name.
pub const PROVIDER: &str = "cursor";
/// Cursor's currently documented executable name.
pub const BINARY: &str = "agent";

/// Offline-only Cursor ACP contract adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct CursorAdapter;

impl CursorAdapter {
    /// Construct the offline contract adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn blocked() -> HarnessError {
    HarnessError::AdmissionBlocked {
        blocker: "CURSOR_ACP_TYPED_PROPOSAL_UNPROVED".to_string(),
    }
}

fn capabilities() -> CapabilityMatrix {
    CapabilityMatrix::new()
        .with(Capability::StructuredEvents, CapabilityState::Supported)
        .with(
            Capability::StructuredOutputSchema,
            CapabilityState::Experimental,
        )
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(Capability::TurnInterrupt, CapabilityState::Unsupported)
}

#[async_trait::async_trait]
impl HarnessAdapter for CursorAdapter {
    fn descriptor(&self) -> HarnessDescriptor {
        HarnessDescriptor {
            provider: PROVIDER.to_string(),
            binary: BINARY.to_string(),
            version: Observation::Unknown {
                source: "runtime admission".to_string(),
                reason: "exact Cursor ACP binary/version has not been admitted".to_string(),
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

    async fn interrupt(&self, _session: &SessionHandle) -> HarnessResult<Ack> {
        Err(unsupported(PROVIDER, "interrupt"))
    }

    async fn terminate(&self, _session: &SessionHandle) -> HarnessResult<Ack> {
        Err(blocked())
    }

    fn events(&self, _session: &SessionHandle) -> HarnessEventStream {
        Box::pin(tokio_stream::empty())
    }
}

impl bullet_harness_core::LiveDispatcher for CursorAdapter {
    fn provider(&self) -> &str {
        PROVIDER
    }

    fn descriptor(&self) -> HarnessDescriptor {
        <Self as HarnessAdapter>::descriptor(self)
    }

    fn observed_runtime_version(&self) -> &str {
        dispatch::CURSOR_OBSERVED_RUNTIME_VERSION
    }

    fn required_protocol(&self) -> bullet_harness_core::ProviderProtocol {
        bullet_harness_core::ProviderProtocol::CursorAcp
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
