//! Harness core: the `HarnessAdapter` trait (spec s8.4), the 24-capability
//! matrix (s8.3), the `AgentEvent` envelope (s18.3), the session state
//! machine (s18.2), the `PatchProposal` contract, guarded argv construction,
//! and the shared conformance suite (s42). No provider-specific code.

pub mod adapter;
pub mod argv;
pub mod capability;
pub mod conformance;
pub mod error;
pub mod event;
pub mod ids;
pub mod probe;
pub mod proposal;
pub mod session;
pub mod spawnrun;
pub mod store;

pub use adapter::{
    unsupported, Ack, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter,
    HarnessDescriptor, HarnessEventStream, HarnessResult, ModelSnapshot, PermissionDecision,
    PlanDecision, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle, StartSession,
    SteeringMessage, Turn, TurnHandle,
};
pub use argv::{
    filter_env, live_admission_granted, ArgvBuilder, InvocationBudget, PreparedInvocation,
    LIVE_ADMISSION_TOKEN, LIVE_ADMISSION_VAR,
};
pub use capability::{Capability, CapabilityMatrix, CapabilityState, PromotionStage};
pub use error::HarnessError;
pub use event::{
    AgentEvent, AgentEventKind, AgentEventPayload, ArtifactRef, EventNormalizer, NativeMeta,
};
pub use ids::{synthetic_uuid, AgentSessionId, EventId, InvocationId};
pub use probe::{ExpectedProfile, ProbeResult, ProfileIdentity, ProfileRef};
pub use proposal::{ChangeOp, FileChange, PatchProposal};
pub use session::SessionState;
pub use spawnrun::{kill_process_group, run_to_completion, PidSlot, RunOutcome};
pub use store::{SessionEntry, SessionStore};
