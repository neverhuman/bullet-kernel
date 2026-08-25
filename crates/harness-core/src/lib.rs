//! Harness core: the `HarnessAdapter` trait (spec s8.4), the 24-capability
//! matrix (s8.3), the `AgentEvent` envelope (s18.3), the session state
//! machine (s18.2), the `PatchProposal` contract, guarded argv construction,
//! and the shared conformance suite (s42). No provider-specific code.

pub mod adapter;
pub mod admission;
pub mod argv;
pub mod capability;
pub mod conformance;
pub mod error;
pub mod event;
pub mod ids;
pub mod launch_grant;
pub mod probe;
pub mod proposal;
pub mod session;
pub mod spawnrun;
pub mod store;
pub mod strict_json;

pub use adapter::{
    unsupported, Ack, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter,
    HarnessDescriptor, HarnessEventStream, HarnessResult, ModelSnapshot, PermissionDecision,
    PlanDecision, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle, StartSession,
    SteeringMessage, Turn, TurnHandle,
};
pub use admission::{
    capability_digest, descriptor_digest, environment_digest, executable_digest, AdmissionBlocker,
    CanarySecrets, ConformanceEvidence, CredentialGrant, CredentialReceipt,
    EgressIsolationEvidence, EgressIsolationRecord, EgressProbe, EgressProbeOutcome,
    EvaluatedAdmission, ProtocolRequirement, ProviderAdmission, ProviderAdmissionPolicy,
    ProviderConformanceReceipt, ProviderProtocol, RuntimeProbeSnapshot, SignedAuthorityRecord,
};
pub use argv::{filter_env, ArgvBuilder, InvocationBudget, PreparedInvocation};
pub use capability::{Capability, CapabilityMatrix, CapabilityState, PromotionStage};
pub use error::HarnessError;
pub use event::{
    AgentEvent, AgentEventKind, AgentEventPayload, ArtifactRef, EventNormalizer, NativeMeta,
};
pub use ids::{synthetic_uuid, AgentSessionId, EventId, InvocationId};
pub use launch_grant::{
    verify_launch_grant, LaunchGrantClaims, LaunchGrantExpectation, LaunchGrantNonceLedger,
    LaunchGrantSigningKey, LaunchGrantVerificationKey, LeaseBinding, MemoryNonceLedger,
    NonceConsumption, PolicyBinding, ProviderBinding, SignedLaunchGrant, VerifiedLaunchGrant,
};
pub use probe::{ExpectedProfile, ProbeResult, ProfileIdentity, ProfileRef};
pub use proposal::{ChangeOp, FileChange, PatchProposal};
pub use session::SessionState;
pub use spawnrun::{
    kill_process_group, run_supervised, run_to_completion, PidSlot, RunOutcome, RunStop,
    SupervisedOutcome, SupervisionSignal,
};
pub use store::{SessionEntry, SessionStore};
pub use strict_json::decode_strict_json;
