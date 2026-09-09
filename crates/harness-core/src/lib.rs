//! Harness core: the `HarnessAdapter` trait (spec s8.4), the 24-capability
//! matrix (s8.3), the `AgentEvent` envelope (s18.3), the session state
//! machine (s18.2), the `PatchProposal` contract, guarded argv construction,
//! and the shared conformance suite (s42). No provider-specific code.

pub mod adapter;
pub mod admission;
pub mod argv;
pub mod candidate_preparation;
pub mod capability;
pub mod conformance;
pub mod error;
pub mod event;
pub mod ids;
pub mod launch_grant;
pub mod lease_transport;
pub mod live;
pub mod probe;
pub mod proposal;
pub mod runtime_passport;
pub mod session;
pub mod spawnrun;
pub mod store;
pub mod strict_json;
pub mod transaction_proof;

pub use adapter::{
    unsupported, Ack, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter,
    HarnessDescriptor, HarnessEventStream, HarnessResult, ModelSnapshot, PermissionDecision,
    PlanDecision, QuotaObservation, ResumeSession, SessionCheckpoint, SessionHandle, StartSession,
    SteeringMessage, Turn, TurnHandle,
};
pub use admission::{
    capability_digest, descriptor_digest, environment_digest, executable_digest,
    mutation_operation_audience, parse_mutation_operation, require_signed_mutation_permit,
    AdmissionBlocker, AuthorityAudience, CanarySecrets, ConformanceEvidence, CredentialGrant,
    CredentialReceipt, EgressIsolationEvidence, EgressIsolationRecord, EgressProbe,
    EgressProbeOutcome, EvaluatedAdmission, MutationOperation, MutationPermitClaims,
    MutationPermitExpectation, MutationPermitSigningKey, MutationPermitVerificationKey,
    PreparedProviderHome, ProtocolRequirement, ProviderAdmission, ProviderAdmissionPolicy,
    ProviderConformanceReceipt, ProviderProtocol, RuntimeProbeSnapshot, SignedAuthorityRecord,
    SignedMutationPermit, MAX_MUTATION_PERMIT_TTL_MS, MUTATION_PERMIT_IMPLICIT_ASSERTION,
    MUTATION_PERMIT_SCHEMA_VERSION,
};
pub use argv::{filter_env, ArgvBuilder, InvocationBudget, PreparedInvocation};
pub use candidate_preparation::{
    authenticate_candidate_preparation_grant, candidate_preparation_scope_paths_digest,
    decode_signed_candidate_preparation_grant, verify_candidate_preparation_grant,
    CandidateNonceConsumption, CandidatePreparationExpectation, CandidatePreparationGrantV1,
    CandidatePreparationNonceLedger, CandidatePreparationSigningKey,
    CandidatePreparationVerificationKey, MemoryCandidatePreparationNonceLedger,
    SignedCandidatePreparationGrantV1, VerifiedCandidatePreparationGrant,
};
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
pub use lease_transport::{
    request_digest, verify_lease_permit, LeaseTransportClaims, LeaseTransportError,
    LeaseTransportExpectation, LeaseTransportOperation, LeaseTransportSigningKey,
    LeaseTransportVerificationKey, SignedLeasePermit, VerifiedLeasePermit,
    LEASE_TRANSPORT_AUDIENCE, LEASE_TRANSPORT_SCHEMA_VERSION,
};
pub use live::{
    capture_turn, is_pong, run_interactive, scan_events, CommandFactory, EgressBackend,
    InteractiveReaction, LineHandler, LiveConformanceReceipt, LiveDispatcher, LiveOutcome,
    LiveStep, LiveStepRecord, LiveTurnOutcome, LiveTurnRequest, PreparedEgress, RawCapture,
    RuntimeConformanceObservation, StepLog, StepStatus, CONFORMANCE_EXPECTED_RESPONSE,
    CONFORMANCE_PROMPT, LIVE_CONFORMANCE_SCHEMA_VERSION,
};
pub use probe::{ExpectedProfile, ProbeResult, ProfileIdentity, ProfileRef};
pub use proposal::{PatchMutation, PatchOperation, PatchProposal, Preimage};
pub use runtime_passport::inspection::{inspect_provider_runtime, InspectedProviderRuntimeV1};
pub use runtime_passport::{
    ProviderRuntimePassportV1, RuntimeExecutionV1, RuntimeFileRoleV1, RuntimeFileV1,
    RuntimeLoaderV1, RuntimePassportError, MAX_RUNTIME_FILES, MAX_RUNTIME_FILE_BYTES,
    MAX_RUNTIME_RELATIVE_PATH_BYTES, MAX_RUNTIME_TOTAL_BYTES, MAX_RUNTIME_VERSION_BYTES,
    RUNTIME_DEPLOYMENT_PREFIX, RUNTIME_PASSPORT_DOMAIN, RUNTIME_PASSPORT_ID_PREFIX,
    RUNTIME_PASSPORT_SCHEMA_VERSION,
};
pub use session::SessionState;
pub use spawnrun::{
    kill_process_group, run_supervised, run_to_completion, PidSlot, RunOutcome, RunStop,
    SupervisedOutcome, SupervisionSignal,
};
pub use store::{SessionEntry, SessionStore};
pub use strict_json::decode_strict_json;
pub use transaction_proof::{
    verify_transaction_component, SignedTransactionComponent, TransactionComponentSigningKey,
    TransactionComponentSubject, TRANSACTION_COMPONENT_CLASS, TRANSACTION_COMPONENT_SCHEMA_VERSION,
    TRANSACTION_COMPONENT_TRUST,
};
