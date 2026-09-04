//! Application services: commands, materializer, leases, queue, demo.

pub mod audit_batch;
pub mod authority;
pub mod authority_revision;
pub mod authority_scope;
pub mod candidate_preparation;
pub mod command_dispatch;
pub mod commands;
pub mod conformance;
pub mod conformance_effects;
pub mod context;
pub mod demo;
pub mod dogfood;
pub mod dogfood_produce;
#[cfg(feature = "dogfood-claude")]
pub mod dogfood_run;
pub mod effect_recovery;
pub mod effect_state;
pub mod effects;
pub mod graph_delta;
pub mod launch_grant;
pub mod lease_transport;
pub mod leases;
pub mod live_conformance;
pub mod materializer;
pub mod memory;
pub mod mutation_reservation;
pub mod nonce_ledger;
pub mod policy_snapshot;
pub mod queue;
pub mod records;
pub mod simulators;
pub mod store;

pub use audit_batch::{
    verify_batch, verify_chain, AuditBatchBuilder, AuditBatchError, AuditChainHead,
};
pub use authority::{check_active_lease_snapshot, ActiveLeaseSubject};
pub use authority_revision::{AuthorityRevisionError, NormalizedAuthority};
pub use authority_scope::{
    prepare_authority_scope_admission, AuthorityScopeAdmission, AuthorityScopeError,
    AuthorityScopeStore, PreparedAuthorityScopeAdmission, AUTHORITY_SCOPE_ENVELOPE_CLASS,
};
pub use candidate_preparation::{
    CandidatePreparationAuthoritySnapshot, CandidatePreparationError, CandidatePreparationIssuer,
    CandidatePreparationNonceStore, CandidatePreparationSource, CandidatePreparationStore,
    CandidatePreparationTransaction, LedgerCandidatePreparationIssuer,
    PreparedCandidatePreparationGrant, RegisteredCandidatePreparationSource,
    StoreCandidatePreparationNonceLedger, StoredCandidatePreparationGrant,
};
pub use command_dispatch::{
    CommandDispatchClaim, CommandDispatchDisposition, CommandDispatchError, CommandDispatchStore,
    ComponentCommandCompletionV1, COMMAND_DISPATCH_CLAIM_SCHEMA,
    COMPONENT_COMMAND_COMPLETION_SCHEMA, COMPONENT_EVIDENCE_CLASS, COMPONENT_SIGNING_TRUST,
};
pub use commands::{CommandRecord, CommandRequest};
pub use context::{
    initial_context_capsules, validate_initial_context_set, ContextCapsule,
    INITIAL_CONTEXT_CAPSULE_SCHEMA,
};
pub use demo::{derive_receipt, run_demo, DemoReceipt};
pub use dogfood::{
    write_receipt as write_dogfood_receipt, DogfoodError, DogfoodReadOnlyIntentV0,
    DogfoodReadOnlyReceiptV0,
};
#[cfg(feature = "dogfood-claude")]
pub use dogfood_run::{
    run_dogfood_read_only, CredentialSpec, DogfoodReadOnlyOptions, DogfoodRunError,
    DogfoodRunStatus,
};
pub use effect_recovery::{
    EffectRecoveryAuthority, EffectRecoveryClaim, EffectRecoveryContainmentReason,
    EffectRecoveryDisposition, EffectRecoveryError, EffectRecoveryObservation, EffectRecoveryStore,
    EffectRecoveryTransition, CANDIDATE_REF_PREFIX, EFFECT_RECOVERY_AUTHORITY_SCHEMA,
    EFFECT_RECOVERY_CLAIM_SCHEMA, EFFECT_RECOVERY_TRANSITION_SCHEMA, LOCAL_BARE_RECOVERY_PROVIDER,
    MAX_CREATE_RECOVERY_RETRIES,
};
pub use effect_state::EffectState;
pub use effects::{
    receipt_id, recovery_receipt_id, EffectIntentRecord, EffectReceiptRecord, ReceiptVerdict,
    ZERO_OID,
};
pub use graph_delta::{apply_graph_delta, graph_digest, GraphDelta, GraphOp};
pub use launch_grant::{
    LaunchGrantIssueError, LaunchGrantIssuer, LaunchGrantNonceRecord, LaunchGrantNonceStore,
    LaunchGrantRequest, LedgerLaunchGrantIssuer, StoreNonceLedger, StoredLaunchGrantNonce,
};
#[cfg(any(test, feature = "test-seams"))]
pub use lease_transport::SignedLeaseService;
#[cfg(any(test, feature = "test-seams"))]
pub use lease_transport::{issue_operation_permit, issue_permit};
pub use lease_transport::{SignedAcquireBody, SignedLeaseError};
pub use leases::LeaseService;
pub use live_conformance::{
    run_live_conformance, LiveConformanceError, LiveConformanceOptions, LiveConformanceRun,
};
#[cfg(any(test, feature = "test-seams"))]
pub use materializer::materialize_synthetic_selection;
pub use materializer::{materialize_plan, PlanInput};
pub use memory::MemoryLedger;
pub use mutation_reservation::{
    LeaseGate, MutationReservationStore, MutationReserveRequest, OneUsePermit, ReservationError,
};
pub use nonce_ledger::{IssuedNonce, MemoryNonceLedger, NonceError, NonceLedger, NonceState};
pub use policy_snapshot::{load_policy, load_policy_from_environment, LoadedPolicy};
pub use queue::{claim_ready, ready_queue, ReadyItem};
pub use records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReadyRow, ReleaseRequest, StoredGraph,
};
pub use simulators::{ProviderSimulator, ScmSimulator, SimulatedInvocation};
pub use store::{Ledger, LedgerError};
