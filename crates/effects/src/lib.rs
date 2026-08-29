//! Effect and delivery plane (spec section 23): durable intents unique on
//! `(provider, logical_effect_key)`, a typed state machine where a lost
//! response is `OUTCOME_UNKNOWN`, read-back verified receipts, and
//! reconcile-before-retry by construction.

pub mod attest;
pub mod broker;
pub mod durable;
pub mod error;
pub mod forge;
pub mod git_env;
pub mod github;
pub mod gitlab;
pub mod integration;
pub mod jeryu;
pub mod local;
mod local_integration;
mod local_state;
pub mod lost;
pub mod observation;
pub mod recovery;

pub use attest::{attestor_push, broker_attest, validate_attestation_request, AttestorCredential};
pub use broker::{authorize, dispatch, propose, reconcile, IntentInput, ReconcileOutcome};
pub use bullet_application::{
    receipt_id, EffectIntentRecord, EffectReceiptRecord, EffectState, ReceiptVerdict, ZERO_OID,
};
pub use durable::{DurableJob, DurableQueue};
pub use error::EffectsError;
pub use forge::{
    is_create, require_candidate_ref, require_oid, ForgeDescriptor, ForgeEffects, PushRequest,
    CANDIDATE_REF_PREFIX,
};
pub use github::{GitHubForge, GITHUB_PROVIDER};
pub use gitlab::{GitLabForge, GitLabProfile, GITLAB_PROVIDER};
pub use integration::{
    require_probed, Capability, CheckPublication, CheckReceipt, ForgeIntegration,
    IntegrationDescriptor, IntegrationReceipt, IntegrationSubject, IntegrationSubjectRequest,
    MergeGroupSubject, ProtectedIntegrationRequest, ProtectionState,
};
pub use jeryu::{JeryuForge, JERYU_BASE_URL, JERYU_PROVIDER};
pub use local::{LocalBareForge, LOCAL_PROVIDER};
pub use lost::{LossMode, LostResponseForge};
pub use observation::{
    canonical_observation_bytes, decode_and_verify_fixture_observation, FixtureObserverSigningKey,
    FixtureObserverVerificationKey, ObservationError, ObservationInputV1, ObservationOutcomeV1,
    ObservationSubjectV1, ObservationV1, SignedObservationV1,
};
pub use recovery::{reconcile_local_bare_restart, RestartReconcileOutcome, RestartRecoveryError};
