//! Pure Bullet Farm domain. No I/O, env, or clocks that mutate.

pub mod authority;
pub mod behavior;
pub mod digest;
pub mod entities;
pub mod error;
pub mod gates;
pub mod ids;
pub mod mutation_guard;
pub mod observation;
pub mod schema_bundle;
pub mod states;
pub mod taxonomy;

pub use authority::AuthorityToken;
pub use behavior::{default_catalog, reject_worktree, BehaviorRule, Enforcement};
pub use digest::Digest;
pub use entities::{
    AcceptanceRequirement, Attempt, Candidate, Effect, Evidence, Mission, PlanRevision, Variant,
    WorkPackage,
};
pub use error::DomainError;
pub use gates::{
    gate_definition, parse_gate_ids, EvidenceTier, GateDefinition, GateId, GateOutcome,
    MAX_GATE_IDS, MAX_GATE_ID_BYTES, REASON_ZERO_TESTS, REPOSITORY_GATE_ID,
};
pub use ids::*;
pub use mutation_guard::{MutationContext, MutationGuard, MutationRefusal};
pub use observation::Observation;
pub use states::{AttemptState, CommandPhase, MissionState, WorkPackageState};
pub use taxonomy::{ModelTier, TaskClass, TaskClassification};
