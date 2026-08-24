//! Pure Bullet Farm domain. No I/O, env, or clocks that mutate.

pub mod authority;
pub mod behavior;
pub mod digest;
pub mod entities;
pub mod error;
pub mod gates;
pub mod ids;
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
pub use gates::{EvidenceTier, GateOutcome, REASON_ZERO_TESTS};
pub use ids::*;
pub use observation::Observation;
pub use states::{AttemptState, CommandPhase, MissionState, WorkPackageState};
pub use taxonomy::{ModelTier, TaskClass, TaskClassification};
