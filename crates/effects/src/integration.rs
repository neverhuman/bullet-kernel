//! Integration-authority operations additive over [`ForgeEffects`].
//! Every method may refuse. `Unprobed` never authorizes a dispatch.

use crate::error::EffectsError;
use crate::forge::ForgeEffects;
use serde::{Deserialize, Serialize};

/// Four-valued capability. `Unprobed` is the default and is not permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Adapter proved it can do this.
    Supported,
    /// Adapter can approximate; the note names the limitation.
    SupportedWithLimitations(&'static str),
    /// Adapter structurally cannot.
    Unsupported,
    /// Not probed. Must not authorize.
    Unprobed,
}

impl Capability {
    /// Whether a dispatch may proceed.
    #[must_use]
    pub const fn authorizes(self) -> bool {
        matches!(self, Self::Supported | Self::SupportedWithLimitations(_))
    }
}

/// Probed integration surface. Never assumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationDescriptor {
    /// Expected-old-OID compare-and-swap on push.
    pub exact_oid_cas: Capability,
    /// Protected-ref rules the adapter can read.
    pub protected_refs: Capability,
    /// Check runs bound to a proof root.
    pub check_runs: Capability,
    /// Merge-group composition disclosure.
    pub merge_group: Capability,
    /// Authoritative target-ref read-back.
    pub exact_oid_readback: Capability,
    /// Whether a third-party credential must exist.
    pub third_party_credential: Capability,
}

impl IntegrationDescriptor {
    /// Default: everything unprobed.
    #[must_use]
    pub const fn unprobed() -> Self {
        Self {
            exact_oid_cas: Capability::Unprobed,
            protected_refs: Capability::Unprobed,
            check_runs: Capability::Unprobed,
            merge_group: Capability::Unprobed,
            exact_oid_readback: Capability::Unprobed,
            third_party_credential: Capability::Unprobed,
        }
    }
}

/// Observed protection on one target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionState {
    /// Target ref.
    pub target: String,
    /// Whether the adapter reports protection in force.
    pub protected: bool,
    /// Required proof-root rule, if any.
    pub required_proof_root: Option<String>,
}

/// Attestor publication of one check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPublication {
    /// Exact commit.
    pub sha: String,
    /// Check name.
    pub name: String,
    /// Opaque proof root echoed on read-back.
    pub proof_root: String,
}

/// Read-back of a published check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    /// Exact commit.
    pub sha: String,
    /// Check name.
    pub name: String,
    /// Echoed proof root.
    pub proof_root: String,
}

/// Open or reconcile a PR / change request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationSubjectRequest {
    /// Exact base commit expected at the target.
    pub base: String,
    /// Head SHA.
    pub head: String,
    /// Target ref.
    pub target: String,
}

/// Durable integration subject.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationSubject {
    /// Adapter-native identity.
    pub id: String,
    /// Exact base commit expected at the target.
    pub base: String,
    /// Head SHA.
    pub head: String,
    /// Target ref.
    pub target: String,
}

/// One authorized protected-target compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedIntegrationRequest {
    /// Previously persisted exact integration subject.
    pub subject: IntegrationSubject,
    /// Exact old target OID; must equal the subject base.
    pub expected_old_oid: String,
    /// Exact check name required on the subject head.
    pub check_name: String,
    /// Exact proof root required by target protection and check read-back.
    pub proof_root: String,
}

/// Authoritative read-back of a completed local protected integration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationReceipt {
    /// Persisted integration-subject identity.
    pub subject_id: String,
    /// Protected target ref.
    pub target: String,
    /// Exact target value before mutation.
    pub previous_oid: String,
    /// Exact target value observed after mutation.
    pub integrated_oid: String,
    /// Exact check that authorized the mutation.
    pub check: CheckReceipt,
}

/// Composed merge-group SHA, if the adapter discloses one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeGroupSubject {
    /// Composed head the queue will test.
    pub sha: String,
}

/// Integration authority. Supertrait of [`ForgeEffects`].
pub trait ForgeIntegration: ForgeEffects {
    /// Probed capabilities. `Unprobed` never authorizes.
    fn integration_descriptor(&self) -> IntegrationDescriptor;

    /// Read protection currently in force on `target`.
    ///
    /// # Errors
    ///
    /// Typed adapter or live-admission refusal.
    fn read_protection(&self, target: &str) -> Result<ProtectionState, EffectsError>;

    /// Publish one check bound to one SHA and one proof root.
    ///
    /// # Errors
    ///
    /// Typed adapter or live-admission refusal. Attestor-only in production.
    fn publish_check(&mut self, req: &CheckPublication) -> Result<CheckReceipt, EffectsError>;

    /// Read a previously published check. `None` is authoritative absence.
    ///
    /// # Errors
    ///
    /// Typed adapter or live-admission refusal.
    fn read_check(&self, sha: &str, name: &str) -> Result<Option<CheckReceipt>, EffectsError>;

    /// Idempotent integration subject on `(base, head, target)`.
    ///
    /// # Errors
    ///
    /// Typed adapter or live-admission refusal.
    fn ensure_integration_subject(
        &mut self,
        req: &IntegrationSubjectRequest,
    ) -> Result<IntegrationSubject, EffectsError>;

    /// Integrate one persisted subject through an expected-old-OID mutation.
    /// Implementations must verify protection and exact-SHA check read-back
    /// before mutating, then authoritatively read the target.
    ///
    /// # Errors
    ///
    /// Typed protection, check, stale-target, drift, or adapter refusal.
    fn integrate_protected(
        &mut self,
        req: &ProtectedIntegrationRequest,
    ) -> Result<IntegrationReceipt, EffectsError>;

    /// Merge-group SHA, or `Ok(None)` when the adapter has no queue.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_BY_ADAPTER` or `MERGE_GROUP_OPAQUE`.
    fn merge_group_subject(
        &self,
        subject: &IntegrationSubject,
    ) -> Result<Option<MergeGroupSubject>, EffectsError>;

    /// Read the target after integration. Only this may mark verified.
    ///
    /// # Errors
    ///
    /// `TARGET_READBACK_UNAVAILABLE` must become `OUTCOME_UNKNOWN`.
    fn read_target(&self, target: &str) -> Result<Option<String>, EffectsError>;
}

/// Refuse when a capability is unprobed or unsupported.
///
/// # Errors
///
/// Returns `CAPABILITY_UNPROBED` when no probe ran and
/// `UNSUPPORTED_BY_ADAPTER` when the adapter structurally lacks the operation.
pub fn require_probed(capability: Capability, operation: &str) -> Result<(), EffectsError> {
    match capability {
        Capability::Supported | Capability::SupportedWithLimitations(_) => Ok(()),
        Capability::Unprobed => Err(EffectsError::CapabilityUnprobed(format!(
            "{operation} is unprobed"
        ))),
        Capability::Unsupported => Err(EffectsError::UnsupportedByAdapter(format!(
            "{operation} is unsupported"
        ))),
    }
}
