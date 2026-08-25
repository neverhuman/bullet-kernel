//! Integration-authority operations additive over [`ForgeEffects`].
//! Every method may refuse. `Unprobed` never authorizes a dispatch.

use crate::error::EffectsError;
use crate::forge::ForgeEffects;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionState {
    /// Target ref.
    pub target: String,
    /// Whether the adapter reports protection in force.
    pub protected: bool,
    /// Required proof-root rule, if any.
    pub required_proof_root: Option<String>,
}

/// Attestor publication of one check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckPublication {
    /// Exact commit.
    pub sha: String,
    /// Check name.
    pub name: String,
    /// Opaque proof root echoed on read-back.
    pub proof_root: String,
}

/// Read-back of a published check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReceipt {
    /// Exact commit.
    pub sha: String,
    /// Check name.
    pub name: String,
    /// Echoed proof root.
    pub proof_root: String,
}

/// Open or reconcile a PR / change request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationSubjectRequest {
    /// Base ref.
    pub base: String,
    /// Head SHA.
    pub head: String,
    /// Target ref.
    pub target: String,
}

/// Durable integration subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationSubject {
    /// Adapter-native identity.
    pub id: String,
    /// Base ref.
    pub base: String,
    /// Head SHA.
    pub head: String,
    /// Target ref.
    pub target: String,
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

/// Refuse when a capability is unprobed.
///
/// # Errors
///
/// Always `CAPABILITY_UNPROBED` unless `capability.authorizes()`.
pub fn require_probed(capability: Capability, operation: &str) -> Result<(), EffectsError> {
    if capability.authorizes() {
        Ok(())
    } else {
        Err(EffectsError::CapabilityUnprobed(format!(
            "{operation} is {}",
            match capability {
                Capability::Unprobed => "unprobed",
                Capability::Unsupported => "unsupported",
                Capability::Supported | Capability::SupportedWithLimitations(_) => "authorized",
            }
        )))
    }
}
