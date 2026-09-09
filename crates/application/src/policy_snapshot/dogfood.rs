//! Dogfood-scoped admission (ADR 0015). Mirrors bullet-wire `policy/live.rs`
//! dogfood validators. A dogfood binding cannot satisfy live admission, and
//! a live-enabled snapshot cannot satisfy dogfood admission.

use super::{invalid, live::LIVE_ADMISSION_MIN_GENERATION, POLICY_SCHEMA_VERSION_V1ALPHA2};
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, IssuerKeyV1, KeyAlgorithmV1, KeyPurposeV1, PolicySnapshotV1,
};
use bullet_harness_core::HarnessError;

/// Purpose-separated dogfood audience. Not an authority-key audience.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DogfoodAudience {
    /// Read-only propose runner.
    DogfoodRunner,
}

/// Purpose-separated dogfood operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DogfoodOperation {
    /// One plan-mode PatchProposal. No write.
    ReadOnlyPropose,
}

/// Typed dogfood scope presented beside a policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DogfoodBinding {
    /// Binding schema. Only `v1alpha1` is admitted.
    pub schema_version: String,
    /// Dogfood audience.
    pub audience: DogfoodAudience,
    /// Dogfood operation.
    pub operation: DogfoodOperation,
}

impl DogfoodBinding {
    /// The only admitted binding.
    #[must_use]
    pub fn read_only_propose() -> Self {
        Self {
            schema_version: "v1alpha1".to_owned(),
            audience: DogfoodAudience::DogfoodRunner,
            operation: DogfoodOperation::ReadOnlyPropose,
        }
    }
}

/// Admit one dogfood-scoped binding against a snapshot that stays offline.
///
/// # Errors
///
/// `POLICY_INVALID` whose reason starts with the bullet-wire code.
pub fn validate_dogfood_admission(
    policy: &PolicySnapshotV1,
    binding: &DogfoodBinding,
) -> Result<(), HarnessError> {
    if policy.sandbox_policy.live_admission_enabled {
        return Err(invalid(
            "DOGFOOD_REFUSES_LIVE_ADMISSION",
            "dogfood admission refuses a general live binding",
        ));
    }
    if policy.schema_version != POLICY_SCHEMA_VERSION_V1ALPHA2 {
        return Err(invalid(
            "UNSUPPORTED_POLICY_SCHEMA",
            "dogfood admission requires policy schema v1alpha2",
        ));
    }
    if policy.policy_generation < LIVE_ADMISSION_MIN_GENERATION {
        return Err(invalid(
            "LIVE_ADMISSION_REQUIRES_GENERATION",
            &format!(
                "dogfood admission requires policy generation {LIVE_ADMISSION_MIN_GENERATION} or later; generation {} is refused",
                policy.policy_generation
            ),
        ));
    }
    validate_binding(binding)?;
    if !policy
        .issuer_keys
        .iter()
        .any(|key| qualifies_for_live_admission(key) && overlaps_policy_window(key, policy))
    {
        return Err(invalid(
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
            "dogfood admission requires an unrevoked authority-signing PASETO key admitted for the provider-runner audience within the policy window",
        ));
    }
    Ok(())
}

/// A dogfood binding can never satisfy the general live path.
///
/// # Errors
///
/// Always `LIVE_ADMISSION_REFUSES_DOGFOOD_BINDING`.
pub fn refuse_dogfood_binding_as_live(binding: &DogfoodBinding) -> Result<(), HarnessError> {
    validate_binding(binding)?;
    Err(invalid(
        "LIVE_ADMISSION_REFUSES_DOGFOOD_BINDING",
        "a dogfood audience/operation binding cannot satisfy live admission",
    ))
}

fn validate_binding(binding: &DogfoodBinding) -> Result<(), HarnessError> {
    if binding.schema_version != "v1alpha1" {
        return Err(invalid(
            "INVALID_DOGFOOD_BINDING",
            "dogfood binding requires schema v1alpha1",
        ));
    }
    if binding.audience != DogfoodAudience::DogfoodRunner
        || binding.operation != DogfoodOperation::ReadOnlyPropose
    {
        return Err(invalid(
            "INVALID_DOGFOOD_BINDING",
            "dogfood binding must be dogfood-runner / read-only-propose",
        ));
    }
    Ok(())
}

fn qualifies_for_live_admission(key: &IssuerKeyV1) -> bool {
    key.key_purpose == KeyPurposeV1::AuthoritySigning
        && key.algorithm == KeyAlgorithmV1::PasetoV4Public
        && key.audiences.contains(&AuthorityAudienceV1::ProviderRunner)
        && key.revoked_at_unix_ms.is_none()
}

fn overlaps_policy_window(key: &IssuerKeyV1, policy: &PolicySnapshotV1) -> bool {
    key.activates_at_unix_ms < policy.expires_at_unix_ms
        && key.expires_at_unix_ms > policy.activation_at_unix_ms
}
