//! v1alpha2 live-admission rule, mirrored from bullet-wire `policy/live.rs`
//! (ADR 0012). A snapshot may set `sandbox_policy.live_admission_enabled` only
//! at an operator generation of at least [`LIVE_ADMISSION_MIN_GENERATION`] and
//! only while it registers an unrevoked `authority-signing` PASETO key admitted
//! for the `provider-runner` audience. `validate_policy` stays structural;
//! `validate_policy_at` applies the same instant semantics as
//! `authority_key_at` (activation inclusive, expiry and revocation exclusive).
//!
//! The Kernel cannot depend on bullet-wire, so equivalence is proven by
//! `tests/policy_v1alpha2.rs`, which mirrors the hub suite one-for-one.

use super::{invalid, validate_policy, POLICY_SCHEMA_VERSION};
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, IssuerKeyV1, KeyAlgorithmV1, KeyPurposeV1, PolicySnapshotV1,
};
use bullet_harness_core::HarnessError;

/// Second accepted snapshot schema version (ADR 0012).
pub const POLICY_SCHEMA_VERSION_V1ALPHA2: &str = "v1alpha2";

/// First policy generation that may enable live provider admission. Generation
/// 1 is the committed Gate 0 offline policy and can never admit a provider.
pub const LIVE_ADMISSION_MIN_GENERATION: u64 = 2;

/// Snapshot schema versions the loader accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySchemaVersion {
    /// Gate 0 offline policy: live admission is always `UNSAFE_POLICY`.
    V1Alpha1,
    /// v1alpha1 plus the operator-ratified live-admission rule (ADR 0012).
    V1Alpha2,
}

impl PolicySchemaVersion {
    /// Exact `schema_version` values, in the order the JSON-Schema enum lists
    /// them.
    pub const ACCEPTED: [&'static str; 2] = [POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_V1ALPHA2];

    /// Parse an exact `schema_version` value.
    ///
    /// # Errors
    ///
    /// `POLICY_INVALID` (`UNSUPPORTED_POLICY_SCHEMA`) for any other value.
    pub fn parse(actual: &str) -> Result<Self, HarnessError> {
        match actual {
            POLICY_SCHEMA_VERSION => Ok(Self::V1Alpha1),
            POLICY_SCHEMA_VERSION_V1ALPHA2 => Ok(Self::V1Alpha2),
            _ => Err(super::unsupported_schema(actual, "PolicySnapshotV1")),
        }
    }

    /// The exact wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1Alpha1 => POLICY_SCHEMA_VERSION,
            Self::V1Alpha2 => POLICY_SCHEMA_VERSION_V1ALPHA2,
        }
    }
}

/// `validate_policy` plus the time-bound checks at `now_unix_ms`: the snapshot
/// window must contain the instant and, when live admission is enabled, at
/// least one qualifying provider-runner key must be active at that instant.
///
/// # Errors
///
/// Every `validate_policy` refusal, then `POLICY_INVALID` with
/// `POLICY_NOT_ACTIVE` or `LIVE_ADMISSION_REQUIRES_RUNNER_KEY` as the reason
/// prefix.
pub fn validate_policy_at(policy: &PolicySnapshotV1, now_unix_ms: u64) -> Result<(), HarnessError> {
    validate_policy(policy)?;
    require_active_at(policy, now_unix_ms)
}

/// The time-bound half of `validate_policy_at` for an already-validated
/// snapshot.
pub(super) fn require_active_at(
    policy: &PolicySnapshotV1,
    now_unix_ms: u64,
) -> Result<(), HarnessError> {
    if now_unix_ms < policy.activation_at_unix_ms || now_unix_ms >= policy.expires_at_unix_ms {
        return Err(invalid(
            "POLICY_NOT_ACTIVE",
            "policy snapshot is not active at the validation instant",
        ));
    }
    if policy.sandbox_policy.live_admission_enabled
        && !policy
            .issuer_keys
            .iter()
            .any(|key| qualifies_for_live_admission(key) && key_active_at(key, now_unix_ms))
    {
        return Err(invalid(
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
            "no provider-runner authority key is active at the validation instant",
        ));
    }
    Ok(())
}

/// Structural rule for a v1alpha2 snapshot whose live admission is enabled.
/// The caller has already enforced the immutable conservatism set.
pub(super) fn validate_live_admission(policy: &PolicySnapshotV1) -> Result<(), HarnessError> {
    if !policy.sandbox_policy.live_admission_enabled {
        return Err(invalid(
            "LIVE_ADMISSION_DISABLED",
            "live admission cannot be satisfied by a dogfood-only or offline policy",
        ));
    }
    if policy.policy_generation < LIVE_ADMISSION_MIN_GENERATION {
        return Err(invalid(
            "LIVE_ADMISSION_REQUIRES_GENERATION",
            &format!(
                "live admission requires policy generation {LIVE_ADMISSION_MIN_GENERATION} or later; generation {} is refused",
                policy.policy_generation
            ),
        ));
    }
    if !policy
        .issuer_keys
        .iter()
        .any(|key| qualifies_for_live_admission(key) && overlaps_policy_window(key, policy))
    {
        return Err(invalid(
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
            "live admission requires an unrevoked authority-signing PASETO key admitted for the provider-runner audience within the policy window",
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

/// Same instant semantics as `authority_key_at`: activation inclusive, expiry
/// and revocation exclusive.
fn key_active_at(key: &IssuerKeyV1, now_unix_ms: u64) -> bool {
    now_unix_ms >= key.activates_at_unix_ms
        && now_unix_ms < key.expires_at_unix_ms
        && key
            .revoked_at_unix_ms
            .is_none_or(|revoked| now_unix_ms < revoked)
}
