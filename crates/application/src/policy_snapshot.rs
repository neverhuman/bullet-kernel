//! v1alpha1 policy snapshot loader over the generated `PolicySnapshotV1`.
//!
//! The loader enforces the same conservatism rule as bullet-wire
//! (`UNSAFE_POLICY`): a policy that enables live admission, arbitrary shell
//! gates, headroom-from-unknown-quota, evolutionary authority, or any other
//! relaxation is refused as `POLICY_INVALID`. Because v1alpha1 therefore
//! always carries `sandbox_policy.live_admission_enabled = false`, every
//! otherwise-valid launch grant ends in `POLICY_LIVE_ADMISSION_DISABLED`.

mod keys;
mod load;

use bullet_domain::schema_bundle::PolicySnapshotV1;
use bullet_harness_core::launch_grant::{
    decode_canonical, is_lower_hex_64, policy_snapshot_digest, LaunchGrantVerificationKey,
    PolicyBinding, MAX_SAFE_INTEGER,
};
use bullet_harness_core::HarnessError;

pub use load::{load_policy, load_policy_from_environment, POLICY_PATH_ENV};

/// Frozen policy schema version.
pub const POLICY_SCHEMA_VERSION: &str = "v1alpha1";
/// The exact policy field that refuses live admission in v1alpha1.
pub const LIVE_ADMISSION_FIELD: &str = "sandbox_policy.live_admission_enabled";

/// A validated policy snapshot plus the digest of its exact bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedPolicy {
    snapshot: PolicySnapshotV1,
    digest: String,
}

impl LoadedPolicy {
    /// Validate exact canonical policy bytes.
    ///
    /// # Errors
    ///
    /// `POLICY_INVALID` whose reason starts with the bullet-wire code
    /// (`UNSUPPORTED_POLICY_SCHEMA`, `INVALID_POLICY_WINDOW`,
    /// `INVALID_ISSUER_KEY_LIFECYCLE`, `INVALID_AUTHORITY_PUBLIC_KEY`,
    /// `INVALID_RELEASE_PUBLIC_KEY`, `INVALID_KEY_USE`, `UNSAFE_POLICY`, or
    /// `NON_CANONICAL_POLICY`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HarnessError> {
        let snapshot: PolicySnapshotV1 = decode_canonical(bytes).map_err(|error| {
            invalid(
                "NON_CANONICAL_POLICY",
                &format!("policy.json must be canonical RFC 8785 v1alpha1 bytes: {error}"),
            )
        })?;
        validate_policy(&snapshot)?;
        let digest = policy_snapshot_digest(bytes)
            .map_err(|error| invalid("NON_CANONICAL_POLICY", &error.to_string()))?;
        Ok(Self { snapshot, digest })
    }

    /// The validated snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &PolicySnapshotV1 {
        &self.snapshot
    }

    /// Framed `policy.snapshot` digest of the exact loaded bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Policy generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.snapshot.policy_generation
    }

    /// Whether the loaded policy permits live provider admission at all.
    #[must_use]
    pub fn live_admission_enabled(&self) -> bool {
        self.snapshot.sandbox_policy.live_admission_enabled
    }

    /// Facts a launch-grant verifier or issuer binds.
    #[must_use]
    pub fn binding(&self) -> PolicyBinding {
        PolicyBinding {
            policy_snapshot_digest: self.digest.clone(),
            policy_generation: self.generation(),
            live_admission_enabled: self.live_admission_enabled(),
        }
    }

    /// Refuse unless the policy enables live admission.
    ///
    /// # Errors
    ///
    /// `POLICY_LIVE_ADMISSION_DISABLED` naming the generation and field.
    pub fn require_live_admission(&self) -> Result<(), HarnessError> {
        if self.live_admission_enabled() {
            return Ok(());
        }
        Err(HarnessError::PolicyLiveAdmissionDisabled {
            generation: self.generation(),
            field: LIVE_ADMISSION_FIELD.to_string(),
        })
    }

    /// Resolve the verification key for `(issuer, key_id)` admitted for
    /// `audience` at `now_unix_ms`.
    ///
    /// # Errors
    ///
    /// `POLICY_INVALID` (`POLICY_NOT_ACTIVE`) outside the policy window;
    /// `LAUNCH_GRANT_KEY_UNKNOWN` for an unregistered, wrong-purpose,
    /// wrong-audience, inactive, expired, or revoked key.
    pub fn authority_key_at(
        &self,
        issuer: &str,
        key_id: &str,
        audience: &str,
        now_unix_ms: u64,
    ) -> Result<LaunchGrantVerificationKey, HarnessError> {
        keys::authority_key_at(&self.snapshot, issuer, key_id, audience, now_unix_ms)
    }
}

/// Validate a decoded snapshot with the bullet-wire rules.
///
/// # Errors
///
/// `POLICY_INVALID` with the bullet-wire code as the reason prefix.
pub fn validate_policy(policy: &PolicySnapshotV1) -> Result<(), HarnessError> {
    require_v1alpha1(&policy.schema_version, "PolicySnapshotV1")?;
    if policy.policy_generation == 0
        || policy.policy_generation > MAX_SAFE_INTEGER
        || policy.activation_at_unix_ms >= policy.expires_at_unix_ms
        || policy.expires_at_unix_ms > MAX_SAFE_INTEGER
        || policy.issuer_keys.is_empty()
    {
        return Err(invalid(
            "INVALID_POLICY_WINDOW",
            "policy requires a generation, issuer key, and ordered validity window",
        ));
    }
    if !is_lower_hex_64(&policy.schema_bundle_hash)
        || !is_lower_hex_64(&policy.invariant_registry_hash)
    {
        return Err(invalid(
            "INVALID_POLICY_WINDOW",
            "policy bundle and registry hashes must be 64 lowercase hex characters",
        ));
    }
    for (name, version) in [
        ("risk_policy", policy.risk_policy.schema_version.as_str()),
        (
            "evidence_policy",
            policy.evidence_policy.schema_version.as_str(),
        ),
        (
            "sandbox_policy",
            policy.sandbox_policy.schema_version.as_str(),
        ),
        (
            "budget_policy",
            policy.budget_policy.schema_version.as_str(),
        ),
        ("route_policy", policy.route_policy.schema_version.as_str()),
    ] {
        require_v1alpha1(version, name)?;
    }
    keys::validate_issuer_keys(&policy.issuer_keys)?;
    if policy.budget_policy.maximum_lease_ttl_seconds > 15
        || policy.budget_policy.unknown_quota_is_headroom
        || policy.sandbox_policy.live_admission_enabled
        || policy.sandbox_policy.arbitrary_shell_gates
        || policy.evidence_policy.author_evidence_is_independent
        || policy.evidence_policy.unknown_satisfies_gate
        || !policy.evidence_policy.r2_requires_sealed_product_holdout
        || policy.route_policy.universal_incumbent != "T0"
        || policy.route_policy.evolutionary_authority
    {
        return Err(invalid(
            "UNSAFE_POLICY",
            "v1alpha1 Gate 0 policy must remain offline, conservative, and T0-anchored",
        ));
    }
    Ok(())
}

fn require_v1alpha1(actual: &str, kind: &str) -> Result<(), HarnessError> {
    if actual != POLICY_SCHEMA_VERSION {
        return Err(invalid(
            "UNSUPPORTED_POLICY_SCHEMA",
            &format!("{kind} schema {actual:?} is unsupported"),
        ));
    }
    Ok(())
}

pub(crate) fn invalid(code: &str, message: &str) -> HarnessError {
    HarnessError::PolicyInvalid {
        reason: format!("{code}: {message}"),
    }
}
