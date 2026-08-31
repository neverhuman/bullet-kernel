//! Policy snapshot loader over the generated `PolicySnapshotV1`, mirroring the
//! bullet-wire validator (ADR 0012).
//!
//! Two schema versions are accepted. Both enforce the immutable conservatism
//! set (`UNSAFE_POLICY`): lease TTL above 15 s, headroom-from-unknown-quota,
//! arbitrary shell gates, author evidence as independent, unknown satisfying a
//! gate, no sealed product holdout, a non-`T0` incumbent, or evolutionary
//! authority, and the A7 STONITH inequality (a zero maximum lease TTL leaves
//! no self-kill grace strictly inside the TTL). `v1alpha1` additionally
//! refuses live admission as `UNSAFE_POLICY`; `v1alpha2` admits it only at
//! generation
//! [`LIVE_ADMISSION_MIN_GENERATION`] or later with a qualifying
//! `provider-runner` authority key (`live`). Every refusal is `POLICY_INVALID`
//! whose reason starts with the bullet-wire code; the Kernel cannot import
//! bullet-wire, so equivalence is proven by `tests/policy_v1alpha2.rs`.
//!
//! Configuration generations (spec §49.2) live in `generation`: a sealed
//! `ConfigurationGeneration` binds a policy digest and routing digest, and
//! `activation`'s `ActivationLedger` admits Attempts only against a
//! generation every required component acknowledged, with abort as the only
//! typed exit (`tests/config_generation.rs`).

mod activation;
mod dogfood;
mod generation;
mod keys;
mod live;
mod load;

use bullet_domain::schema_bundle::PolicySnapshotV1;
use bullet_harness_core::launch_grant::{
    decode_canonical, is_lower_hex_64, policy_snapshot_digest, LaunchGrantVerificationKey,
    PolicyBinding, MAX_SAFE_INTEGER,
};
use bullet_harness_core::HarnessError;

pub use activation::{AbortRecord, ActivationLedger, ActivationState};
pub use dogfood::{
    refuse_dogfood_binding_as_live, validate_dogfood_admission, DogfoodAudience, DogfoodBinding,
    DogfoodOperation,
};
pub use generation::{
    Component, ConfigurationGeneration, GenerationBinding, GenerationContent, GenerationError,
    RecordedGeneration, CONFIGURATION_GENERATION_DOMAIN, MAX_ACTIVATION_SUBJECT_BYTES,
};
pub use live::{
    validate_policy_at, PolicySchemaVersion, LIVE_ADMISSION_MIN_GENERATION,
    POLICY_SCHEMA_VERSION_V1ALPHA2,
};
pub use load::{load_policy, load_policy_from_environment, POLICY_PATH_ENV};

/// Gate 0 policy schema version; also the only version nested records and
/// issuer keys may carry.
pub const POLICY_SCHEMA_VERSION: &str = "v1alpha1";
/// The exact policy field that gates live admission.
pub const LIVE_ADMISSION_FIELD: &str = "sandbox_policy.live_admission_enabled";

/// A validated policy snapshot plus the digest of its exact bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedPolicy {
    snapshot: PolicySnapshotV1,
    schema: PolicySchemaVersion,
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
    /// `INVALID_RELEASE_PUBLIC_KEY`, `INVALID_KEY_USE`, `UNSAFE_POLICY`,
    /// `LIVE_ADMISSION_REQUIRES_GENERATION`,
    /// `LIVE_ADMISSION_REQUIRES_RUNNER_KEY`, or `NON_CANONICAL_POLICY`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HarnessError> {
        let snapshot: PolicySnapshotV1 = decode_canonical(bytes).map_err(|error| {
            invalid(
                "NON_CANONICAL_POLICY",
                &format!("policy.json must be canonical RFC 8785 bytes: {error}"),
            )
        })?;
        let schema = validate_policy(&snapshot)?;
        let digest = policy_snapshot_digest(bytes)
            .map_err(|error| invalid("NON_CANONICAL_POLICY", &error.to_string()))?;
        Ok(Self {
            snapshot,
            schema,
            digest,
        })
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

    /// The accepted snapshot schema version.
    #[must_use]
    pub fn schema(&self) -> PolicySchemaVersion {
        self.schema
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

    /// The time-bound checks of bullet-wire `validate_at` at `now_unix_ms`
    /// (the structural half already ran in [`LoadedPolicy::from_bytes`]).
    ///
    /// # Errors
    ///
    /// `POLICY_INVALID` (`POLICY_NOT_ACTIVE`) outside the policy window;
    /// `POLICY_INVALID` (`LIVE_ADMISSION_REQUIRES_RUNNER_KEY`) when live
    /// admission is enabled and no qualifying provider-runner key is active
    /// at the instant.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), HarnessError> {
        live::require_active_at(&self.snapshot, now_unix_ms)
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

/// Validate a decoded snapshot with the bullet-wire rules and return its
/// schema version. The conservatism set is checked before the live-admission
/// rule, so no v1alpha2 policy can trade one for the other.
///
/// # Errors
///
/// `POLICY_INVALID` with the bullet-wire code as the reason prefix.
pub fn validate_policy(policy: &PolicySnapshotV1) -> Result<PolicySchemaVersion, HarnessError> {
    let schema = PolicySchemaVersion::parse(&policy.schema_version)?;
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
        || policy.sandbox_policy.arbitrary_shell_gates
        || policy.evidence_policy.author_evidence_is_independent
        || policy.evidence_policy.unknown_satisfies_gate
        || !policy.evidence_policy.r2_requires_sealed_product_holdout
        || policy.route_policy.universal_incumbent != "T0"
        || policy.route_policy.evolutionary_authority
    {
        return Err(unsafe_policy(schema));
    }
    if !self_kill_grace_precedes_expiry(policy.budget_policy.maximum_lease_ttl_seconds) {
        return Err(invalid("UNSAFE_POLICY", STONITH_REASON));
    }
    if !policy.sandbox_policy.live_admission_enabled {
        return Ok(schema);
    }
    match schema {
        PolicySchemaVersion::V1Alpha1 => Err(unsafe_policy(schema)),
        PolicySchemaVersion::V1Alpha2 => live::validate_live_admission(policy).map(|()| schema),
    }
}

/// `UNSAFE_POLICY` reason for the A7 STONITH inequality; byte-identical to
/// the bullet-wire rule.
pub const STONITH_REASON: &str = "self-kill grace must be strictly less than lease TTL";

/// The A7 STONITH inequality at policy level. The runner's self-kill budget
/// is 4/5 of the admitted TTL (`SelfKillDeadline`), so both that budget and
/// the remaining grace must fall strictly inside the TTL for the local
/// monotonic deadline to fire strictly before the server expiry. At
/// millisecond granularity only a zero maximum violates it, and a zero
/// maximum would otherwise validate.
#[must_use]
pub fn self_kill_grace_precedes_expiry(maximum_lease_ttl_seconds: u64) -> bool {
    let ttl_ms = maximum_lease_ttl_seconds.saturating_mul(1_000);
    let budget_ms = ttl_ms / 5 * 4;
    let grace_ms = ttl_ms - budget_ms;
    budget_ms < ttl_ms && grace_ms < ttl_ms
}

fn unsafe_policy(schema: PolicySchemaVersion) -> HarnessError {
    let reason = match schema {
        PolicySchemaVersion::V1Alpha1 => {
            "v1alpha1 Gate 0 policy must remain offline, conservative, and T0-anchored"
        }
        PolicySchemaVersion::V1Alpha2 => {
            "v1alpha2 policy must remain conservative, T0-anchored, and without evolutionary authority"
        }
    };
    invalid("UNSAFE_POLICY", reason)
}

fn require_v1alpha1(actual: &str, kind: &str) -> Result<(), HarnessError> {
    if actual != POLICY_SCHEMA_VERSION {
        return Err(unsupported_schema(actual, kind));
    }
    Ok(())
}

fn unsupported_schema(actual: &str, kind: &str) -> HarnessError {
    invalid(
        "UNSUPPORTED_POLICY_SCHEMA",
        &format!("{kind} schema {actual:?} is unsupported"),
    )
}

pub(crate) fn invalid(code: &str, message: &str) -> HarnessError {
    HarnessError::PolicyInvalid {
        reason: format!("{code}: {message}"),
    }
}
