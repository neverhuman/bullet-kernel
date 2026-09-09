//! `LaunchGrantClaimsV1` payload and `SignedLaunchGrantV1` envelope shapes.
//! Every field is validated exactly; the shape never carries authority by
//! itself and is only trusted after `verify::verify_launch_grant`.

use super::canonical::{hash_canonical, hash_framed_bytes, is_lower_hex_64};
use crate::admission::ProviderProtocol;
use crate::error::HarnessError;
use bullet_domain::{
    AttemptId, MissionId, ProfileId, RepositoryId, RunnerId, VariantId, WorkPackageId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Frozen schema version of the launch-grant contract.
pub const LAUNCH_GRANT_SCHEMA_VERSION: &str = "v1alpha1";
/// The only audience a launch grant may name.
pub const LAUNCH_GRANT_AUDIENCE: &str = "provider-runner";
/// The only operation a launch grant may authorize.
pub const LAUNCH_GRANT_OPERATION: &str = "launch-provider";
/// Footer purpose that binds the signing key to launch grants only.
pub const LAUNCH_GRANT_KEY_PURPOSE: &str = "launch-grant-signing";
/// PASETO implicit assertion; never transmitted, always authenticated.
pub const LAUNCH_GRANT_IMPLICIT_ASSERTION: &[u8] = b"bullet-farm.launch-grant.v1alpha1";
/// Envelope digest domain (same helper family as `authority.envelope.v1alpha1`).
pub const LAUNCH_GRANT_ENVELOPE_DOMAIN: &str = "authority.launch-grant-envelope.v1alpha1";
/// Digest domain for the canonical claims digest.
pub const LAUNCH_GRANT_CLAIMS_DOMAIN: &str = "authority.launch-grant-claims.v1alpha1";
/// Digest domain for the 32-byte workspace nonce binding.
pub const WORKSPACE_NONCE_DOMAIN: &str = "launch-grant.workspace-nonce.v1alpha1";
/// Digest domain for the canonical child environment binding.
pub const ENVIRONMENT_DOMAIN: &str = "launch-grant.environment.v1alpha1";
/// Digest domain for the exact loaded policy bytes (the pinned policy identity).
pub const POLICY_SNAPSHOT_DOMAIN: &str = "policy.snapshot";
/// Maximum lifetime of one grant, in milliseconds.
pub const MAX_LAUNCH_GRANT_TTL_MS: u64 = 15_000;
/// Maximum gate identifiers one grant may carry.
pub const MAX_GATE_IDS: usize = 16;
/// Largest integer every JSON consumer represents exactly.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4_096;
const PROVIDERS: [&str; 4] = ["claude", "codex", "cursor", "agy"];

/// Signed claim set. Field order is irrelevant on the wire (RFC 8785).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchGrantClaims {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Unique 64-hex grant identifier.
    pub grant_id: String,
    /// Always `provider-runner`.
    pub audience: String,
    /// Always `launch-provider`.
    pub operation: String,
    /// Issuer label; must equal the footer and the policy issuer key.
    pub issuer: String,
    /// Key label; must equal the footer and the policy issuer key.
    pub key_id: String,
    /// Issue instant.
    pub issued_at_unix_ms: u64,
    /// Inclusive validity start.
    pub not_before_unix_ms: u64,
    /// Exclusive validity end; at most 15 s after `not_before_unix_ms`.
    pub expires_at_unix_ms: u64,
    /// Single-use 64-hex nonce persisted by the issuer.
    pub grant_nonce: String,
    /// Mission owning the durable lease.
    pub mission_id: String,
    /// Repository the Mission targets.
    pub repository_id: String,
    /// Graph revision (`grf_` + 64 hex) the lease was minted against.
    pub graph_revision_id: String,
    /// Work package the Attempt writes.
    pub work_package_id: String,
    /// Variant whose single writer is leased.
    pub variant_id: String,
    /// Attempt incarnation holding the durable lease.
    pub attempt_id: String,
    /// Permanent fence on Attempt and lease; at least 1.
    pub attempt_fence: u64,
    /// Runner holding the lease.
    pub runner_id: String,
    /// Runner incarnation.
    pub runner_epoch: u64,
    /// Private workspace bound to the Attempt.
    pub workspace_id: String,
    /// Framed BLAKE3 of the 32-byte workspace nonce.
    pub workspace_nonce_digest: String,
    /// Kernel authority epoch.
    pub authority_epoch: u64,
    /// Kernel freeze generation.
    pub freeze_generation: u64,
    /// One of `claude`, `codex`, `cursor`, `agy`.
    pub provider: String,
    /// Adapter label.
    pub adapter: String,
    /// Authorized credential profile (`prf_` + 64 hex).
    pub provider_profile_id: String,
    /// Model label.
    pub model: String,
    /// Credential material generation.
    pub credential_generation: u64,
    /// `ProviderProtocol` wire label demonstrated by the runtime probe.
    pub protocol: String,
    /// Absolute canonical executable path.
    pub executable_path: String,
    /// Exact executable bytes digest.
    pub executable_digest: String,
    /// Exact complete descriptor digest.
    pub descriptor_digest: String,
    /// Exact capability matrix digest.
    pub capability_digest: String,
    /// BLAKE3 over the exact loaded policy bytes.
    pub policy_snapshot_digest: String,
    /// Policy generation the digest belongs to.
    pub policy_generation: u64,
    /// Digest of the sandbox manifest the child will run under.
    pub sandbox_manifest_digest: String,
    /// Digest over the canonical sorted allow-listed child environment.
    pub environment_digest: String,
    /// 1..=16 unique `gat_` gate identifiers.
    pub gate_ids: Vec<String>,
    /// Budget reservation identifier (64 hex).
    pub budget_reservation_id: String,
    /// Maximum provider invocations; at least 1.
    pub max_invocations: u64,
    /// Maximum wall clock; at least 1 ms.
    pub max_wall_clock_ms: u64,
    /// Maximum spend in micro-USD.
    pub max_cost_micro_usd: u64,
}

impl LaunchGrantClaims {
    /// Validate every field exactly. Shape validity is not authority.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_AUDIENCE_MISMATCH`, `LAUNCH_GRANT_TTL_EXCEEDED`, or
    /// `LAUNCH_GRANT_INVALID` naming the offending field.
    pub fn validate_shape(&self) -> Result<(), HarnessError> {
        if self.schema_version != LAUNCH_GRANT_SCHEMA_VERSION {
            return Err(invalid("schema_version must be v1alpha1"));
        }
        if self.audience != LAUNCH_GRANT_AUDIENCE {
            return Err(HarnessError::LaunchGrantAudienceMismatch {
                audience: printable(&self.audience),
            });
        }
        if self.operation != LAUNCH_GRANT_OPERATION {
            return Err(invalid("operation must be launch-provider"));
        }
        validate_label("issuer", &self.issuer)?;
        validate_label("key_id", &self.key_id)?;
        for (name, value) in self.digest_fields() {
            if !is_lower_hex_64(value) {
                return Err(invalid(&format!(
                    "{name} must be 64 lowercase hex characters"
                )));
            }
        }
        self.validate_identities()?;
        self.validate_provider()?;
        self.validate_integers()?;
        self.validate_gates()?;
        self.validate_window()
    }

    /// Exact validity window in milliseconds `[not_before, expires_at)`.
    #[must_use]
    pub fn window(&self) -> (u64, u64) {
        (self.not_before_unix_ms, self.expires_at_unix_ms)
    }

    /// Framed digest of the canonical claims (bullet-wire `LaunchGrantClaims::digest`).
    ///
    /// # Errors
    ///
    /// Shape refusal or `LAUNCH_GRANT_INVALID` on encoding failure.
    pub fn digest(&self) -> Result<String, HarnessError> {
        self.validate_shape()?;
        hash_canonical(LAUNCH_GRANT_CLAIMS_DOMAIN, self)
    }

    fn digest_fields(&self) -> [(&'static str, &str); 10] {
        [
            ("grant_id", &self.grant_id),
            ("grant_nonce", &self.grant_nonce),
            ("workspace_nonce_digest", &self.workspace_nonce_digest),
            ("executable_digest", &self.executable_digest),
            ("descriptor_digest", &self.descriptor_digest),
            ("capability_digest", &self.capability_digest),
            ("policy_snapshot_digest", &self.policy_snapshot_digest),
            ("sandbox_manifest_digest", &self.sandbox_manifest_digest),
            ("environment_digest", &self.environment_digest),
            ("budget_reservation_id", &self.budget_reservation_id),
        ]
    }

    fn validate_identities(&self) -> Result<(), HarnessError> {
        let checks: [(&str, bool); 8] = [
            ("mission_id", MissionId::parse(&self.mission_id).is_ok()),
            (
                "repository_id",
                RepositoryId::parse(&self.repository_id).is_ok(),
            ),
            (
                "graph_revision_id",
                prefixed_hex("grf_", &self.graph_revision_id),
            ),
            (
                "work_package_id",
                WorkPackageId::parse(&self.work_package_id).is_ok(),
            ),
            ("variant_id", VariantId::parse(&self.variant_id).is_ok()),
            ("attempt_id", AttemptId::parse(&self.attempt_id).is_ok()),
            ("runner_id", RunnerId::parse(&self.runner_id).is_ok()),
            (
                "workspace_id",
                WorkspaceId::parse(&self.workspace_id).is_ok(),
            ),
        ];
        for (name, ok) in checks {
            if !ok {
                return Err(invalid(&format!("{name} is not a frozen typed id")));
            }
        }
        if ProfileId::parse(&self.provider_profile_id).is_err() {
            return Err(invalid("provider_profile_id is not a frozen typed id"));
        }
        Ok(())
    }

    fn validate_provider(&self) -> Result<(), HarnessError> {
        if !PROVIDERS.contains(&self.provider.as_str()) {
            return Err(invalid("provider is not in the frozen provider set"));
        }
        validate_label("adapter", &self.adapter)?;
        validate_label("model", &self.model)?;
        if protocol_of(&self.protocol).is_none() {
            return Err(invalid("protocol is not a frozen ProviderProtocol label"));
        }
        let path = &self.executable_path;
        if path.is_empty()
            || path.len() > MAX_EXECUTABLE_PATH_BYTES
            || !Path::new(path).is_absolute()
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .skip(1)
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(invalid(
                "executable_path must be a bounded, normalized, absolute, control-free path",
            ));
        }
        Ok(())
    }

    fn validate_integers(&self) -> Result<(), HarnessError> {
        let bounded = [
            ("attempt_fence", self.attempt_fence),
            ("runner_epoch", self.runner_epoch),
            ("authority_epoch", self.authority_epoch),
            ("freeze_generation", self.freeze_generation),
            ("credential_generation", self.credential_generation),
            ("policy_generation", self.policy_generation),
            ("max_invocations", self.max_invocations),
            ("max_wall_clock_ms", self.max_wall_clock_ms),
            ("max_cost_micro_usd", self.max_cost_micro_usd),
            ("issued_at_unix_ms", self.issued_at_unix_ms),
            ("not_before_unix_ms", self.not_before_unix_ms),
            ("expires_at_unix_ms", self.expires_at_unix_ms),
        ];
        for (name, value) in bounded {
            if value > MAX_SAFE_INTEGER {
                return Err(invalid(&format!(
                    "{name} exceeds the interoperable integer range"
                )));
            }
        }
        for (name, value) in [
            ("attempt_fence", self.attempt_fence),
            ("policy_generation", self.policy_generation),
            ("max_invocations", self.max_invocations),
            ("max_wall_clock_ms", self.max_wall_clock_ms),
        ] {
            if value == 0 {
                return Err(invalid(&format!("{name} must be at least 1")));
            }
        }
        Ok(())
    }

    fn validate_gates(&self) -> Result<(), HarnessError> {
        if self.gate_ids.is_empty() || self.gate_ids.len() > MAX_GATE_IDS {
            return Err(invalid("gate_ids must contain 1..=16 entries"));
        }
        let unique: BTreeSet<&str> = self.gate_ids.iter().map(String::as_str).collect();
        if unique.len() != self.gate_ids.len()
            || self.gate_ids.iter().any(|gate| !prefixed_hex("gat_", gate))
        {
            return Err(invalid("gate_ids must be unique gat_ identifiers"));
        }
        Ok(())
    }

    fn validate_window(&self) -> Result<(), HarnessError> {
        if self.issued_at_unix_ms > self.not_before_unix_ms
            || self.not_before_unix_ms >= self.expires_at_unix_ms
        {
            return Err(invalid(
                "window requires issued_at <= not_before < expires_at",
            ));
        }
        if self.expires_at_unix_ms - self.not_before_unix_ms > MAX_LAUNCH_GRANT_TTL_MS {
            return Err(HarnessError::LaunchGrantTtlExceeded {
                ttl_ms: self.expires_at_unix_ms - self.not_before_unix_ms,
            });
        }
        Ok(())
    }
}

/// Compact envelope carrying one PASETO v4.public token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLaunchGrant {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Issuer label repeated from the footer.
    pub issuer: String,
    /// Key label repeated from the footer.
    pub key_id: String,
    /// `v4.public.` token with canonical footer.
    pub paseto: String,
}

impl SignedLaunchGrant {
    /// Validate framing without trusting anything inside the token.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for an unsupported schema, label, or framing.
    pub fn validate_envelope(&self) -> Result<(), HarnessError> {
        if self.schema_version != LAUNCH_GRANT_SCHEMA_VERSION {
            return Err(invalid("envelope schema_version must be v1alpha1"));
        }
        validate_label("issuer", &self.issuer)?;
        validate_label("key_id", &self.key_id)?;
        if !self.paseto.starts_with("v4.public.")
            || self.paseto.len() > MAX_TOKEN_BYTES
            || !self
                .paseto
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(invalid(
                "launch grant must be a bounded compact PASETO v4.public token",
            ));
        }
        Ok(())
    }

    /// Framed digest of the exact token bytes.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for an invalid envelope.
    pub fn envelope_digest(&self) -> Result<String, HarnessError> {
        self.validate_envelope()?;
        hash_framed_bytes(LAUNCH_GRANT_ENVELOPE_DOMAIN, self.paseto.as_bytes())
    }
}

/// Canonical footer bound into every launch-grant signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LaunchGrantFooter {
    pub schema_version: String,
    pub issuer: String,
    pub key_id: String,
    pub purpose: String,
}

impl LaunchGrantFooter {
    pub(crate) fn new(issuer: &str, key_id: &str) -> Self {
        Self {
            schema_version: LAUNCH_GRANT_SCHEMA_VERSION.to_string(),
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            purpose: LAUNCH_GRANT_KEY_PURPOSE.to_string(),
        }
    }
}

/// Parse a frozen `ProviderProtocol` wire label.
#[must_use]
pub fn protocol_of(label: &str) -> Option<ProviderProtocol> {
    serde_json::from_value(serde_json::Value::String(label.to_string())).ok()
}

/// Bounded printable identifier text (same rule as bullet-wire labels).
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` naming the field.
pub fn validate_label(name: &str, value: &str) -> Result<(), HarnessError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(invalid(&format!(
            "{name} must be bounded printable identifier text"
        )));
    }
    Ok(())
}

fn prefixed_hex(prefix: &str, value: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_lower_hex_64)
}

fn printable(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}

fn invalid(reason: &str) -> HarnessError {
    HarnessError::LaunchGrantInvalid {
        reason: reason.to_string(),
    }
}
