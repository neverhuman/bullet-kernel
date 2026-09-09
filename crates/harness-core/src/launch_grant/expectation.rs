//! The exact subject a launch grant must bind: the durable active lease, the
//! evaluated provider admission, and the loaded policy. Every field is
//! compared for equality; a grant that binds anything else is refused.

use super::canonical::{hash_canonical, hash_framed_bytes};
use super::claims::{
    LaunchGrantClaims, ENVIRONMENT_DOMAIN, POLICY_SNAPSHOT_DOMAIN, WORKSPACE_NONCE_DOMAIN,
};
use crate::admission::ProviderProtocol;
use crate::error::HarnessError;
use std::collections::BTreeMap;

/// Durable active-lease row, read by the Kernel, never by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseBinding {
    /// Mission owning the lease.
    pub mission_id: String,
    /// Repository the Mission targets.
    pub repository_id: String,
    /// Graph revision the lease was minted against.
    pub graph_revision_id: String,
    /// Work package under lease.
    pub work_package_id: String,
    /// Leased variant.
    pub variant_id: String,
    /// Attempt incarnation holding the lease.
    pub attempt_id: String,
    /// Permanent fence.
    pub attempt_fence: u64,
    /// Runner holding the lease.
    pub runner_id: String,
    /// Runner incarnation.
    pub runner_epoch: u64,
    /// Private workspace.
    pub workspace_id: String,
    /// Framed digest of the 32-byte workspace nonce.
    pub workspace_nonce_digest: String,
    /// Kernel authority epoch.
    pub authority_epoch: u64,
    /// Kernel freeze generation.
    pub freeze_generation: u64,
}

/// Exact provider facts from the local admission evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBinding {
    /// Provider wire name.
    pub provider: String,
    /// Adapter label.
    pub adapter: String,
    /// Authorized credential profile.
    pub provider_profile_id: String,
    /// Model label.
    pub model: String,
    /// Credential generation.
    pub credential_generation: u64,
    /// Protocol observed by the runtime probe.
    pub protocol: ProviderProtocol,
    /// Absolute canonical executable path.
    pub executable_path: String,
    /// Exact executable digest.
    pub executable_digest: String,
    /// Exact descriptor digest.
    pub descriptor_digest: String,
    /// Exact capability digest.
    pub capability_digest: String,
    /// Sandbox manifest digest the child will run under.
    pub sandbox_manifest_digest: String,
    /// Digest over the canonical sorted child environment.
    pub environment_digest: String,
}

/// Loaded policy facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBinding {
    /// BLAKE3 over the exact loaded policy bytes.
    pub policy_snapshot_digest: String,
    /// Policy generation.
    pub policy_generation: u64,
    /// `sandbox_policy.live_admission_enabled` from the loaded policy.
    pub live_admission_enabled: bool,
}

/// Everything a grant must equal, plus the verification instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchGrantExpectation {
    /// Verification instant.
    pub now_unix_ms: u64,
    /// Durable lease facts.
    pub lease: LeaseBinding,
    /// Evaluated admission facts.
    pub provider: ProviderBinding,
    /// Loaded policy facts.
    pub policy: PolicyBinding,
}

impl LaunchGrantExpectation {
    /// Compare every bound field; the first mismatch is reported by name.
    pub(crate) fn check_subject(&self, claims: &LaunchGrantClaims) -> Result<(), HarnessError> {
        let lease = &self.lease;
        let provider = &self.provider;
        let policy = &self.policy;
        let strings: [(&str, &str, &str); 21] = [
            ("mission_id", &claims.mission_id, &lease.mission_id),
            ("repository_id", &claims.repository_id, &lease.repository_id),
            (
                "graph_revision_id",
                &claims.graph_revision_id,
                &lease.graph_revision_id,
            ),
            (
                "work_package_id",
                &claims.work_package_id,
                &lease.work_package_id,
            ),
            ("variant_id", &claims.variant_id, &lease.variant_id),
            ("attempt_id", &claims.attempt_id, &lease.attempt_id),
            ("runner_id", &claims.runner_id, &lease.runner_id),
            ("workspace_id", &claims.workspace_id, &lease.workspace_id),
            (
                "workspace_nonce_digest",
                &claims.workspace_nonce_digest,
                &lease.workspace_nonce_digest,
            ),
            ("provider", &claims.provider, &provider.provider),
            ("adapter", &claims.adapter, &provider.adapter),
            (
                "provider_profile_id",
                &claims.provider_profile_id,
                &provider.provider_profile_id,
            ),
            ("model", &claims.model, &provider.model),
            ("protocol", &claims.protocol, provider.protocol.as_str()),
            (
                "executable_path",
                &claims.executable_path,
                &provider.executable_path,
            ),
            (
                "executable_digest",
                &claims.executable_digest,
                &provider.executable_digest,
            ),
            (
                "descriptor_digest",
                &claims.descriptor_digest,
                &provider.descriptor_digest,
            ),
            (
                "capability_digest",
                &claims.capability_digest,
                &provider.capability_digest,
            ),
            (
                "sandbox_manifest_digest",
                &claims.sandbox_manifest_digest,
                &provider.sandbox_manifest_digest,
            ),
            (
                "environment_digest",
                &claims.environment_digest,
                &provider.environment_digest,
            ),
            (
                "policy_snapshot_digest",
                &claims.policy_snapshot_digest,
                &policy.policy_snapshot_digest,
            ),
        ];
        for (field, actual, expected) in strings {
            if actual != expected {
                return Err(mismatch(field));
            }
        }
        let integers: [(&str, u64, u64); 6] = [
            ("attempt_fence", claims.attempt_fence, lease.attempt_fence),
            ("runner_epoch", claims.runner_epoch, lease.runner_epoch),
            (
                "authority_epoch",
                claims.authority_epoch,
                lease.authority_epoch,
            ),
            (
                "freeze_generation",
                claims.freeze_generation,
                lease.freeze_generation,
            ),
            (
                "credential_generation",
                claims.credential_generation,
                provider.credential_generation,
            ),
            (
                "policy_generation",
                claims.policy_generation,
                policy.policy_generation,
            ),
        ];
        for (field, actual, expected) in integers {
            if actual != expected {
                return Err(mismatch(field));
            }
        }
        Ok(())
    }
}

/// Framed digest binding a 32-byte workspace nonce without revealing it.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for an all-zero nonce.
pub fn workspace_nonce_digest(nonce: &[u8; 32]) -> Result<String, HarnessError> {
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(HarnessError::LaunchGrantInvalid {
            reason: "workspace nonce must not be all zero".to_string(),
        });
    }
    hash_framed_bytes(WORKSPACE_NONCE_DOMAIN, nonce)
}

/// Framed digest over the canonical JSON object of the sorted child
/// environment (bullet-wire `environment_digest`). Duplicate names, `=` or NUL
/// in a name, NUL in a value, or oversized entries are refused.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for a malformed environment.
pub fn environment_digest(env: &[(String, String)]) -> Result<String, HarnessError> {
    let mut sorted = BTreeMap::new();
    for (name, value) in env {
        if name.is_empty()
            || name.len() > 256
            || value.len() > 32_768
            || name.bytes().any(|byte| byte == b'=' || byte == 0)
            || value.bytes().any(|byte| byte == 0)
            || sorted.insert(name.clone(), value.clone()).is_some()
        {
            return Err(HarnessError::LaunchGrantInvalid {
                reason: "child environment names must be unique, bounded, and free of '=' and NUL"
                    .to_string(),
            });
        }
    }
    hash_canonical(ENVIRONMENT_DOMAIN, &sorted)
}

/// Framed digest of the exact loaded policy bytes (the pinned `policy.snapshot`
/// identity of canonical `policy.json`).
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for empty bytes.
pub fn policy_snapshot_digest(canonical_policy: &[u8]) -> Result<String, HarnessError> {
    if canonical_policy.is_empty() {
        return Err(HarnessError::LaunchGrantInvalid {
            reason: "policy snapshot bytes are empty".to_string(),
        });
    }
    hash_framed_bytes(POLICY_SNAPSHOT_DOMAIN, canonical_policy)
}

fn mismatch(field: &str) -> HarnessError {
    HarnessError::LaunchGrantSubjectMismatch {
        field: field.to_string(),
    }
}
