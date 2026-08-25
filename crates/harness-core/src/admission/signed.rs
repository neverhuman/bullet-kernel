//! Evidence that clears exactly one admission blocker each: a verified
//! Kernel launch grant for `SIGNED_ADMISSION_UNAVAILABLE`, and audited egress
//! isolation for `EGRESS_ISOLATION_UNAVAILABLE`. Nothing else removes a
//! blocker, and neither path spawns anything.

use super::receipt::AdmissionBlocker;
use super::EvaluatedAdmission;
use crate::error::HarnessError;
use crate::launch_grant::{environment_digest, is_lower_hex_64, VerifiedLaunchGrant};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Probe names an egress evidence bundle must contain: direct internet
/// egress and the host Jeryu endpoint (`bullet-harness-egress` receipts).
pub const REQUIRED_EGRESS_PROBES: [&str; 2] = ["direct-internet", "host-jeryu"];
const MAX_EGRESS_PROBES: usize = 32;

/// Non-secret record of the grant that cleared the signed-authority blocker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityRecord {
    /// Grant identifier.
    pub grant_id: String,
    /// Signing key label.
    pub key_id: String,
    /// Issuer label.
    pub issuer: String,
    /// Framed digest of the exact token bytes.
    pub envelope_digest: String,
    /// Exclusive grant expiry.
    pub expires_at_unix_ms: u64,
}

/// Observed outcome of one containment probe run from inside the sandbox.
/// Serialized as the bare variant name (`Refused`), matching the
/// `bullet-harness-egress` receipt evidence vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressProbeOutcome {
    /// The connection was actively refused.
    Refused,
    /// The destination was unreachable (no route, timeout inside bound).
    Unreachable,
    /// The destination answered; containment failed.
    Reached,
    /// The probe could not decide.
    Unknown,
}

/// One named probe and what it observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressProbe {
    /// Stable probe name.
    pub name: String,
    /// Observed outcome.
    pub outcome: EgressProbeOutcome,
}

/// Evidence produced by the egress containment backend (separate crate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressIsolationEvidence {
    /// Digest of the containment receipt.
    pub receipt_digest: String,
    /// Digest of the applied network ruleset.
    pub ruleset_digest: String,
    /// Digest of the provider host allowlist.
    pub allowlist_digest: String,
    /// Probes executed from inside the containment.
    pub probes: Vec<EgressProbe>,
}

/// Non-secret record of the evidence that cleared the egress blocker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressIsolationRecord {
    /// Digest of the containment receipt.
    pub receipt_digest: String,
    /// Digest of the applied network ruleset.
    pub ruleset_digest: String,
    /// Digest of the provider host allowlist.
    pub allowlist_digest: String,
    /// Exact probes admitted.
    pub probes: Vec<EgressProbe>,
}

impl EgressIsolationEvidence {
    fn validate(&self) -> Result<(), HarnessError> {
        for (name, value) in [
            ("receipt_digest", &self.receipt_digest),
            ("ruleset_digest", &self.ruleset_digest),
            ("allowlist_digest", &self.allowlist_digest),
        ] {
            if !is_lower_hex_64(value) {
                return Err(refused(&format!(
                    "egress {name} must be 64 lowercase hex characters"
                )));
            }
        }
        if self.probes.is_empty() || self.probes.len() > MAX_EGRESS_PROBES {
            return Err(refused("egress evidence must contain 1..=32 probes"));
        }
        let names: BTreeSet<&str> = self
            .probes
            .iter()
            .map(|probe| probe.name.as_str())
            .collect();
        if names.len() != self.probes.len() {
            return Err(refused("egress probe names must be unique"));
        }
        for required in REQUIRED_EGRESS_PROBES {
            if !names.contains(required) {
                return Err(refused(&format!("egress evidence lacks probe {required}")));
            }
        }
        for probe in &self.probes {
            if probe.name.is_empty()
                || probe.name.len() > 64
                || !probe
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(refused("egress probe names must be lowercase labels"));
            }
            if !matches!(
                probe.outcome,
                EgressProbeOutcome::Refused | EgressProbeOutcome::Unreachable
            ) {
                return Err(refused(&format!(
                    "egress probe {} observed {:?}; containment is not proven",
                    probe.name, probe.outcome
                )));
            }
        }
        Ok(())
    }
}

impl EvaluatedAdmission {
    /// Clear only `SIGNED_ADMISSION_UNAVAILABLE` with a verified grant whose
    /// provider binding equals this admission's own observed facts.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_SUBJECT_MISMATCH` naming the first differing field, or
    /// `ADMISSION_REFUSED` when the blocker was already cleared or the
    /// receipt cannot be resealed. On error the admission is dropped.
    pub fn admit_signed(mut self, grant: VerifiedLaunchGrant) -> Result<Self, HarnessError> {
        let claims = grant.claims();
        let receipt = &self.receipt;
        let executable = self.executable.to_string_lossy();
        let environment = environment_digest(self.home.env())?;
        let facts: [(&str, &str, &str); 8] = [
            ("provider", &claims.provider, &receipt.provider),
            ("executable_path", &claims.executable_path, &executable),
            (
                "executable_digest",
                &claims.executable_digest,
                &receipt.executable_blake3,
            ),
            (
                "descriptor_digest",
                &claims.descriptor_digest,
                &receipt.descriptor_blake3,
            ),
            (
                "capability_digest",
                &claims.capability_digest,
                &receipt.capability_blake3,
            ),
            (
                "provider_profile_id",
                &claims.provider_profile_id,
                &receipt.profile_id,
            ),
            (
                "protocol",
                &claims.protocol,
                receipt.current_protocol.as_str(),
            ),
            (
                "environment_digest",
                &claims.environment_digest,
                &environment,
            ),
        ];
        for (field, actual, expected) in facts {
            if actual != expected {
                return Err(HarnessError::LaunchGrantSubjectMismatch {
                    field: field.to_string(),
                });
            }
        }
        self.receipt.verify()?;
        if self.receipt.signed_authority.is_some() {
            return Err(refused("signed authority was already admitted"));
        }
        let record = SignedAuthorityRecord {
            grant_id: claims.grant_id.clone(),
            key_id: claims.key_id.clone(),
            issuer: claims.issuer.clone(),
            envelope_digest: grant.envelope_digest().to_string(),
            expires_at_unix_ms: claims.expires_at_unix_ms,
        };
        self.receipt.signed_authority = Some(record);
        self.receipt
            .clear_blocker(&AdmissionBlocker::SignedAuthorityUnavailable)?;
        Ok(self)
    }

    /// Clear only `EGRESS_ISOLATION_UNAVAILABLE` with evidence whose every
    /// probe observed refusal or unreachability.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` for malformed evidence, a probe that reached its
    /// destination, or an already-cleared blocker.
    pub fn admit_egress(mut self, evidence: EgressIsolationEvidence) -> Result<Self, HarnessError> {
        evidence.validate()?;
        self.receipt.verify()?;
        if self.receipt.egress_isolation.is_some() {
            return Err(refused("egress isolation was already admitted"));
        }
        self.receipt.egress_isolation = Some(EgressIsolationRecord {
            receipt_digest: evidence.receipt_digest,
            ruleset_digest: evidence.ruleset_digest,
            allowlist_digest: evidence.allowlist_digest,
            probes: evidence.probes,
        });
        self.receipt
            .clear_blocker(&AdmissionBlocker::EgressIsolationUnavailable)?;
        Ok(self)
    }
}

fn refused(reason: &str) -> HarnessError {
    HarnessError::AdmissionRefused {
        reason: reason.to_string(),
    }
}
