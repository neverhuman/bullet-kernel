//! Canary inspection and deterministic local conformance receipts.

use super::credentials::CredentialReceipt;
use super::protocol::ProviderProtocol;
use super::signed::{EgressIsolationRecord, SignedAuthorityRecord};
use crate::error::HarnessError;
use crate::event::{AgentEvent, AgentEventKind};
use crate::proposal::PatchProposal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A reason live dispatch remains unavailable after local checks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionBlocker {
    /// No Kernel-signed short-lived authority validator is wired here.
    SignedAuthorityUnavailable,
    /// No audited provider-only network containment backend is installed.
    EgressIsolationUnavailable,
    /// Runtime protocol differs from the required V1 protocol.
    ProtocolNonconformant,
    /// One required capability is not conformant.
    CapabilityNonconformant,
}

impl AdmissionBlocker {
    /// Stable blocker code.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SignedAuthorityUnavailable => "SIGNED_ADMISSION_UNAVAILABLE",
            Self::EgressIsolationUnavailable => "EGRESS_ISOLATION_UNAVAILABLE",
            Self::ProtocolNonconformant => "PROTOCOL_NONCONFORMANT",
            Self::CapabilityNonconformant => "CAPABILITY_NONCONFORMANT",
        }
    }
}

/// Secret canaries injected only into the hostile test/input environment.
#[derive(Clone, Debug)]
pub struct CanarySecrets(Vec<String>);

impl CanarySecrets {
    /// Validate a small unique set. Values are never serialized into receipts.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` for weak or duplicate canaries.
    pub fn new(values: Vec<String>) -> Result<Self, HarnessError> {
        let unique: BTreeSet<&str> = values.iter().map(String::as_str).collect();
        if values.is_empty()
            || values.len() > 8
            || unique.len() != values.len()
            || values.iter().any(|value| value.len() < 16)
        {
            return Err(HarnessError::AdmissionRefused {
                reason: "canaries must be 1..=8 unique values of at least 16 bytes".into(),
            });
        }
        Ok(Self(values))
    }

    pub(crate) fn inspect(&self, surface: &'static str, bytes: &[u8]) -> Result<(), HarnessError> {
        if self
            .0
            .iter()
            .any(|secret| contains(bytes, secret.as_bytes()))
        {
            return Err(HarnessError::SecretCanaryExposure { surface });
        }
        Ok(())
    }

    pub(crate) fn inspect_env(&self, env: &[(String, String)]) -> Result<(), HarnessError> {
        for (key, value) in env {
            self.inspect("environment", key.as_bytes())?;
            self.inspect("environment", value.as_bytes())?;
        }
        Ok(())
    }
}

/// Offline evidence submitted to the admission evaluator.
pub struct ConformanceEvidence<'a> {
    /// Complete stdout bytes (or fixture bytes in an offline check).
    pub stdout: &'a [u8],
    /// Complete stderr bytes.
    pub stderr: &'a [u8],
    /// Normalized events for exactly one invocation.
    pub events: &'a [AgentEvent],
    /// Validated proposal that would be admitted to the writer.
    pub proposal: &'a PatchProposal,
}

impl ConformanceEvidence<'_> {
    pub(crate) fn validate(
        &self,
        provider: &str,
        canaries: &CanarySecrets,
    ) -> Result<EvidenceCommitments, HarnessError> {
        canaries.inspect("stdout", self.stdout)?;
        canaries.inspect("stderr", self.stderr)?;
        let event_bytes =
            serde_json::to_vec(self.events).map_err(|error| HarnessError::AdmissionRefused {
                reason: format!("event serialization failed: {error}"),
            })?;
        canaries.inspect("event_log", &event_bytes)?;
        validate_invocation_events(provider, self.events)?;
        self.proposal.validate()?;
        let proposal =
            serde_json::to_vec(self.proposal).map_err(|error| HarnessError::AdmissionRefused {
                reason: format!("proposal serialization failed: {error}"),
            })?;
        canaries.inspect("accepted_patch", &proposal)?;
        Ok(EvidenceCommitments {
            stdout_blake3: artifact_digest(b"stdout", self.stdout),
            stderr_blake3: artifact_digest(b"stderr", self.stderr),
            events_blake3: artifact_digest(b"events", &event_bytes),
            proposal_blake3: artifact_digest(b"proposal", &proposal),
        })
    }
}

pub(crate) struct EvidenceCommitments {
    pub stdout_blake3: String,
    pub stderr_blake3: String,
    pub events_blake3: String,
    pub proposal_blake3: String,
}

/// Durable-shaped local receipt. It is deliberately not a signed authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConformanceReceipt {
    /// Domain-separated digest of every following field.
    pub receipt_id: String,
    /// Provider wire name.
    pub provider: String,
    /// Exact canonical executable path.
    pub executable: String,
    /// Exact executable bytes.
    pub executable_blake3: String,
    /// Exact probed version.
    pub version: String,
    /// Exact capability matrix digest.
    pub capability_blake3: String,
    /// Exact complete runtime descriptor digest.
    pub descriptor_blake3: String,
    /// Authorized Kernel profile identifier.
    pub profile_id: String,
    /// Exact verified probe identity digest.
    pub profile_blake3: String,
    /// Exact positive child environment digest.
    pub environment_blake3: String,
    /// Protocol reported by the runtime probe.
    pub current_protocol: ProviderProtocol,
    /// Frozen protocol required for V1.
    pub required_protocol: ProviderProtocol,
    /// Runtime probe observation time.
    pub probed_at: DateTime<Utc>,
    /// Evaluation time.
    pub evaluated_at: DateTime<Utc>,
    /// Non-secret staged credential commitments.
    pub credentials: Vec<CredentialReceipt>,
    /// Digest of the accepted proposal bytes.
    pub proposal_blake3: String,
    /// Digest of complete captured stdout bytes.
    pub stdout_blake3: String,
    /// Digest of complete captured stderr bytes.
    pub stderr_blake3: String,
    /// Digest of the normalized event log.
    pub events_blake3: String,
    /// Surfaces checked for canary leakage.
    pub canary_surfaces: Vec<String>,
    /// Complete sorted reasons dispatch remains blocked.
    pub blockers: Vec<AdmissionBlocker>,
    /// Verified Kernel grant that cleared `SIGNED_ADMISSION_UNAVAILABLE`.
    #[serde(default)]
    pub signed_authority: Option<SignedAuthorityRecord>,
    /// Audited evidence that cleared `EGRESS_ISOLATION_UNAVAILABLE`.
    #[serde(default)]
    pub egress_isolation: Option<EgressIsolationRecord>,
}

/// Inputs to deterministic receipt construction.
pub(crate) struct ReceiptInput<'a> {
    pub provider: &'a str,
    pub executable: &'a str,
    pub executable_blake3: &'a str,
    pub version: &'a str,
    pub capability_blake3: &'a str,
    pub descriptor_blake3: &'a str,
    pub profile_id: &'a str,
    pub profile_blake3: &'a str,
    pub environment_blake3: &'a str,
    pub current_protocol: ProviderProtocol,
    pub required_protocol: ProviderProtocol,
    pub probed_at: DateTime<Utc>,
    pub evaluated_at: DateTime<Utc>,
    pub credentials: &'a [CredentialReceipt],
    pub evidence: &'a EvidenceCommitments,
    pub blockers: &'a BTreeSet<AdmissionBlocker>,
}

impl ProviderConformanceReceipt {
    pub(crate) fn from_input(input: ReceiptInput<'_>) -> Result<Self, HarnessError> {
        let blockers: Vec<_> = input.blockers.iter().cloned().collect();
        let canary_surfaces = [
            "environment",
            "stdout",
            "stderr",
            "event_log",
            "accepted_patch",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut receipt = Self {
            receipt_id: String::new(),
            provider: input.provider.to_string(),
            executable: input.executable.to_string(),
            executable_blake3: input.executable_blake3.to_string(),
            version: input.version.to_string(),
            capability_blake3: input.capability_blake3.to_string(),
            descriptor_blake3: input.descriptor_blake3.to_string(),
            profile_id: input.profile_id.to_string(),
            profile_blake3: input.profile_blake3.to_string(),
            environment_blake3: input.environment_blake3.to_string(),
            current_protocol: input.current_protocol,
            required_protocol: input.required_protocol,
            probed_at: input.probed_at,
            evaluated_at: input.evaluated_at,
            credentials: input.credentials.to_vec(),
            proposal_blake3: input.evidence.proposal_blake3.clone(),
            stdout_blake3: input.evidence.stdout_blake3.clone(),
            stderr_blake3: input.evidence.stderr_blake3.clone(),
            events_blake3: input.evidence.events_blake3.clone(),
            canary_surfaces,
            blockers,
            signed_authority: None,
            egress_isolation: None,
        };
        receipt.receipt_id = receipt.seal_digest()?;
        Ok(receipt)
    }

    /// A serialized receipt is never spawn authority: it fails on its first
    /// blocker and, with none recorded, as `UNSIGNED_RECEIPT`. Only a live
    /// `EvaluatedAdmission` that cleared every blocker with evidence can
    /// dispatch.
    ///
    /// # Errors
    ///
    /// Always `PROVIDER_ADMISSION_BLOCKED` (or `ADMISSION_REFUSED` on tamper).
    pub fn require_dispatch(&self) -> Result<(), HarnessError> {
        self.verify()?;
        Err(HarnessError::AdmissionBlocked {
            blocker: self.first_blocker().to_string(),
        })
    }

    /// First remaining blocker code, or `UNSIGNED_RECEIPT` when none remain.
    #[must_use]
    pub fn first_blocker(&self) -> &'static str {
        self.blockers
            .first()
            .map(AdmissionBlocker::as_str)
            .unwrap_or("UNSIGNED_RECEIPT")
    }

    /// Recompute the domain-separated receipt identifier.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` if the receipt was modified or cannot serialize.
    pub fn verify(&self) -> Result<(), HarnessError> {
        if self.receipt_id != self.seal_digest()? {
            return Err(HarnessError::AdmissionRefused {
                reason: "provider conformance receipt digest mismatch".into(),
            });
        }
        Ok(())
    }

    /// Remove exactly one present blocker and reseal. Callers verify the
    /// receipt before recording the clearing evidence and calling this.
    pub(crate) fn clear_blocker(&mut self, blocker: &AdmissionBlocker) -> Result<(), HarnessError> {
        let Some(index) = self.blockers.iter().position(|present| present == blocker) else {
            return Err(HarnessError::AdmissionRefused {
                reason: format!("blocker {} is not present", blocker.as_str()),
            });
        };
        self.blockers.remove(index);
        self.receipt_id = self.seal_digest()?;
        Ok(())
    }

    fn seal_digest(&self) -> Result<String, HarnessError> {
        let mut unsigned = self.clone();
        unsigned.receipt_id = String::new();
        let bytes =
            serde_json::to_vec(&unsigned).map_err(|error| HarnessError::AdmissionRefused {
                reason: format!("receipt serialization failed: {error}"),
            })?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bullet-provider-conformance-receipt-v1\0");
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

fn validate_invocation_events(provider: &str, events: &[AgentEvent]) -> Result<(), HarnessError> {
    let mut ids = BTreeSet::new();
    let mut last_sequence = None;
    let mut started = 0_u8;
    let mut completed = 0_u8;
    let mut failed = 0_u8;
    let mut closed = false;
    for event in events {
        if event.provider != provider
            || !ids.insert(event.event_id.as_str())
            || last_sequence.is_some_and(|sequence| event.sequence <= sequence)
        {
            return Err(protocol(provider, "duplicate or out-of-order envelope"));
        }
        last_sequence = Some(event.sequence);
        if event.kind == AgentEventKind::ProtocolError {
            return Err(protocol(
                provider,
                "provider stream contains protocol.error",
            ));
        }
        if event.kind == AgentEventKind::TurnStarted {
            if closed {
                return Err(protocol(
                    provider,
                    "delayed turn started after terminal event",
                ));
            }
            started = started.saturating_add(1);
        }
        if closed
            && matches!(
                event.kind,
                AgentEventKind::TurnDelta
                    | AgentEventKind::ThinkingDelta
                    | AgentEventKind::ToolRequested
                    | AgentEventKind::ToolStarted
                    | AgentEventKind::ToolCompleted
                    | AgentEventKind::ToolFailed
            )
        {
            return Err(protocol(
                provider,
                "delayed event arrived after turn terminal",
            ));
        }
        match event.kind {
            AgentEventKind::TurnCompleted => {
                completed = completed.saturating_add(1);
                closed = true;
            }
            AgentEventKind::TurnFailed => {
                failed = failed.saturating_add(1);
                closed = true;
            }
            _ => {}
        }
    }
    if started != 1 || completed != 1 || failed != 0 {
        return Err(protocol(
            provider,
            "invocation must contain exactly one turn start and successful terminal",
        ));
    }
    Ok(())
}

fn protocol(provider: &str, reason: &str) -> HarnessError {
    HarnessError::Protocol {
        provider: provider.to_string(),
        reason: reason.to_string(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn artifact_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bullet-provider-conformance-artifact-v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}
