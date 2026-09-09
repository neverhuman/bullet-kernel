//! Four-valued observations. Read failure is never empty or healthy.

use crate::{Attempt, AttemptId, Digest, DomainError, WorkspaceId};
use serde::{Deserialize, Serialize};

/// Observation of an external or derived fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation<T> {
    /// A verified value.
    Value {
        /// Observed payload.
        value: T,
    },
    /// Authoritative absence.
    Empty,
    /// The probe did not establish a value.
    Unknown {
        /// Probe identity.
        source: String,
        /// Why the value is unknown.
        reason: String,
    },
    /// Distinct sources disagree.
    Contradictory {
        /// Disagreeing sources.
        sources: Vec<String>,
        /// Human-readable conflict.
        reason: String,
    },
}

impl<T> Observation<T> {
    /// Construct a verified value.
    #[must_use]
    pub fn value(value: T) -> Self {
        Self::Value { value }
    }

    /// True only for a verified value. Never treat unknown as success.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    /// Serialize the discriminant for APIs that must not collapse unknowns.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Value { .. } => "value",
            Self::Empty => "empty",
            Self::Unknown { .. } => "unknown",
            Self::Contradictory { .. } => "contradictory",
        }
    }
}

/// Destructive operation bound by a preservation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationOperation {
    /// Delete the exact private workspace generation after preservation.
    CleanupWorkspace,
}

/// Outcome reported by the preservation authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreservationOutcome {
    /// The exact workspace was durably preserved.
    Preserved,
    /// Preservation ran and failed.
    Failed,
    /// The authority does not support the requested preservation operation.
    Unsupported,
    /// The authority returned an error.
    Error,
    /// The authority could not establish an outcome.
    Unknown,
    /// A successor Attempt invalidated this preservation result.
    Superseded,
}

/// Exact workspace subject named by a preservation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservationSubject {
    /// Attempt whose private workspace was preserved.
    pub attempt_id: AttemptId,
    /// Permanent Attempt fence.
    pub fence: u64,
    /// Exact private workspace.
    pub workspace_id: WorkspaceId,
    /// Workspace generation nonce.
    pub workspace_nonce: [u8; 32],
}

impl PreservationSubject {
    /// Bind the immutable workspace identity of an Attempt.
    #[must_use]
    pub fn from_attempt(attempt: &Attempt) -> Self {
        Self {
            attempt_id: attempt.id.clone(),
            fence: attempt.fence,
            workspace_id: attempt.workspace_id.clone(),
            workspace_nonce: attempt.workspace_nonce,
        }
    }
}

/// Typed result carried inside a four-valued observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservationRecord {
    /// Exact subject the daemon preserved.
    pub subject: PreservationSubject,
    /// Destructive operation this record may precede.
    pub operation: PreservationOperation,
    /// Digest of the durable daemon-issued receipt.
    pub receipt_digest: Digest,
    /// Typed preservation outcome. Only `Preserved` may authorize.
    pub outcome: PreservationOutcome,
}

impl PreservationRecord {
    /// Build an exact preservation result for one Attempt.
    #[must_use]
    pub fn for_attempt(
        attempt: &Attempt,
        operation: PreservationOperation,
        receipt_digest: Digest,
        outcome: PreservationOutcome,
    ) -> Self {
        Self {
            subject: PreservationSubject::from_attempt(attempt),
            operation,
            receipt_digest,
            outcome,
        }
    }
}

/// Non-serializable, exact-subject cleanup decision.
///
/// Its fields are private so an external observation cannot be re-labeled as
/// authority. Construction requires a positive, exact preservation record.
#[must_use = "a preservation decision must be consumed by the exact cleanup operation"]
#[derive(Debug, PartialEq, Eq)]
pub struct PreservationDecision {
    subject: PreservationSubject,
    operation: PreservationOperation,
    receipt_digest: Digest,
}

impl PreservationDecision {
    /// Construct an exact post-terminal workspace-cleanup decision.
    ///
    /// # Errors
    ///
    /// Refuses every non-value observation, every non-preserved outcome, a
    /// mismatched subject, a live writer, and a quarantined Attempt pending
    /// explicit operator policy.
    pub fn for_workspace_cleanup(
        observation: &Observation<PreservationRecord>,
        attempt: &Attempt,
    ) -> Result<Self, DomainError> {
        if !attempt.state.permits_preserved_workspace_cleanup() {
            return Err(Self::refusal(attempt, "Attempt state cannot clean up"));
        }
        let record = match observation {
            Observation::Value { value } => value,
            other => {
                return Err(Self::refusal(
                    attempt,
                    &format!("preservation observation is {}", other.kind_name()),
                ));
            }
        };
        if record.outcome != PreservationOutcome::Preserved {
            return Err(Self::refusal(
                attempt,
                &format!("preservation outcome is {:?}", record.outcome),
            ));
        }
        if record.operation != PreservationOperation::CleanupWorkspace
            || record.subject != PreservationSubject::from_attempt(attempt)
        {
            return Err(Self::refusal(
                attempt,
                "preservation subject or operation does not match",
            ));
        }
        Ok(Self {
            subject: record.subject.clone(),
            operation: record.operation,
            receipt_digest: record.receipt_digest,
        })
    }

    /// Consume the decision immediately before exact terminal-workspace cleanup.
    ///
    /// # Errors
    ///
    /// Refuses when the Attempt subject or state changed after construction.
    pub fn authorize_workspace_cleanup(self, attempt: &Attempt) -> Result<Digest, DomainError> {
        if self.operation != PreservationOperation::CleanupWorkspace
            || self.subject != PreservationSubject::from_attempt(attempt)
            || !attempt.state.permits_preserved_workspace_cleanup()
        {
            return Err(Self::refusal(
                attempt,
                "cleanup decision is stale or mismatched",
            ));
        }
        Ok(self.receipt_digest)
    }

    fn refusal(attempt: &Attempt, reason: &str) -> DomainError {
        DomainError::StaleAuthority(format!("{reason} for {}", attempt.id))
    }
}

impl Observation<String> {
    /// Render for operator surfaces. Unknown stays unknown.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Value { value } => value.clone(),
            Self::Empty => "empty".to_string(),
            Self::Unknown { source, reason } => format!("unknown ({source}: {reason})"),
            Self::Contradictory { reason, .. } => format!("contradictory ({reason})"),
        }
    }
}
