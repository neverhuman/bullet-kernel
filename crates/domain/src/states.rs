//! Explicit state machines. Prompt compliance is not a transition.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// Mission lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionState {
    /// Not yet admitted.
    Draft,
    /// Acceptance contract frozen.
    Admitted,
    /// Planning collaboration in progress.
    Planning,
    /// Graph materialized and work may run.
    Active,
    /// Integrated and watching.
    Observing,
    /// Observation window passed.
    Survived,
    /// Rejected or reverted.
    Rejected,
}

/// Work package lifecycle per spec section 24.1. Integration is repository truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkPackageState {
    /// Waiting on dependencies.
    Pending,
    /// Eligible for dispatch.
    Ready,
    /// A fenced writer lease is granted.
    Leased,
    /// The fenced Attempt is writing.
    Executing,
    /// Candidate prepared, not yet verified.
    Prepared,
    /// Independent verification is running.
    Verifying,
    /// Independent evidence attached.
    Verified,
    /// Semantic review of the exact Candidate.
    Reviewing,
    /// All gates passed; queued for integration.
    IntegrationReady,
    /// Landing on the protected target.
    Integrating,
    /// Landed on the protected target.
    Integrated,
    /// Post-integration observation window.
    Observing,
    /// Observation passed.
    Survived,
    /// Progress stalled; salvage evaluation running.
    Struggling,
    /// Escalated for replan or human decision.
    Escalating,
    /// Isolated pending investigation.
    Quarantined,
    /// Cancelled by operator or policy.
    Cancelled,
    /// Terminal failure after retries.
    Failed,
    /// Integration was reverted from the target.
    Reverted,
    /// Rejected by contract or policy.
    Rejected,
}

/// Attempt incarnation per spec section 24.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Row exists; lease not yet granted to a runner session.
    Created,
    /// Lease granted, session starting.
    Starting,
    /// Writer is live.
    Running,
    /// Writer paused by policy or operator.
    Paused,
    /// Durable checkpoint in progress.
    Checkpointing,
    /// Preparing an exact Candidate.
    Preparing,
    /// Incarnation finished with a Candidate.
    Succeeded,
    /// A successor fence exists. Absorbing; cannot act.
    Superseded,
    /// Terminal failure.
    Failed,
    /// Runner or session died; detected by lease expiry.
    Crashed,
    /// Cancelled by operator or policy.
    Cancelled,
    /// Isolated pending investigation.
    Quarantined,
}

/// Command acknowledgement distinct from verified effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandPhase {
    /// Recorded, not yet applied.
    Pending,
    /// Durable local transition applied.
    Applied,
    /// Command was durably refused; the stored response explains why.
    Failed,
    /// External postcondition observed.
    Verified,
    /// Probe did not establish the effect.
    Unknown,
}

impl CommandPhase {
    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Verified => "verified",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a stable wire name.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` for any label outside the catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            "verified" => Ok(Self::Verified),
            "unknown" => Ok(Self::Unknown),
            other => Err(DomainError::UnknownState(format!("command phase {other}"))),
        }
    }
}

macro_rules! allow {
    ($from:expr, $to:expr, $($ok:pat => $dst:expr),+ $(,)?) => {
        match ($from, $to) {
            $($ok => Ok($dst),)+
            _ => Err(DomainError::InvalidTransition {
                from: format!("{:?}", $from),
                to: format!("{:?}", $to),
            }),
        }
    };
}

impl MissionState {
    /// Apply one legal edge.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTransition` for any edge outside the machine.
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use MissionState::*;
        allow!(
            self,
            to,
            (Draft, Admitted) => Admitted,
            (Admitted, Planning) => Planning,
            (Planning, Active) => Active,
            (Active, Observing) => Observing,
            (Observing, Survived) => Survived,
            (Draft | Admitted | Planning | Active | Observing, Rejected) => Rejected,
        )
    }
}

impl WorkPackageState {
    /// Apply one legal edge.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTransition` for any edge outside the machine.
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use WorkPackageState::*;
        allow!(
            self,
            to,
            (Pending, Ready) => Ready,
            (Ready, Pending) => Pending,
            (Ready, Leased) => Leased,
            (Leased, Executing) => Executing,
            (Leased | Executing, Ready) => Ready,
            (Executing, Prepared) => Prepared,
            (Prepared, Verifying) => Verifying,
            (Verifying, Verified) => Verified,
            (Verified, Reviewing) => Reviewing,
            (Reviewing, IntegrationReady) => IntegrationReady,
            (IntegrationReady, Integrating) => Integrating,
            (Integrating, Integrated) => Integrated,
            (Integrated, Observing) => Observing,
            (Observing, Survived) => Survived,
            (Executing, Struggling) => Struggling,
            (Struggling | Escalating, Executing) => Executing,
            (Struggling, Escalating) => Escalating,
            (Integrated | Observing, Reverted) => Reverted,
            (
                Pending | Ready | Leased | Executing | Prepared | Verifying | Verified
                    | Reviewing | IntegrationReady | Integrating | Struggling | Escalating,
                Rejected
            ) => Rejected,
            (
                Pending | Ready | Leased | Executing | Prepared | Verifying | Verified
                    | Reviewing | IntegrationReady | Integrating | Struggling | Escalating,
                Failed
            ) => Failed,
            (
                Pending | Ready | Leased | Executing | Prepared | Verifying | Verified
                    | Reviewing | IntegrationReady | Integrating | Struggling | Escalating,
                Cancelled
            ) => Cancelled,
            (
                Pending | Ready | Leased | Executing | Prepared | Verifying | Verified
                    | Reviewing | IntegrationReady | Integrating | Struggling | Escalating,
                Quarantined
            ) => Quarantined,
        )
    }

    /// Stable wire name. Matches the serde encoding.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Leased => "leased",
            Self::Executing => "executing",
            Self::Prepared => "prepared",
            Self::Verifying => "verifying",
            Self::Verified => "verified",
            Self::Reviewing => "reviewing",
            Self::IntegrationReady => "integration_ready",
            Self::Integrating => "integrating",
            Self::Integrated => "integrated",
            Self::Observing => "observing",
            Self::Survived => "survived",
            Self::Struggling => "struggling",
            Self::Escalating => "escalating",
            Self::Quarantined => "quarantined",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Reverted => "reverted",
            Self::Rejected => "rejected",
        }
    }
}

impl AttemptState {
    /// Apply one legal edge. Superseded is absorbing for writes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTransition` for any edge outside the machine.
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use AttemptState::*;
        allow!(
            self,
            to,
            (Created, Starting) => Starting,
            (Starting, Running) => Running,
            (Running, Paused) => Paused,
            (Paused | Checkpointing, Running) => Running,
            (Running, Checkpointing) => Checkpointing,
            (Running | Checkpointing, Preparing) => Preparing,
            (Preparing, Succeeded) => Succeeded,
            (
                Created | Starting | Running | Paused | Checkpointing | Preparing,
                Superseded
            ) => Superseded,
            (
                Created | Starting | Running | Paused | Checkpointing | Preparing,
                Failed
            ) => Failed,
            (
                Created | Starting | Running | Paused | Checkpointing | Preparing,
                Crashed
            ) => Crashed,
            (
                Created | Starting | Running | Paused | Checkpointing | Preparing,
                Cancelled
            ) => Cancelled,
            (
                Created | Starting | Running | Paused | Checkpointing | Preparing,
                Quarantined
            ) => Quarantined,
        )
    }

    /// Whether a persisted active lease may accept a heartbeat in this state.
    #[must_use]
    pub fn permits_lease_heartbeat(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::Paused | Self::Checkpointing | Self::Preparing
        )
    }

    /// Whether an online authority check may observe this Attempt as the
    /// holder of an active lease. This observation is not mutation authority.
    #[must_use]
    pub fn permits_online_lease_check(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::Paused | Self::Checkpointing | Self::Preparing
        )
    }

    /// Whether a token may authorize applying a patch to the private workspace.
    #[must_use]
    pub fn permits_patch_application(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether expiry may move the active lease holder to `Crashed`.
    #[must_use]
    pub fn permits_expiry_reclaim(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::Paused | Self::Checkpointing | Self::Preparing
        )
    }

    /// Whether a release request names an absorbing terminal state.
    #[must_use]
    pub fn is_terminal_release_target(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Superseded
                | Self::Failed
                | Self::Crashed
                | Self::Cancelled
                | Self::Quarantined
        )
    }

    /// Whether this Attempt belongs in the active-attempt projection.
    #[must_use]
    pub fn appears_in_active_attempt_projection(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::Paused | Self::Checkpointing | Self::Preparing
        )
    }

    /// Whether exact preservation may authorize cleanup after lease release.
    #[must_use]
    pub fn permits_preserved_workspace_cleanup(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Superseded | Self::Failed | Self::Crashed | Self::Cancelled
        )
    }

    /// Stable wire name. Matches the serde encoding.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Checkpointing => "checkpointing",
            Self::Preparing => "preparing",
            Self::Succeeded => "succeeded",
            Self::Superseded => "superseded",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantined",
        }
    }

    /// Parse a stable wire name.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` for any label outside the catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "created" => Ok(Self::Created),
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "paused" => Ok(Self::Paused),
            "checkpointing" => Ok(Self::Checkpointing),
            "preparing" => Ok(Self::Preparing),
            "succeeded" => Ok(Self::Succeeded),
            "superseded" => Ok(Self::Superseded),
            "failed" => Ok(Self::Failed),
            "crashed" => Ok(Self::Crashed),
            "cancelled" => Ok(Self::Cancelled),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(DomainError::UnknownState(format!("attempt state {other}"))),
        }
    }
}
