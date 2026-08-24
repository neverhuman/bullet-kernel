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

/// Work package lifecycle. `integrated` is repository truth, not agent exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkPackageState {
    /// Waiting on dependencies.
    Pending,
    /// Eligible for dispatch.
    Ready,
    /// A fenced Attempt is writing.
    Running,
    /// Candidate prepared, not yet verified.
    Prepared,
    /// Independent evidence attached.
    Verified,
    /// Landed on the protected target.
    Integrated,
    /// Observation passed.
    Survived,
    /// Terminal failure.
    Rejected,
}

/// Attempt incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Lease granted, not yet acknowledged.
    Dispatched,
    /// Structured accept received.
    Accepted,
    /// Writer is live.
    Executing,
    /// Preparing a Candidate.
    Finalizing,
    /// Incarnation finished without further writes.
    Closed,
    /// Superseded. Cannot act.
    Stale,
}

/// Command acknowledgement distinct from verified effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandPhase {
    /// Recorded, not yet applied.
    Pending,
    /// Durable local transition applied.
    Applied,
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
            Self::Verified => "verified",
            Self::Unknown => "unknown",
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
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use WorkPackageState::*;
        allow!(
            self,
            to,
            (Pending, Ready) => Ready,
            (Ready, Running) => Running,
            (Running, Prepared) => Prepared,
            (Prepared, Verified) => Verified,
            (Verified, Integrated) => Integrated,
            (Integrated, Survived) => Survived,
            (Pending | Ready | Running | Prepared | Verified, Rejected) => Rejected,
        )
    }
}

impl AttemptState {
    /// Apply one legal edge. Stale is absorbing for writes.
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use AttemptState::*;
        allow!(
            self,
            to,
            (Dispatched, Accepted) => Accepted,
            (Accepted, Executing) => Executing,
            (Executing, Finalizing) => Finalizing,
            (Dispatched | Accepted | Executing | Finalizing, Closed) => Closed,
            (Dispatched | Accepted | Executing | Finalizing, Stale) => Stale,
        )
    }

    /// Stale attempts cannot heartbeat, expand scope, or create effects.
    #[must_use]
    pub fn may_mutate(self) -> bool {
        matches!(
            self,
            Self::Dispatched | Self::Accepted | Self::Executing | Self::Finalizing
        )
    }
}
