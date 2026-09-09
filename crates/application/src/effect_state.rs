//! Spec section 23.1 effect state machine. Every edge outside the table is
//! a typed refusal; a timeout after dispatch is `OUTCOME_UNKNOWN`, and the
//! only exits from `OUTCOME_UNKNOWN` are read-back reconciliation results.

use bullet_domain::DomainError;
use serde::{Deserialize, Serialize};

/// Durable effect phase per spec section 23.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectState {
    /// Intent recorded before authorization.
    Proposed,
    /// Internal authorization granted against a current fence.
    Authorized,
    /// External call in flight.
    Dispatching,
    /// Dispatch answered; read-back verification pending.
    ReceiptPending,
    /// Remote state read back and matched the desired hash.
    Verified,
    /// Receipt committed to the local ledger.
    Committed,
    /// Dispatch or read-back was lost; remote truth unestablished.
    OutcomeUnknown,
    /// Isolated pending investigation; no automatic retry.
    Quarantined,
    /// Refused or failed before any external mutation.
    Failed,
    /// Compensation required.
    CompensationPending,
    /// Compensation in flight.
    Compensating,
    /// Compensation observed on the remote.
    Compensated,
    /// A remote object exists with no local owner.
    OrphanedRemote,
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

impl EffectState {
    /// Apply one legal edge.
    ///
    /// The `OutcomeUnknown -> Dispatching` edge exists solely for a
    /// reconcile that proved non-execution; the broker is the only caller.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTransition` for any edge outside the machine.
    pub fn transition(self, to: Self) -> Result<Self, DomainError> {
        use EffectState::*;
        allow!(
            self,
            to,
            (Proposed, Authorized) => Authorized,
            (Proposed | Authorized, Failed) => Failed,
            (Authorized, Dispatching) => Dispatching,
            (Dispatching, ReceiptPending) => ReceiptPending,
            (Dispatching | ReceiptPending, OutcomeUnknown) => OutcomeUnknown,
            (ReceiptPending, Verified) => Verified,
            (OutcomeUnknown, Verified) => Verified,
            (OutcomeUnknown, Dispatching) => Dispatching,
            (OutcomeUnknown, OrphanedRemote) => OrphanedRemote,
            (Verified, Committed) => Committed,
            (Dispatching | ReceiptPending | OutcomeUnknown, Quarantined) => Quarantined,
            (Quarantined, CompensationPending) => CompensationPending,
            (CompensationPending, Compensating) => Compensating,
            (Compensating, Compensated) => Compensated,
        )
    }

    /// States that require reconciliation before any further dispatch.
    #[must_use]
    pub fn needs_reconcile(self) -> bool {
        matches!(self, Self::OutcomeUnknown)
    }

    /// Unresolved states: dispatched (or mid-dispatch) without a verified
    /// receipt or explicit terminal disposition.
    #[must_use]
    pub fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::Dispatching | Self::ReceiptPending | Self::OutcomeUnknown
        )
    }

    /// Normalize any restart-recoverable state to `OUTCOME_UNKNOWN` before a
    /// durable recovery claim is created. No other state enters recovery.
    pub fn normalize_unresolved_for_recovery(self) -> Result<Self, DomainError> {
        match self {
            Self::Dispatching | Self::ReceiptPending | Self::OutcomeUnknown => {
                Ok(Self::OutcomeUnknown)
            }
            other => Err(DomainError::InvalidTransition {
                from: other.as_str().into(),
                to: Self::OutcomeUnknown.as_str().into(),
            }),
        }
    }

    /// Absorbing states.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Failed | Self::Compensated | Self::OrphanedRemote
        )
    }

    /// Stable wire name. Matches the serde encoding.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Authorized => "AUTHORIZED",
            Self::Dispatching => "DISPATCHING",
            Self::ReceiptPending => "RECEIPT_PENDING",
            Self::Verified => "VERIFIED",
            Self::Committed => "COMMITTED",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Self::Quarantined => "QUARANTINED",
            Self::Failed => "FAILED",
            Self::CompensationPending => "COMPENSATION_PENDING",
            Self::Compensating => "COMPENSATING",
            Self::Compensated => "COMPENSATED",
            Self::OrphanedRemote => "ORPHANED_REMOTE",
        }
    }

    /// Parse a stable wire name.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` for any label outside the catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "PROPOSED" => Ok(Self::Proposed),
            "AUTHORIZED" => Ok(Self::Authorized),
            "DISPATCHING" => Ok(Self::Dispatching),
            "RECEIPT_PENDING" => Ok(Self::ReceiptPending),
            "VERIFIED" => Ok(Self::Verified),
            "COMMITTED" => Ok(Self::Committed),
            "OUTCOME_UNKNOWN" => Ok(Self::OutcomeUnknown),
            "QUARANTINED" => Ok(Self::Quarantined),
            "FAILED" => Ok(Self::Failed),
            "COMPENSATION_PENDING" => Ok(Self::CompensationPending),
            "COMPENSATING" => Ok(Self::Compensating),
            "COMPENSATED" => Ok(Self::Compensated),
            "ORPHANED_REMOTE" => Ok(Self::OrphanedRemote),
            other => Err(DomainError::UnknownState(format!("effect state {other}"))),
        }
    }

    /// Every state, for exhaustive edge-table tests.
    #[must_use]
    pub fn all() -> [Self; 13] {
        [
            Self::Proposed,
            Self::Authorized,
            Self::Dispatching,
            Self::ReceiptPending,
            Self::Verified,
            Self::Committed,
            Self::OutcomeUnknown,
            Self::Quarantined,
            Self::Failed,
            Self::CompensationPending,
            Self::Compensating,
            Self::Compensated,
            Self::OrphanedRemote,
        ]
    }
}
