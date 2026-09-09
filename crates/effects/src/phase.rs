//! Spec §23.1 effect phases. Timeout is OUTCOME_UNKNOWN, never VERIFIED.

/// Durable effect phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectPhase {
    /// Intent recorded, not authorized.
    Proposed,
    /// Internal authorization granted.
    Authorized,
    /// External call in flight.
    Dispatching,
    /// Waiting for a read-back.
    ReceiptPending,
    /// Remote state matched the desired hash.
    Verified,
    /// Local ledger committed the receipt.
    Committed,
    /// Dispatch timed out or read-back failed.
    OutcomeUnknown,
    /// Isolated pending investigation.
    Quarantined,
    /// Terminal failure after reconciliation.
    Failed,
    /// Compensation required.
    CompensationPending,
    /// Compensation in flight.
    Compensating,
    /// Compensation observed.
    Compensated,
    /// Remote object exists with no local owner.
    OrphanedRemote,
}

impl EffectPhase {
    /// Stable wire name.
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

    /// Timeout after dispatch is UNKNOWN, never success.
    #[must_use]
    pub fn after_timeout(self) -> Self {
        match self {
            Self::Dispatching | Self::ReceiptPending => Self::OutcomeUnknown,
            other => other,
        }
    }

    /// UNKNOWN is not a verified effect.
    #[must_use]
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified | Self::Committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_unknown_not_verified() {
        assert_eq!(
            EffectPhase::Dispatching.after_timeout(),
            EffectPhase::OutcomeUnknown
        );
        assert!(!EffectPhase::OutcomeUnknown.is_verified());
    }
}
