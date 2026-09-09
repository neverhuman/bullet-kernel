//! Stable refusal vocabulary for signed lease transport.

use crate::store::LedgerError;
use bullet_harness_core::lease_transport::LeaseTransportError;

/// Service-level refusal.
#[derive(Debug, thiserror::Error)]
pub enum SignedLeaseError {
    /// Permit verification failed.
    #[error(transparent)]
    Transport(LeaseTransportError),
    /// Ledger refused the operation.
    #[error(transparent)]
    Ledger(LedgerError),
    /// A general readback or Attempt subject is unavailable.
    #[error("lease transport unknown")]
    Unknown,
    /// Active readback proved that no strict grant row exists for the exact key.
    #[error("lease transport grant absent")]
    GrantAbsent,
    /// Historical terminal readback proved that no exact settlement row exists.
    #[error("lease transport settlement absent")]
    SettlementAbsent,
    /// The presented Attempt's fence is not the active lease's fence.
    #[error("lease fence stale: attempt fence {attempt_fence}, lease fence {lease_fence}")]
    FenceStale {
        /// Presented Attempt fence.
        attempt_fence: u64,
        /// Active lease fence.
        lease_fence: u64,
    },
    /// No active, unexpired lease backs the presented Attempt.
    #[error("lease not active: {reason}")]
    NotActive {
        /// Store-side detail.
        reason: String,
    },
    /// The requested edge `from -> to` is outside the Attempt state machine.
    #[error("attempt transition illegal: {from} -> {to}")]
    TransitionIllegal {
        /// Current state.
        from: &'static str,
        /// Requested state.
        to: &'static str,
    },
}

impl SignedLeaseError {
    /// Stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Transport(error) => error.reason_code(),
            Self::Ledger(error) => error.reason_code(),
            Self::Unknown => "LEASE_TRANSPORT_UNKNOWN",
            Self::GrantAbsent => "LEASE_TRANSPORT_GRANT_ABSENT",
            Self::SettlementAbsent => "LEASE_TRANSPORT_SETTLEMENT_ABSENT",
            Self::FenceStale { .. } => "LEASE_FENCE_STALE",
            Self::NotActive { .. } => "LEASE_NOT_ACTIVE",
            Self::TransitionIllegal { .. } => "ATTEMPT_TRANSITION_ILLEGAL",
        }
    }
}

impl From<LedgerError> for SignedLeaseError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}
