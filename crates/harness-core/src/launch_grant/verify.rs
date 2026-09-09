//! Fail-closed launch-grant verification. Authentication first, then shape,
//! subject, time, policy, and finally the single side effect: nonce
//! consumption (same check order as bullet-wire, plus policy and nonce). Any
//! failure leaves the admission blocker in place.

use super::claims::{LaunchGrantClaims, SignedLaunchGrant};
use super::expectation::LaunchGrantExpectation;
use super::keys::LaunchGrantVerificationKey;
use super::nonce::{LaunchGrantNonceLedger, NonceConsumption};
use crate::error::HarnessError;

/// A grant that passed every check against one exact expectation. It cannot
/// be cloned, serialized, or constructed outside `verify_launch_grant`.
#[derive(Debug)]
#[must_use = "a verified grant must be consumed by admission or dropped"]
pub struct VerifiedLaunchGrant {
    claims: LaunchGrantClaims,
    envelope_digest: String,
}

impl VerifiedLaunchGrant {
    /// Authenticated claims.
    #[must_use]
    pub fn claims(&self) -> &LaunchGrantClaims {
        &self.claims
    }

    /// Framed digest of the exact token bytes.
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

/// Verify one grant against the exact expectation and consume its nonce.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID`, `LAUNCH_GRANT_KEY_UNKNOWN`,
/// `LAUNCH_GRANT_AUDIENCE_MISMATCH`, `LAUNCH_GRANT_TTL_EXCEEDED`,
/// `LAUNCH_GRANT_NOT_YET_VALID`, `LAUNCH_GRANT_EXPIRED`,
/// `LAUNCH_GRANT_SUBJECT_MISMATCH`, `POLICY_LIVE_ADMISSION_DISABLED`, or
/// `LAUNCH_GRANT_REPLAYED`. Nothing is consumed unless every other check passed.
pub fn verify_launch_grant(
    grant: &SignedLaunchGrant,
    key: &LaunchGrantVerificationKey,
    expectation: &LaunchGrantExpectation,
    nonces: &mut dyn LaunchGrantNonceLedger,
) -> Result<VerifiedLaunchGrant, HarnessError> {
    let envelope_digest = grant.envelope_digest()?;
    let claims = key.authenticate(grant)?;
    expectation.check_subject(&claims)?;
    let (not_before, expires_at) = claims.window();
    if expectation.now_unix_ms < not_before {
        return Err(HarnessError::LaunchGrantNotYetValid {
            not_before_unix_ms: not_before,
        });
    }
    if expectation.now_unix_ms >= expires_at {
        return Err(HarnessError::LaunchGrantExpired {
            expires_at_unix_ms: expires_at,
        });
    }
    if !expectation.policy.live_admission_enabled {
        return Err(HarnessError::PolicyLiveAdmissionDisabled {
            generation: expectation.policy.policy_generation,
            field: "sandbox_policy.live_admission_enabled".to_string(),
        });
    }
    match nonces.consume_nonce(
        &claims.grant_nonce,
        &claims.attempt_id,
        expectation.now_unix_ms,
    )? {
        NonceConsumption::Consumed => Ok(VerifiedLaunchGrant {
            claims,
            envelope_digest,
        }),
        NonceConsumption::Replayed => Err(HarnessError::LaunchGrantReplayed {
            grant_id: claims.grant_id.clone(),
        }),
        NonceConsumption::Expired => Err(HarnessError::LaunchGrantExpired {
            expires_at_unix_ms: expires_at,
        }),
        NonceConsumption::Unknown => Err(HarnessError::LaunchGrantInvalid {
            reason: "grant nonce was never registered for this Attempt".to_string(),
        }),
    }
}
