//! Profile identity verification (spec s8.6). A mismatch with the authorized
//! profile fails closed; an unverified identity also fails closed.

use crate::error::HarnessError;
use bullet_domain::{Observation, ProfileId};
use serde::{Deserialize, Serialize};

/// The identity a provider session is actually running as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIdentity {
    /// Provider name.
    pub provider: String,
    /// Account email when the provider reports one.
    pub email: Option<String>,
    /// Account id when the provider reports one.
    pub account_id: Option<String>,
    /// Subscription tier when reported.
    pub subscription: Option<String>,
    /// Auth method when reported.
    pub auth_method: Option<String>,
}

/// What the authorized profile is expected to look like.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedProfile {
    /// Exact account email.
    pub email: Option<String>,
    /// Account id prefix (ids may be long opaque strings).
    pub account_id_prefix: Option<String>,
}

/// Reference to an authorized credential profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    /// Kernel profile id.
    pub profile_id: ProfileId,
    /// Expected identity; verification fails closed against this.
    pub expected: ExpectedProfile,
}

/// Result of probing an adapter's effective identity and version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Probed identity as an observation; Unknown is never a pass.
    pub profile: Observation<ProfileIdentity>,
    /// Observed binary version string.
    pub version: String,
}

impl ProbeResult {
    /// Verify the probed identity against the expectation. Fails closed.
    ///
    /// # Errors
    ///
    /// `PROFILE_UNVERIFIED` when the identity is not a verified observation
    /// or the expectation is empty; `PROFILE_MISMATCH` when any expected
    /// criterion does not match.
    pub fn verify(
        &self,
        provider: &str,
        expected: &ExpectedProfile,
    ) -> Result<&ProfileIdentity, HarnessError> {
        let identity = match &self.profile {
            Observation::Value { value } => value,
            other => {
                return Err(HarnessError::ProfileUnverified {
                    provider: provider.to_string(),
                    reason: format!("identity observation is {}", other.kind_name()),
                });
            }
        };
        if expected.email.is_none() && expected.account_id_prefix.is_none() {
            return Err(HarnessError::ProfileUnverified {
                provider: provider.to_string(),
                reason: "empty expectation; refusing to auto-pass".to_string(),
            });
        }
        if let Some(email) = &expected.email {
            if identity.email.as_deref() != Some(email.as_str()) {
                return Err(HarnessError::ProfileMismatch {
                    expected: format!("email={email}"),
                    actual: format!("email={:?}", identity.email),
                });
            }
        }
        if let Some(prefix) = &expected.account_id_prefix {
            let matched = identity
                .account_id
                .as_deref()
                .is_some_and(|id| id.starts_with(prefix.as_str()));
            if !matched {
                return Err(HarnessError::ProfileMismatch {
                    expected: format!("account_id starts with {prefix}"),
                    actual: format!("account_id={:?}", identity.account_id),
                });
            }
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProfileIdentity {
        ProfileIdentity {
            provider: "claude".into(),
            email: Some("ben@veox.ai".into()),
            account_id: Some("016926d0-c801".into()),
            subscription: Some("max".into()),
            auth_method: None,
        }
    }

    fn result_with(profile: Observation<ProfileIdentity>) -> ProbeResult {
        ProbeResult {
            profile,
            version: "1.0.0".into(),
        }
    }

    #[test]
    fn matching_email_verifies() {
        let expected = ExpectedProfile {
            email: Some("ben@veox.ai".into()),
            account_id_prefix: None,
        };
        let result = result_with(Observation::value(identity()));
        assert!(result.verify("claude", &expected).is_ok());
    }

    #[test]
    fn mismatch_fails_closed_with_profile_mismatch() {
        let expected = ExpectedProfile {
            email: Some("intruder@example.com".into()),
            account_id_prefix: None,
        };
        let result = result_with(Observation::value(identity()));
        let err = result.verify("claude", &expected).unwrap_err();
        assert_eq!(err.reason_code(), "PROFILE_MISMATCH");
    }

    #[test]
    fn account_prefix_checks() {
        let expected = ExpectedProfile {
            email: None,
            account_id_prefix: Some("016926d0".into()),
        };
        let result = result_with(Observation::value(identity()));
        assert!(result.verify("codex", &expected).is_ok());
        let wrong = ExpectedProfile {
            email: None,
            account_id_prefix: Some("ffffffff".into()),
        };
        assert_eq!(
            result.verify("codex", &wrong).unwrap_err().reason_code(),
            "PROFILE_MISMATCH"
        );
    }

    #[test]
    fn unknown_observation_fails_closed() {
        let expected = ExpectedProfile {
            email: Some("ben@veox.ai".into()),
            account_id_prefix: None,
        };
        let result = result_with(Observation::Unknown {
            source: "agy".into(),
            reason: "no identity surface".into(),
        });
        let err = result.verify("agy", &expected).unwrap_err();
        assert_eq!(err.reason_code(), "PROFILE_UNVERIFIED");
    }

    #[test]
    fn empty_expectation_never_auto_passes() {
        let result = result_with(Observation::value(identity()));
        let err = result
            .verify("claude", &ExpectedProfile::default())
            .unwrap_err();
        assert_eq!(err.reason_code(), "PROFILE_UNVERIFIED");
    }
}
