//! Wave 3 DF-304: S2 Firecracker guest admission.
//!
//! An S2-required policy refuses before spawn until an exact guest image has
//! its own containment receipt. S2→S1 downgrade is forbidden.

/// Typed S2 spawn refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S2BoundaryError {
    /// Policy requires S2 and no certified guest receipt exists.
    GuestUncertified,
    /// Caller asked to run S1 after S2 was required.
    DowngradeForbidden,
}

impl S2BoundaryError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::GuestUncertified => "S2_GUEST_UNCERTIFIED",
            Self::DowngradeForbidden => "S2_DOWNGRADE_FORBIDDEN",
        }
    }
}

/// Admit a provider/Git/forge spawn under an S2 policy.
///
/// `guest_certified` is true only after an exact guest image has a containment
/// receipt. This function never inspects the host or starts Firecracker.
pub fn admit_s2_spawn(
    policy_requires_s2: bool,
    guest_certified: bool,
    requested_s1_downgrade: bool,
) -> Result<(), S2BoundaryError> {
    if !policy_requires_s2 {
        if requested_s1_downgrade {
            return Ok(());
        }
        return Ok(());
    }
    if requested_s1_downgrade {
        return Err(S2BoundaryError::DowngradeForbidden);
    }
    if !guest_certified {
        return Err(S2BoundaryError::GuestUncertified);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{admit_s2_spawn, S2BoundaryError};

    #[test]
    fn s2_required_refuses_before_spawn_without_certified_guest() {
        let error = admit_s2_spawn(true, false, false).expect_err("uncertified");
        assert_eq!(error, S2BoundaryError::GuestUncertified);
        assert_eq!(error.reason_code(), "S2_GUEST_UNCERTIFIED");
    }

    #[test]
    fn s2_required_forbids_s1_downgrade_even_if_a_guest_exists() {
        let error = admit_s2_spawn(true, true, true).expect_err("downgrade");
        assert_eq!(error, S2BoundaryError::DowngradeForbidden);
        assert_eq!(error.reason_code(), "S2_DOWNGRADE_FORBIDDEN");
    }

    #[test]
    fn s1_policy_does_not_require_a_guest() {
        admit_s2_spawn(false, false, false).expect("s1");
    }

    #[test]
    fn certified_s2_guest_admits_without_downgrade() {
        admit_s2_spawn(true, true, false).expect("certified s2");
    }
}
