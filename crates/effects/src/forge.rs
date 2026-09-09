//! The `ForgeEffects` port: a candidate-ref push with an expected-old-OID
//! precondition, plus the authoritative read-back the broker verifies
//! against. Only `refs/heads/bullet/candidate/*` is ever a destination.

use crate::error::EffectsError;
use bullet_application::ZERO_OID;
use std::path::PathBuf;

/// The only ref namespace effects may write.
pub const CANDIDATE_REF_PREFIX: &str = "refs/heads/bullet/candidate/";

/// One requested candidate-ref push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRequest {
    /// Workspace clone the objects are pushed from.
    pub workspace_repo: PathBuf,
    /// Fully qualified target ref.
    pub ref_name: String,
    /// Expected current remote OID; [`ZERO_OID`] means the ref must not
    /// exist yet.
    pub expected_old_oid: String,
    /// New OID the ref must point at.
    pub new_oid: String,
}

/// Capability descriptor a forge reports about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeDescriptor {
    /// Provider label recorded on intents.
    pub provider: String,
    /// Whether an operator-authenticated token is present.
    pub authenticated: bool,
    /// Whether candidate-ref pushes are proven available.
    pub can_push_candidate_ref: bool,
    /// Honest operator-facing note.
    pub notes: String,
}

/// External mutation port. Implementations never invent success: a push
/// answer is only trusted after the broker's independent read-back.
pub trait ForgeEffects {
    /// Self-description.
    fn descriptor(&self) -> ForgeDescriptor;

    /// Push `new_oid` to `ref_name` with the expected-old-OID precondition.
    ///
    /// # Errors
    ///
    /// `REF_DENIED`, `BAD_OID`, `PUSH_REJECTED` (stale precondition),
    /// `RESPONSE_LOST`, `FORGE_UNAUTHENTICATED`, or infrastructure codes.
    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError>;

    /// Authoritative read-back of one ref. `None` is authoritative absence.
    ///
    /// # Errors
    ///
    /// `REF_DENIED`, `FORGE_UNAUTHENTICATED`, or infrastructure codes.
    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError>;
}

/// Refuse any destination outside the candidate namespace. `HEAD` and every
/// reserved ref are never push destinations.
///
/// # Errors
///
/// Returns `REF_DENIED` naming the offending ref.
pub fn require_candidate_ref(ref_name: &str) -> Result<(), EffectsError> {
    let suffix = ref_name
        .strip_prefix(CANDIDATE_REF_PREFIX)
        .unwrap_or_default();
    if suffix.is_empty()
        || suffix.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || part == "HEAD" || part.contains('\\')
        })
    {
        return Err(EffectsError::RefDenied(format!(
            "{ref_name} is outside {CANDIDATE_REF_PREFIX}"
        )));
    }
    Ok(())
}

/// Validate a 40-lowercase-hex OID. [`ZERO_OID`] is accepted where the
/// caller allows create semantics.
///
/// # Errors
///
/// Returns `BAD_OID` naming the field.
pub fn require_oid(name: &str, value: &str) -> Result<(), EffectsError> {
    let valid = value.len() == 40
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !valid {
        return Err(EffectsError::BadOid(format!(
            "{name} must be 40 lowercase hex characters"
        )));
    }
    Ok(())
}

/// Whether an expected-old OID means create semantics.
#[must_use]
pub fn is_create(expected_old_oid: &str) -> bool {
    expected_old_oid == ZERO_OID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_namespace_is_enforced() {
        require_candidate_ref("refs/heads/bullet/candidate/can_1").expect("allowed");
        for denied in [
            "refs/heads/main",
            "HEAD",
            "refs/heads/bullet/candidate/",
            "refs/heads/bullet/candidate/../../main",
            "refs/tags/v1",
            "refs/heads/bullet/candidate/HEAD",
            "refs/heads/bullet/other/x",
        ] {
            let err = require_candidate_ref(denied).expect_err(denied);
            assert_eq!(err.reason_code(), "REF_DENIED", "{denied}");
        }
    }

    #[test]
    fn oids_are_validated() {
        require_oid("new_oid", &"a".repeat(40)).expect("valid");
        require_oid("expected", ZERO_OID).expect("zeros are well-formed");
        for bad in ["", "abc", &"A".repeat(40) as &str] {
            assert_eq!(
                require_oid("new_oid", bad).expect_err("bad").reason_code(),
                "BAD_OID"
            );
        }
    }
}
