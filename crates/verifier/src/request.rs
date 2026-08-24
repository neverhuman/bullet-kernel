//! Verifier input. Every field is validated before any process spawns.

use crate::error::VerifierError;
use serde::{Deserialize, Serialize};

/// One clean-room verification request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierRequest {
    /// Path of the workspace repository to reconstruct from.
    pub workspace_repo_path: String,
    /// Candidate base commit SHA (40 lowercase hex).
    pub base_sha: String,
    /// Candidate head commit SHA (40 lowercase hex).
    pub head_sha: String,
    /// Candidate tree SHA (40 lowercase hex).
    pub tree_sha: String,
    /// Gate command executed inside the clean clone via `sh -c`.
    pub gate_command: String,
    /// Gate budget in seconds.
    pub timeout_secs: u64,
    /// Attempt that authored the Candidate; recorded for independence
    /// checks, never granted authority.
    pub author_attempt_id: String,
}

fn is_full_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl VerifierRequest {
    /// Validate shape before any work.
    ///
    /// # Errors
    ///
    /// Returns `BAD_INPUT` naming the offending field.
    pub fn validate(&self) -> Result<(), VerifierError> {
        if self.workspace_repo_path.is_empty() {
            return Err(VerifierError::BadInput(
                "workspace_repo_path is empty".into(),
            ));
        }
        for (name, value) in [
            ("base_sha", &self.base_sha),
            ("head_sha", &self.head_sha),
            ("tree_sha", &self.tree_sha),
        ] {
            if !is_full_sha(value) {
                return Err(VerifierError::BadInput(format!(
                    "{name} is not 40 lowercase hex characters"
                )));
            }
        }
        if self.gate_command.trim().is_empty() {
            return Err(VerifierError::BadInput("gate_command is empty".into()));
        }
        if self.timeout_secs == 0 {
            return Err(VerifierError::BadInput(
                "timeout_secs must be positive".into(),
            ));
        }
        if self.author_attempt_id.is_empty() {
            return Err(VerifierError::BadInput("author_attempt_id is empty".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> VerifierRequest {
        VerifierRequest {
            workspace_repo_path: "/tmp/repo".into(),
            base_sha: "a".repeat(40),
            head_sha: "b".repeat(40),
            tree_sha: "c".repeat(40),
            gate_command: "true".into(),
            timeout_secs: 5,
            author_attempt_id: "atm_x".into(),
        }
    }

    #[test]
    fn valid_request_passes() {
        request().validate().expect("valid");
    }

    #[test]
    fn short_or_uppercase_shas_are_refused() {
        let mut bad = request();
        bad.head_sha = "B".repeat(40);
        assert_eq!(
            bad.validate().expect_err("upper").reason_code(),
            "BAD_INPUT"
        );
        bad.head_sha = "b".repeat(39);
        assert_eq!(
            bad.validate().expect_err("short").reason_code(),
            "BAD_INPUT"
        );
    }

    #[test]
    fn zero_timeout_and_empty_fields_are_refused() {
        let mut bad = request();
        bad.timeout_secs = 0;
        assert!(bad.validate().is_err());
        let mut empty = request();
        empty.gate_command = "  ".into();
        assert!(empty.validate().is_err());
    }
}
