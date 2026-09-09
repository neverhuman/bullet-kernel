//! Exact verification subject. Writer workspace is never this plane.

/// Custody of an evidence record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceCustody {
    /// Produced inside the writer Attempt.
    Writer,
    /// Produced in a clean reconstruction.
    Independent,
}

/// Exact Candidate identity the gate ran against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSubject {
    /// Head commit SHA (40 hex).
    pub head_sha: String,
}

impl CandidateSubject {
    /// Build a subject. Empty SHA is rejected by callers.
    #[must_use]
    pub fn new(head_sha: impl Into<String>) -> Self {
        Self {
            head_sha: head_sha.into(),
        }
    }
}

/// One typed evidence record. `result: String` is forbidden here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Exact subject.
    pub subject: CandidateSubject,
    /// Who produced it.
    pub custody: EvidenceCustody,
    /// Trust tier label such as `E3`.
    pub tier: String,
    /// Gate name.
    pub gate: String,
    /// Typed outcome.
    pub outcome: crate::gate::GateOutcome,
}

/// Independent reconstruction of a Candidate. Distinct workspace id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanWorkspace {
    /// Writer workspace that must not be reused.
    pub writer_workspace: String,
    /// Fresh workspace used for reconstruction.
    pub verifier_workspace: String,
    /// Reconstructed head SHA.
    pub reconstructed: CandidateSubject,
}

impl CleanWorkspace {
    /// Reconstruct `subject` in a new workspace. Same path as the writer is refused.
    ///
    /// # Errors
    ///
    /// Returns a message when the verifier would share the writer checkout.
    pub fn reconstruct(
        writer_workspace: impl Into<String>,
        verifier_workspace: impl Into<String>,
        subject: CandidateSubject,
    ) -> Result<Self, &'static str> {
        let writer_workspace = writer_workspace.into();
        let verifier_workspace = verifier_workspace.into();
        if writer_workspace == verifier_workspace {
            return Err("verifier cannot share the writer workspace");
        }
        if subject.head_sha.len() != 40 {
            return Err("subject is not a 40-hex SHA");
        }
        Ok(Self {
            writer_workspace,
            verifier_workspace,
            reconstructed: subject,
        })
    }
}

/// Bundle that cleanup must present before a workspace may be destroyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservationReceipt {
    /// Attempt that owned the workspace.
    pub attempt_id: String,
    /// Workspace nonce bound at lease time.
    pub workspace_nonce: String,
    /// Content digest of the preserved bundle.
    pub bundle_digest: String,
}

/// Fail-closed cleanup. Missing receipt is not success.
///
/// # Errors
///
/// Returns a message when the receipt does not bind the attempt and nonce.
pub fn cleanup_workspace(
    attempt_id: &str,
    workspace_nonce: &str,
    receipt: Option<&PreservationReceipt>,
) -> Result<(), &'static str> {
    let receipt = receipt.ok_or("cleanup requires a preservation receipt")?;
    if receipt.attempt_id != attempt_id || receipt.workspace_nonce != workspace_nonce {
        return Err("preservation receipt does not bind this workspace");
    }
    if receipt.bundle_digest.is_empty() {
        return Err("preservation receipt has no bundle");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_workspace_is_refused() {
        let subject = CandidateSubject::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let err =
            CleanWorkspace::reconstruct("ws-writer", "ws-writer", subject).expect_err("shared");
        assert!(err.contains("share"));
    }

    #[test]
    fn cleanup_without_receipt_fails() {
        assert!(cleanup_workspace("atm_1", "nonce", None).is_err());
    }

    #[test]
    fn cleanup_with_bound_receipt_ok() {
        let receipt = PreservationReceipt {
            attempt_id: "atm_1".into(),
            workspace_nonce: "nonce".into(),
            bundle_digest: "dig".into(),
        };
        cleanup_workspace("atm_1", "nonce", Some(&receipt)).expect("ok");
    }
}
