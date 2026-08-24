//! Verifier workspace custody: the verifier never shares the writer
//! checkout, and cleanup is fail-closed behind a preservation receipt.

/// Independent reconstruction descriptor. Distinct workspace path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanWorkspace {
    /// Writer workspace that must not be reused.
    pub writer_workspace: String,
    /// Fresh workspace used for reconstruction.
    pub verifier_workspace: String,
}

impl CleanWorkspace {
    /// Bind a reconstruction workspace. The writer's path is refused.
    ///
    /// # Errors
    ///
    /// Returns a message when the verifier would share the writer checkout.
    pub fn bind(
        writer_workspace: impl Into<String>,
        verifier_workspace: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let writer_workspace = writer_workspace.into();
        let verifier_workspace = verifier_workspace.into();
        if writer_workspace == verifier_workspace {
            return Err("verifier cannot share the writer workspace");
        }
        Ok(Self {
            writer_workspace,
            verifier_workspace,
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

/// Fail-closed cleanup. A missing receipt is never success.
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
        let err = CleanWorkspace::bind("ws-writer", "ws-writer").expect_err("shared");
        assert!(err.contains("share"));
    }

    #[test]
    fn cleanup_without_receipt_fails() {
        assert!(cleanup_workspace("atm_1", "nonce", None).is_err());
    }

    #[test]
    fn cleanup_with_wrong_binding_fails() {
        let receipt = PreservationReceipt {
            attempt_id: "atm_2".into(),
            workspace_nonce: "nonce".into(),
            bundle_digest: "dig".into(),
        };
        assert!(cleanup_workspace("atm_1", "nonce", Some(&receipt)).is_err());
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
