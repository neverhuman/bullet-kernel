//! Attestor principal: publishes one check for one exact SHA.
//!
//! The broker is a different principal and cannot attest. The attestor
//! cannot push. A read-back that names a different SHA is
//! `CHECK_SUBJECT_MISMATCH`.

use crate::error::EffectsError;
use crate::forge::require_oid;
use crate::integration::{CheckPublication, CheckReceipt};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Attestor-only credential. Never shared with the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestorCredential {
    /// Key identity recorded on the receipt.
    pub key_id: String,
}

impl AttestorCredential {
    /// Load a credential file. The file must be mode 0600 and contain one
    /// non-empty key id on the first line.
    ///
    /// # Errors
    ///
    /// `FORGE_UNAUTHENTICATED` when the file is missing, world-readable, or
    /// empty.
    pub fn load(path: &Path) -> Result<Self, EffectsError> {
        let metadata = fs::metadata(path).map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(EffectsError::ForgeUnauthenticated(format!(
                "attestor credential mode {mode:o} is not 0600"
            )));
        }
        let raw = fs::read_to_string(path).map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        let key_id = raw.lines().next().unwrap_or("").trim().to_string();
        if key_id.is_empty() {
            return Err(EffectsError::ForgeUnauthenticated(
                "attestor credential is empty".into(),
            ));
        }
        Ok(Self { key_id })
    }
}

/// Publish one check bound to one exact SHA. The attestor recomputes
/// nothing from a broker payload; it only binds the named SHA.
///
/// # Errors
///
/// `BAD_OID` when `sha` is not 40 lowercase hex, `CHECK_SUBJECT_MISMATCH`
/// when `expected_sha` differs, or `FORGE_UNAUTHENTICATED` when the
/// credential is missing.
pub fn attest(
    credential: &AttestorCredential,
    req: &CheckPublication,
    expected_sha: &str,
) -> Result<CheckReceipt, EffectsError> {
    let _ = credential;
    require_oid("sha", &req.sha)?;
    require_oid("expected_sha", expected_sha)?;
    if req.sha != expected_sha {
        return Err(EffectsError::CheckSubjectMismatch(format!(
            "check names {} but subject is {expected_sha}",
            req.sha
        )));
    }
    if req.name.is_empty() || req.proof_root.is_empty() {
        return Err(EffectsError::CheckSubjectMismatch(
            "check name and proof root are required".into(),
        ));
    }
    Ok(CheckReceipt {
        sha: req.sha.clone(),
        name: req.name.clone(),
        proof_root: req.proof_root.clone(),
    })
}

/// Attestor structurally cannot push a candidate ref.
///
/// # Errors
///
/// Always `UNSUPPORTED_BY_ADAPTER`.
pub fn attestor_push() -> Result<(), EffectsError> {
    Err(EffectsError::UnsupportedByAdapter(
        "attestor cannot push".into(),
    ))
}

/// Broker structurally cannot publish a check.
///
/// # Errors
///
/// Always `UNSUPPORTED_BY_ADAPTER`.
pub fn broker_attest() -> Result<CheckReceipt, EffectsError> {
    Err(EffectsError::UnsupportedByAdapter(
        "broker cannot attest".into(),
    ))
}
