//! Attestor principal: validates one check request for one exact SHA.
//!
//! The broker is a different principal and cannot attest. The attestor
//! cannot push. Validation is deliberately non-admitting until an
//! authenticated signature and read-back protocol is available.

use crate::error::EffectsError;
use crate::forge::require_oid;
use crate::integration::{CheckPublication, CheckReceipt};
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Attestor-only credential. Never shared with the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestorCredential {
    /// Candidate key identity for future authenticated admission. This is not
    /// a signature or a receipt.
    key_id: String,
}

impl AttestorCredential {
    /// Load a credential file. The file must be mode 0600 and contain one
    /// non-empty key id on the first line.
    ///
    /// # Errors
    ///
    /// `FORGE_UNAUTHENTICATED` when the file is missing, world-readable, or
    /// empty. Non-Unix platforms refuse because their credential containment
    /// profile is not certified.
    pub fn load(path: &Path) -> Result<Self, EffectsError> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(EffectsError::LiveAdmissionUnavailable(
                "attestor credential-file admission is only certified on Unix".into(),
            ));
        }
        #[cfg(unix)]
        Self::load_unix(path)
    }

    /// Validated candidate credential identity. This is not secret material,
    /// an admitted signature, or a receipt.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[cfg(unix)]
    fn load_unix(path: &Path) -> Result<Self, EffectsError> {
        let path_metadata = fs::symlink_metadata(path).map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
            return Err(EffectsError::ForgeUnauthenticated(
                "attestor credential must be a non-symlink regular file".into(),
            ));
        }
        let mode = path_metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(EffectsError::ForgeUnauthenticated(format!(
                "attestor credential mode {mode:o} is not 0600"
            )));
        }
        if path_metadata.len() == 0 || path_metadata.len() > 4_096 {
            return Err(EffectsError::ForgeUnauthenticated(
                "attestor credential size is outside 1..=4096 bytes".into(),
            ));
        }
        let mut file = File::open(path).map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        let opened_metadata = file.metadata().map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
        {
            return Err(EffectsError::ForgeUnauthenticated(
                "attestor credential identity changed while opening".into(),
            ));
        }
        let mut raw = String::new();
        file.read_to_string(&mut raw).map_err(|err| {
            EffectsError::ForgeUnauthenticated(format!("attestor credential: {err}"))
        })?;
        let key_id = raw.lines().next().unwrap_or("").trim().to_string();
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(EffectsError::ForgeUnauthenticated(
                "attestor key id must use 1..=128 ASCII letters, digits, dot, underscore, colon, or hyphen"
                    .into(),
            ));
        }
        Ok(Self { key_id })
    }
}

/// Validate a check request before any forge call.
///
/// # Errors
///
/// `BAD_OID` for malformed subjects or `CHECK_SUBJECT_MISMATCH` for an
/// incomplete or unexpected subject.
pub fn validate_attestation_request(
    credential: &AttestorCredential,
    req: &CheckPublication,
    expected_sha: &str,
) -> Result<(), EffectsError> {
    if credential.key_id().is_empty() {
        return Err(EffectsError::ForgeUnauthenticated(
            "attestor credential identity is empty".into(),
        ));
    }
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
    Ok(())
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
