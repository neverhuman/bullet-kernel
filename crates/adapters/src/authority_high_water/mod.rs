//! External durable high-water storage for mutation authority.
//!
//! This component deliberately does not perform restore admission or enter
//! `RECOVERING`. It only persists the authority epoch and freeze generation
//! outside the restorable SQLite database so later recovery wiring has a
//! rollback-resistant local subject.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod storage;

/// Persisted record schema version.
pub const AUTHORITY_HIGH_WATER_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 4_096;
const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const CHECKSUM_DOMAIN: &[u8] = b"bullet.kernel.authority-high-water.v1";

/// Exact external authority high-water record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHighWaterV1 {
    /// Strict record version.
    pub schema_version: u32,
    /// Restore-invalidated Kernel authority epoch. Starts at one.
    pub authority_epoch: u64,
    /// Monotonic fleet-freeze generation. Zero means never frozen.
    pub freeze_generation: u64,
    /// Domain-separated BLAKE3 over the version and both counters.
    pub checksum: String,
}

impl AuthorityHighWaterV1 {
    fn from_values(
        authority_epoch: u64,
        freeze_generation: u64,
    ) -> Result<Self, AuthorityHighWaterError> {
        validate_counters(authority_epoch, freeze_generation)?;
        Ok(Self {
            schema_version: AUTHORITY_HIGH_WATER_SCHEMA_VERSION,
            authority_epoch,
            freeze_generation,
            checksum: checksum(authority_epoch, freeze_generation),
        })
    }

    fn validate(&self) -> Result<(), AuthorityHighWaterError> {
        if self.schema_version != AUTHORITY_HIGH_WATER_SCHEMA_VERSION {
            return Err(corrupt("unsupported authority high-water schema version"));
        }
        validate_counters(self.authority_epoch, self.freeze_generation)?;
        if self.checksum != checksum(self.authority_epoch, self.freeze_generation) {
            return Err(corrupt("authority high-water checksum mismatch"));
        }
        Ok(())
    }
}

/// External high-water persistence failure.
#[derive(Debug, Error)]
pub enum AuthorityHighWaterError {
    /// Descriptor-safe storage is currently certified only on Linux.
    #[error("AUTHORITY_HIGH_WATER_UNSUPPORTED: descriptor-safe storage requires Linux")]
    UnsupportedPlatform,
    /// The configured subject path is not an unambiguous absolute file path.
    #[error("AUTHORITY_HIGH_WATER_PATH_INVALID: {detail}")]
    InvalidPath {
        /// Non-secret refusal detail.
        detail: String,
    },
    /// A directory, lock, or record failed owner/mode/type/link admission.
    #[error("AUTHORITY_HIGH_WATER_ADMISSION_REFUSED: {detail}")]
    Admission {
        /// Non-secret refusal detail.
        detail: String,
    },
    /// The bounded strict record is malformed or internally inconsistent.
    #[error("AUTHORITY_HIGH_WATER_CORRUPT: {detail}")]
    Corrupt {
        /// Non-secret refusal detail.
        detail: String,
    },
    /// Either requested counter would move behind durable truth.
    #[error(
        "AUTHORITY_HIGH_WATER_ROLLBACK: current=({current_epoch},{current_generation}) requested=({requested_epoch},{requested_generation})"
    )]
    Rollback {
        /// Durable authority epoch.
        current_epoch: u64,
        /// Durable freeze generation.
        current_generation: u64,
        /// Refused authority epoch.
        requested_epoch: u64,
        /// Refused freeze generation.
        requested_generation: u64,
    },
    /// A pre-publication filesystem phase failed with no admitted advance.
    #[error("AUTHORITY_HIGH_WATER_{phase}: {detail}")]
    Operation {
        /// Stable phase name.
        phase: &'static str,
        /// Non-secret underlying failure.
        detail: String,
    },
    /// Publication may have completed; callers must read back before retrying.
    #[error("AUTHORITY_HIGH_WATER_RESPONSE_LOST: {detail}")]
    ResponseLost {
        /// Non-secret failure after the atomic publication boundary.
        detail: String,
    },
}

impl AuthorityHighWaterError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "AUTHORITY_HIGH_WATER_UNSUPPORTED",
            Self::InvalidPath { .. } => "AUTHORITY_HIGH_WATER_PATH_INVALID",
            Self::Admission { .. } => "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED",
            Self::Corrupt { .. } => "AUTHORITY_HIGH_WATER_CORRUPT",
            Self::Rollback { .. } => "AUTHORITY_HIGH_WATER_ROLLBACK",
            Self::Operation { .. } => "AUTHORITY_HIGH_WATER_OPERATION_FAILED",
            Self::ResponseLost { .. } => "AUTHORITY_HIGH_WATER_RESPONSE_LOST",
        }
    }
}

/// One external high-water subject and its adjacent persistent lock.
#[derive(Clone, Debug)]
pub struct AuthorityHighWaterStore {
    path: PathBuf,
}

impl AuthorityHighWaterStore {
    /// Bind an absolute record path without creating state.
    ///
    /// # Errors
    /// Refuses relative, root, dot, and parent-traversal paths.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, AuthorityHighWaterError> {
        let path = path.into();
        validate_path(&path)?;
        Ok(Self { path })
    }

    /// Read the current durable tuple under the cross-process lock.
    ///
    /// # Errors
    /// Refuses unsafe filesystem subjects and malformed records.
    pub fn load(&self) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
        self.load_platform()
    }

    /// Atomically initialize or monotonically advance both high-water values.
    /// Exact retries are idempotent. If either requested value is lower than
    /// durable truth, the entire mixed update is refused without publication.
    ///
    /// # Errors
    /// Refuses rollback, corrupt current state, unsafe filesystem subjects, or
    /// any uncertain publication result.
    pub fn advance(
        &self,
        authority_epoch: u64,
        freeze_generation: u64,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        self.advance_platform(authority_epoch, freeze_generation, FaultPoint::None)
    }

    #[cfg(test)]
    fn advance_with_fault(
        &self,
        authority_epoch: u64,
        freeze_generation: u64,
        fault: FaultPoint,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        self.advance_platform(authority_epoch, freeze_generation, fault)
    }

    #[cfg(target_os = "linux")]
    fn load_platform(&self) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
        storage::load(&self.path)
    }

    #[cfg(not(target_os = "linux"))]
    fn load_platform(&self) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
        Err(AuthorityHighWaterError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn advance_platform(
        &self,
        authority_epoch: u64,
        freeze_generation: u64,
        fault: FaultPoint,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        let requested = AuthorityHighWaterV1::from_values(authority_epoch, freeze_generation)?;
        storage::advance(&self.path, requested, fault)
    }

    #[cfg(not(target_os = "linux"))]
    fn advance_platform(
        &self,
        _authority_epoch: u64,
        _freeze_generation: u64,
        _fault: FaultPoint,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        Err(AuthorityHighWaterError::UnsupportedPlatform)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn locked_parent(&self) -> Result<storage::LockedParent, AuthorityHighWaterError> {
        storage::LockedParent::open(&self.path)
    }

    #[cfg(test)]
    fn lock_path(&self) -> PathBuf {
        let parent = self.path.parent().expect("validated parent");
        parent.join(lock_name(&self.path))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    None,
    #[cfg(test)]
    BeforePublish,
    #[cfg(test)]
    AfterReadback,
}

fn validate_path(path: &Path) -> Result<(), AuthorityHighWaterError> {
    if !path.is_absolute() || path.file_name().is_none() || path.parent().is_none() {
        return Err(invalid_path(
            "authority high-water record must be an absolute non-root file path",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_path("authority high-water path must be normalized"));
    }
    Ok(())
}

fn validate_counters(
    authority_epoch: u64,
    freeze_generation: u64,
) -> Result<(), AuthorityHighWaterError> {
    if authority_epoch == 0
        || authority_epoch > MAX_SAFE_INTEGER
        || freeze_generation > MAX_SAFE_INTEGER
    {
        return Err(corrupt(
            "authority epoch must be 1..=2^53-1 and freeze generation 0..=2^53-1",
        ));
    }
    Ok(())
}

fn checksum(authority_epoch: u64, freeze_generation: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(CHECKSUM_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(&AUTHORITY_HIGH_WATER_SCHEMA_VERSION.to_be_bytes());
    hasher.update(&authority_epoch.to_be_bytes());
    hasher.update(&freeze_generation.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

fn lock_name(record: &Path) -> std::ffi::OsString {
    let mut name = record
        .file_name()
        .expect("validated file name")
        .to_os_string();
    name.push(".lock");
    name
}

fn invalid_path(detail: impl Into<String>) -> AuthorityHighWaterError {
    AuthorityHighWaterError::InvalidPath {
        detail: detail.into(),
    }
}

fn admission(detail: impl Into<String>) -> AuthorityHighWaterError {
    AuthorityHighWaterError::Admission {
        detail: detail.into(),
    }
}

fn corrupt(detail: impl Into<String>) -> AuthorityHighWaterError {
    AuthorityHighWaterError::Corrupt {
        detail: detail.into(),
    }
}

fn operation(phase: &'static str, detail: impl ToString) -> AuthorityHighWaterError {
    AuthorityHighWaterError::Operation {
        phase,
        detail: detail.to_string(),
    }
}

fn response_lost(detail: impl Into<String>) -> AuthorityHighWaterError {
    AuthorityHighWaterError::ResponseLost {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests;
