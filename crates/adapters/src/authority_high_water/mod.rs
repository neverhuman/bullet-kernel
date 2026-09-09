//! External durable high-water storage for mutation authority.
//!
//! This component persists the authority epoch, freeze generation, restore
//! epoch, and recovery posture outside the restorable SQLite database so a
//! snapshot rollback cannot erase them. It only records those values with
//! rollback-resistant local storage; restore admission and the transition into
//! or out of `RECOVERING` are decided by later recovery wiring, not here.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod storage;

/// Persisted record schema version. Version 1 carried only the authority
/// epoch and freeze generation; version 2 adds the restore epoch and recovery
/// posture. A version 1 record is refused as corrupt rather than defaulted.
pub const AUTHORITY_HIGH_WATER_SCHEMA_VERSION: u32 = 2;
const MAX_RECORD_BYTES: u64 = 4_096;
const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const CHECKSUM_DOMAIN: &[u8] = b"bullet.kernel.authority-high-water.v2";

/// Durable recovery posture recorded beside the counters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryState {
    /// Normal service: no applied restore awaits admission.
    Serving,
    /// A restore was applied and mutation authority awaits admission.
    Recovering,
}

impl RecoveryState {
    /// Stable persisted spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Serving => "SERVING",
            Self::Recovering => "RECOVERING",
        }
    }

    const fn checksum_tag(self) -> u8 {
        match self {
            Self::Serving => 0,
            Self::Recovering => 1,
        }
    }
}

/// The four durable values carried by one high-water record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityHighWaterValues {
    /// Restore-invalidated Kernel authority epoch. Starts at one.
    pub authority_epoch: u64,
    /// Monotonic fleet-freeze generation. Zero means never frozen.
    pub freeze_generation: u64,
    /// Highest restore epoch acknowledged outside the database. Zero means
    /// no restore was ever applied.
    pub restore_epoch: u64,
    /// Recovery posture. `Recovering` requires a nonzero restore epoch.
    pub recovery: RecoveryState,
}

impl AuthorityHighWaterValues {
    fn validate(self) -> Result<(), AuthorityHighWaterError> {
        if self.authority_epoch == 0
            || self.authority_epoch > MAX_SAFE_INTEGER
            || self.freeze_generation > MAX_SAFE_INTEGER
            || self.restore_epoch > MAX_SAFE_INTEGER
        {
            return Err(corrupt(
                "authority epoch must be 1..=2^53-1; freeze generation and restore epoch 0..=2^53-1",
            ));
        }
        if self.recovery == RecoveryState::Recovering && self.restore_epoch == 0 {
            return Err(corrupt("RECOVERING requires a nonzero restore epoch"));
        }
        Ok(())
    }

    /// True when any counter would move behind `current`.
    #[must_use]
    pub const fn regresses_from(self, current: Self) -> bool {
        self.authority_epoch < current.authority_epoch
            || self.freeze_generation < current.freeze_generation
            || self.restore_epoch < current.restore_epoch
    }
}

impl fmt::Display for AuthorityHighWaterValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "(authority_epoch={},freeze_generation={},restore_epoch={},recovery={})",
            self.authority_epoch,
            self.freeze_generation,
            self.restore_epoch,
            self.recovery.code()
        )
    }
}

/// Exact external authority high-water record.
///
/// The type name is the crate's stable export; `schema_version` is the
/// on-disk record version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHighWaterV1 {
    /// Strict record version.
    pub schema_version: u32,
    /// Restore-invalidated Kernel authority epoch. Starts at one.
    pub authority_epoch: u64,
    /// Monotonic fleet-freeze generation. Zero means never frozen.
    pub freeze_generation: u64,
    /// Highest restore epoch acknowledged outside the database.
    pub restore_epoch: u64,
    /// Recovery posture at the time of publication.
    pub recovery: RecoveryState,
    /// Domain-separated BLAKE3 over the version and every value above.
    pub checksum: String,
}

impl AuthorityHighWaterV1 {
    /// The durable values without the version and checksum envelope.
    #[must_use]
    pub const fn values(&self) -> AuthorityHighWaterValues {
        AuthorityHighWaterValues {
            authority_epoch: self.authority_epoch,
            freeze_generation: self.freeze_generation,
            restore_epoch: self.restore_epoch,
            recovery: self.recovery,
        }
    }

    fn from_values(values: AuthorityHighWaterValues) -> Result<Self, AuthorityHighWaterError> {
        values.validate()?;
        Ok(Self {
            schema_version: AUTHORITY_HIGH_WATER_SCHEMA_VERSION,
            authority_epoch: values.authority_epoch,
            freeze_generation: values.freeze_generation,
            restore_epoch: values.restore_epoch,
            recovery: values.recovery,
            checksum: checksum(values),
        })
    }

    fn validate(&self) -> Result<(), AuthorityHighWaterError> {
        if self.schema_version != AUTHORITY_HIGH_WATER_SCHEMA_VERSION {
            return Err(corrupt("unsupported authority high-water schema version"));
        }
        let values = self.values();
        values.validate()?;
        if self.checksum != checksum(values) {
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
    /// A requested counter would move behind durable truth.
    #[error("AUTHORITY_HIGH_WATER_ROLLBACK: current={current} requested={requested}")]
    Rollback {
        /// Durable values.
        current: AuthorityHighWaterValues,
        /// Refused values.
        requested: AuthorityHighWaterValues,
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

    /// Read the current durable record under the cross-process lock.
    ///
    /// # Errors
    /// Refuses unsafe filesystem subjects and malformed records.
    pub fn load(&self) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
        self.load_platform()
    }

    /// Atomically initialize or monotonically advance the durable values.
    /// Exact retries are idempotent. If any requested counter is lower than
    /// durable truth, the entire mixed update is refused without publication.
    /// The recovery posture is recorded as requested; which transitions are
    /// legal is the caller's policy, not this store's.
    ///
    /// # Errors
    /// Refuses rollback, invalid or corrupt state, unsafe filesystem subjects,
    /// or any uncertain publication result.
    pub fn advance(
        &self,
        values: AuthorityHighWaterValues,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        self.advance_platform(values, FaultPoint::None)
    }

    #[cfg(test)]
    fn advance_with_fault(
        &self,
        values: AuthorityHighWaterValues,
        fault: FaultPoint,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        self.advance_platform(values, fault)
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
        values: AuthorityHighWaterValues,
        fault: FaultPoint,
    ) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
        let requested = AuthorityHighWaterV1::from_values(values)?;
        storage::advance(&self.path, requested, fault)
    }

    #[cfg(not(target_os = "linux"))]
    fn advance_platform(
        &self,
        _values: AuthorityHighWaterValues,
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

fn checksum(values: AuthorityHighWaterValues) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(CHECKSUM_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(&AUTHORITY_HIGH_WATER_SCHEMA_VERSION.to_be_bytes());
    hasher.update(&values.authority_epoch.to_be_bytes());
    hasher.update(&values.freeze_generation.to_be_bytes());
    hasher.update(&values.restore_epoch.to_be_bytes());
    hasher.update(&[values.recovery.checksum_tag()]);
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
