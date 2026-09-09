//! Strict, provider-neutral identity and component-only filesystem inspection
//! for one immutable packaged CLI runtime. Neither operation grants authority
//! to enroll or launch the described runtime.

use crate::admission::ProviderProtocol;
use crate::launch_grant::canonical::MAX_CANONICAL_BYTES;
use crate::launch_grant::{
    canonical_json, decode_canonical, hash_framed_bytes, is_lower_hex_64, MAX_SAFE_INTEGER,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod inspection;

pub use inspection::{inspect_provider_runtime, InspectedProviderRuntimeV1};

/// Frozen wire schema version.
pub const RUNTIME_PASSPORT_SCHEMA_VERSION: u32 = 1;
/// Honest evidence ceiling for an inspected runtime filesystem.
pub const RUNTIME_INSPECTION_EVIDENCE_CLASS: &str = "COMPONENT_ONLY";
/// Framed BLAKE3 domain for the canonical passport document.
pub const RUNTIME_PASSPORT_DOMAIN: &str = "provider-runtime-passport.v1";
/// Typed prefix for a passport's full-width digest.
pub const RUNTIME_PASSPORT_ID_PREFIX: &str = "rtp_";
/// Only immutable packaged roots under this directory are representable.
pub const RUNTIME_DEPLOYMENT_PREFIX: &str = "/usr/lib/bullet/providers";
/// Maximum manifest members in one passport document.
pub const MAX_RUNTIME_FILES: usize = 256;
/// Maximum size of one runtime file.
pub const MAX_RUNTIME_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum aggregate size of one packaged runtime.
pub const MAX_RUNTIME_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Maximum bytes in the exact packaged version segment.
pub const MAX_RUNTIME_VERSION_BYTES: usize = 64;
/// Maximum bytes in one root-relative manifest path.
pub const MAX_RUNTIME_RELATIVE_PATH_BYTES: usize = 512;

/// Borrowed, non-serializable observation over one retained runtime subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeInspectionObservationV1<'a> {
    /// Exact full-width passport subject.
    pub passport_id: &'a str,
    /// Exact root-relative entrypoint.
    pub entrypoint: &'a str,
    /// This observation proves only local component inspection.
    pub evidence_class: &'static str,
}

/// Typed structural refusal. A valid passport is still not authority.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RuntimePassportError {
    /// A field or canonical document violates the frozen shape.
    #[error("provider runtime passport malformed: {reason}")]
    Malformed {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// A canonical provider was paired with another provider's protocol.
    #[error("provider runtime passport protocol mismatch for {provider}: expected {expected}, got {actual}")]
    ProtocolMismatch {
        /// Canonical provider wire name.
        provider: String,
        /// Required protocol wire name.
        expected: String,
        /// Substituted protocol wire name.
        actual: String,
    },
    /// The caller's externally locked passport subject did not match.
    #[error("provider runtime passport id does not match the external lock")]
    IdMismatch,
    /// Filesystem inspection is unavailable on this platform.
    #[error("provider runtime passport inspection is unsupported on this platform")]
    PlatformUnsupported,
    /// Runtime directories or file ownership/modes violate fixed custody.
    #[error("provider runtime passport custody invalid: {reason}")]
    CustodyInvalid {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// The filesystem does not exactly realize the closed manifest.
    #[error("provider runtime passport manifest mismatch: {reason}")]
    ManifestMismatch {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// An already observed filesystem subject changed.
    #[error("provider runtime passport changed: {reason}")]
    Changed {
        /// Non-secret refusal detail.
        reason: String,
    },
}

impl RuntimePassportError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "RUNTIME_PASSPORT_MALFORMED",
            Self::ProtocolMismatch { .. } => "RUNTIME_PASSPORT_PROTOCOL_MISMATCH",
            Self::IdMismatch => "RUNTIME_PASSPORT_ID_MISMATCH",
            Self::PlatformUnsupported => "RUNTIME_PASSPORT_PLATFORM_UNSUPPORTED",
            Self::CustodyInvalid { .. } => "RUNTIME_PASSPORT_CUSTODY_INVALID",
            Self::ManifestMismatch { .. } => "RUNTIME_PASSPORT_MANIFEST_MISMATCH",
            Self::Changed { .. } => "RUNTIME_PASSPORT_CHANGED",
        }
    }
}

/// Purpose of one ordinary file in the closed runtime manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFileRoleV1 {
    /// Exact process entrypoint.
    Entrypoint,
    /// Additional executable shipped with the runtime.
    Executable,
    /// Dynamic loader.
    Loader,
    /// Interpreter used by the entrypoint.
    Interpreter,
    /// Native shared library.
    NativeLibrary,
    /// Language or package module.
    Module,
    /// Other immutable package resource.
    Resource,
    /// Provider protocol or output schema.
    ProtocolSchema,
    /// License text.
    License,
    /// Software bill of materials.
    Sbom,
}

impl RuntimeFileRoleV1 {
    fn executable(self) -> bool {
        matches!(
            self,
            Self::Entrypoint | Self::Executable | Self::Loader | Self::Interpreter
        )
    }
}

/// One ordinary file, addressed relative to the immutable deployment root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFileV1 {
    /// Normalized printable-ASCII root-relative path.
    pub path: String,
    /// File purpose.
    pub role: RuntimeFileRoleV1,
    /// Read-only Unix permission bits, without file-type bits.
    pub mode: u32,
    /// Exact file length.
    pub size: u64,
    /// BLAKE3 of the exact file bytes.
    pub blake3: String,
}

/// Loader identity for a native executable or interpreter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeLoaderV1 {
    /// No dynamic loader is involved.
    Static,
    /// Exact manifest member used as the dynamic loader.
    Dynamic {
        /// Normalized root-relative loader path.
        path: String,
        /// Loader digest repeated as an explicit linkage binding.
        blake3: String,
    },
}

/// How the manifest entrypoint is executed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeExecutionV1 {
    /// The entrypoint is a native executable.
    Native {
        /// Static or exact dynamic loader facts.
        loader: RuntimeLoaderV1,
    },
    /// The entrypoint is consumed by an exact packaged interpreter.
    Interpreted {
        /// Normalized root-relative interpreter path.
        interpreter_path: String,
        /// Interpreter digest repeated as an explicit linkage binding.
        interpreter_blake3: String,
        /// Static or exact dynamic loader facts for the interpreter.
        loader: RuntimeLoaderV1,
    },
}

/// Exact immutable package identity for one provider CLI runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntimePassportV1 {
    /// Always [`RUNTIME_PASSPORT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Canonical provider wire name: `claude`, `codex`, `cursor`, or `agy`.
    pub provider: String,
    /// Required native provider protocol.
    pub protocol: ProviderProtocol,
    /// Exact packaged version and immutable-root path segment.
    pub version: String,
    /// Exact `/usr/lib/bullet/providers/<provider>/<version>` root.
    pub deployment_root: String,
    /// Exact root-relative entrypoint manifest member.
    pub entrypoint: String,
    /// Native loader or interpreter facts.
    pub execution: RuntimeExecutionV1,
    /// Strictly unsigned-byte-sorted, duplicate-free, closed file manifest.
    pub files: Vec<RuntimeFileV1>,
    /// Exact manifest length, repeated to make truncation explicit.
    pub aggregate_file_count: u32,
    /// Exact sum of all manifest member sizes.
    pub aggregate_size_bytes: u64,
}

impl ProviderRuntimePassportV1 {
    /// Validate every structural field. Success grants no authority and makes
    /// no claim that the described files exist.
    ///
    /// # Errors
    ///
    /// A stable [`RuntimePassportError`] for the first malformed or
    /// provider-substituted field.
    pub fn validate(&self) -> Result<(), RuntimePassportError> {
        if self.schema_version != RUNTIME_PASSPORT_SCHEMA_VERSION {
            return Err(malformed("schema_version must be 1"));
        }
        let required = ProviderProtocol::required_for_wire_provider(&self.provider)
            .map_err(|_| malformed("provider is not a canonical wire identity"))?;
        if self.protocol != required {
            return Err(RuntimePassportError::ProtocolMismatch {
                provider: self.provider.clone(),
                expected: required.as_str().to_string(),
                actual: self.protocol.as_str().to_string(),
            });
        }
        validate_version(&self.version)?;
        let root = format!(
            "{RUNTIME_DEPLOYMENT_PREFIX}/{}/{}",
            self.provider, self.version
        );
        if self.deployment_root != root {
            return Err(malformed(
                "deployment_root is not the normalized immutable root",
            ));
        }
        validate_relative_path("entrypoint", &self.entrypoint)?;
        self.validate_manifest()?;
        self.validate_execution()
    }

    /// RFC 8785 canonical bytes after full structural validation.
    ///
    /// # Errors
    ///
    /// `RUNTIME_PASSPORT_MALFORMED` for invalid fields or encoding failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimePassportError> {
        self.validate()?;
        let bytes = canonical_json(self).map_err(|_| malformed("RFC 8785 encoding failed"))?;
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(malformed("canonical passport exceeds 64 KiB"));
        }
        Ok(bytes)
    }

    /// Decode exactly one bounded RFC 8785 document and validate its shape.
    ///
    /// # Errors
    ///
    /// Unknown/duplicate fields, non-canonical bytes, and invalid structure
    /// return a stable typed refusal.
    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimePassportError> {
        let passport: Self = decode_canonical(bytes)
            .map_err(|_| malformed("document is not strict canonical ProviderRuntimePassportV1"))?;
        passport.validate()?;
        Ok(passport)
    }

    /// `rtp_` plus the full domain-separated BLAKE3 of canonical bytes.
    ///
    /// # Errors
    ///
    /// The same structural or encoding refusal as [`Self::canonical_bytes`].
    pub fn passport_id(&self) -> Result<String, RuntimePassportError> {
        let bytes = self.canonical_bytes()?;
        let digest = hash_framed_bytes(RUNTIME_PASSPORT_DOMAIN, &bytes)
            .map_err(|_| malformed("passport digest framing failed"))?;
        Ok(format!("{RUNTIME_PASSPORT_ID_PREFIX}{digest}"))
    }

    fn validate_manifest(&self) -> Result<(), RuntimePassportError> {
        if self.files.is_empty() || self.files.len() > MAX_RUNTIME_FILES {
            return Err(malformed("files must contain 1..=256 members"));
        }
        let count = u32::try_from(self.files.len())
            .map_err(|_| malformed("manifest count is outside the safe range"))?;
        if self.aggregate_file_count != count {
            return Err(malformed("aggregate_file_count does not match files"));
        }
        let mut total = 0_u64;
        let mut previous: Option<&[u8]> = None;
        let mut entrypoints = 0_u32;
        for file in &self.files {
            validate_relative_path("file path", &file.path)?;
            if previous.is_some_and(|path| path >= file.path.as_bytes()) {
                return Err(malformed(
                    "files must be strictly unsigned-byte-sorted and unique",
                ));
            }
            previous = Some(file.path.as_bytes());
            validate_file(file)?;
            total = total
                .checked_add(file.size)
                .ok_or_else(|| malformed("aggregate file size overflowed"))?;
            if file.role == RuntimeFileRoleV1::Entrypoint {
                entrypoints += 1;
                if file.path != self.entrypoint {
                    return Err(malformed("entrypoint role does not match entrypoint"));
                }
            }
        }
        if entrypoints != 1 {
            return Err(malformed("manifest must contain exactly one entrypoint"));
        }
        if total != self.aggregate_size_bytes
            || total > MAX_RUNTIME_TOTAL_BYTES
            || total > MAX_SAFE_INTEGER
        {
            return Err(malformed(
                "aggregate_size_bytes is invalid or does not match files",
            ));
        }
        Ok(())
    }

    fn validate_execution(&self) -> Result<(), RuntimePassportError> {
        match &self.execution {
            RuntimeExecutionV1::Native { loader } => self.validate_loader(loader),
            RuntimeExecutionV1::Interpreted {
                interpreter_path,
                interpreter_blake3,
                loader,
            } => {
                self.require_member(
                    interpreter_path,
                    RuntimeFileRoleV1::Interpreter,
                    interpreter_blake3,
                )?;
                self.validate_loader(loader)
            }
        }
    }

    fn validate_loader(&self, loader: &RuntimeLoaderV1) -> Result<(), RuntimePassportError> {
        match loader {
            RuntimeLoaderV1::Static => Ok(()),
            RuntimeLoaderV1::Dynamic { path, blake3 } => {
                self.require_member(path, RuntimeFileRoleV1::Loader, blake3)
            }
        }
    }

    fn require_member(
        &self,
        path: &str,
        role: RuntimeFileRoleV1,
        digest: &str,
    ) -> Result<(), RuntimePassportError> {
        validate_relative_path("linkage path", path)?;
        let member = self
            .files
            .binary_search_by_key(&path, |file| file.path.as_str())
            .ok()
            .map(|index| &self.files[index])
            .ok_or_else(|| malformed("linkage path is absent from files"))?;
        if member.role != role || member.blake3 != digest {
            return Err(malformed("linkage role or digest does not match files"));
        }
        Ok(())
    }
}

fn validate_file(file: &RuntimeFileV1) -> Result<(), RuntimePassportError> {
    if !is_lower_hex_64(&file.blake3) {
        return Err(malformed("file blake3 must be 64 lowercase hex characters"));
    }
    if file.size > MAX_RUNTIME_FILE_BYTES
        || file.size > MAX_SAFE_INTEGER
        || (file.role.executable() && file.size == 0)
    {
        return Err(malformed("file size is outside the admitted range"));
    }
    let valid_mode = file.mode <= 0o777
        && file.mode & 0o222 == 0
        && file.mode & 0o444 != 0
        && (!file.role.executable() || file.mode & 0o111 != 0);
    if !valid_mode {
        return Err(malformed(
            "file mode is not read-only or disagrees with its role",
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), RuntimePassportError> {
    let valid = !version.is_empty()
        && version.len() <= MAX_RUNTIME_VERSION_BYTES
        && version != "."
        && version != ".."
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'));
    if !valid {
        return Err(malformed(
            "version must be one bounded immutable-root segment",
        ));
    }
    Ok(())
}

fn validate_relative_path(field: &str, path: &str) -> Result<(), RuntimePassportError> {
    let segments_ok = !path.is_empty()
        && path.len() <= MAX_RUNTIME_RELATIVE_PATH_BYTES
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !segments_ok {
        return Err(malformed(&format!(
            "{field} is not a normalized relative path"
        )));
    }
    Ok(())
}

fn malformed(reason: &str) -> RuntimePassportError {
    RuntimePassportError::Malformed {
        reason: reason.to_string(),
    }
}

fn decode_expected_passport(
    bytes: &[u8],
    expected: &str,
) -> Result<(ProviderRuntimePassportV1, String), RuntimePassportError> {
    let passport = ProviderRuntimePassportV1::decode(bytes)?;
    if !expected
        .strip_prefix(RUNTIME_PASSPORT_ID_PREFIX)
        .is_some_and(is_lower_hex_64)
    {
        return Err(RuntimePassportError::IdMismatch);
    }
    let actual = passport.passport_id()?;
    if expected != actual {
        return Err(RuntimePassportError::IdMismatch);
    }
    Ok((passport, actual))
}

#[cfg(target_os = "linux")]
fn custody(reason: impl Into<String>) -> RuntimePassportError {
    RuntimePassportError::CustodyInvalid {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn manifest(reason: impl Into<String>) -> RuntimePassportError {
    RuntimePassportError::ManifestMismatch {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn changed(reason: impl Into<String>) -> RuntimePassportError {
    RuntimePassportError::Changed {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn as_changed(error: RuntimePassportError) -> RuntimePassportError {
    changed(error.to_string())
}
