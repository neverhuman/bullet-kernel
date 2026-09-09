//! Policy file admission: `BULLET_POLICY_PATH` (absolute) or
//! `<data-dir>/policy/policy.json`. Absent is `POLICY_UNAVAILABLE`; present
//! but unsafe or malformed is `POLICY_INVALID`.

use super::LoadedPolicy;
use bullet_harness_core::HarnessError;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Environment variable naming an absolute policy override.
pub const POLICY_PATH_ENV: &str = "BULLET_POLICY_PATH";
const MAX_POLICY_BYTES: u64 = 256 * 1024;

/// Default policy location below a data directory.
#[must_use]
pub fn default_policy_path(data_dir: &Path) -> PathBuf {
    data_dir.join("policy").join("policy.json")
}

/// Load the policy from `override_path` or `<data_dir>/policy/policy.json`.
///
/// # Errors
///
/// `POLICY_UNAVAILABLE` for a relative path, a missing, symlinked, or
/// non-regular file, or an unreadable file; `POLICY_INVALID` for oversized,
/// non-canonical, malformed, or unsafe content.
pub fn load_policy(
    data_dir: &Path,
    override_path: Option<&Path>,
) -> Result<LoadedPolicy, HarnessError> {
    let path = match override_path {
        Some(path) => {
            if !path.is_absolute() {
                return Err(unavailable(&format!(
                    "{POLICY_PATH_ENV} must be absolute, got {}",
                    path.display()
                )));
            }
            path.to_path_buf()
        }
        None => {
            if !data_dir.is_absolute() {
                return Err(unavailable("data directory must be absolute"));
            }
            default_policy_path(data_dir)
        }
    };
    let bytes = read_regular_bounded(&path)?;
    LoadedPolicy::from_bytes(&bytes)
}

/// Load using `BULLET_POLICY_PATH` when set, else the data directory default.
///
/// # Errors
///
/// As `load_policy`.
pub fn load_policy_from_environment(data_dir: &Path) -> Result<LoadedPolicy, HarnessError> {
    let override_path = std::env::var_os(POLICY_PATH_ENV).map(PathBuf::from);
    load_policy(data_dir, override_path.as_deref())
}

fn read_regular_bounded(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let linkless = std::fs::symlink_metadata(path).map_err(|error| {
        unavailable(&format!(
            "policy {} is not readable: {error}",
            path.display()
        ))
    })?;
    if linkless.file_type().is_symlink() {
        return Err(unavailable(&format!(
            "policy {} must not be a symlink",
            path.display()
        )));
    }
    if !linkless.file_type().is_file() {
        return Err(unavailable(&format!(
            "policy {} is not a regular file",
            path.display()
        )));
    }
    if linkless.len() > MAX_POLICY_BYTES {
        return Err(HarnessError::PolicyInvalid {
            reason: format!("policy {} exceeds {MAX_POLICY_BYTES} bytes", path.display()),
        });
    }
    let file = std::fs::File::open(path)
        .map_err(|error| unavailable(&format!("open policy {}: {error}", path.display())))?;
    let opened = file
        .metadata()
        .map_err(|error| unavailable(&format!("inspect policy {}: {error}", path.display())))?;
    if !same_file(&linkless, &opened) {
        return Err(unavailable("policy identity changed while opening"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unavailable(&format!("read policy {}: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(HarnessError::PolicyInvalid {
            reason: format!("policy {} exceeds {MAX_POLICY_BYTES} bytes", path.display()),
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.file_type().is_file()
        && before.dev() == opened.dev()
        && before.ino() == opened.ino()
        && before.len() == opened.len()
}

#[cfg(not(unix))]
fn same_file(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    opened.file_type().is_file() && before.len() == opened.len()
}

fn unavailable(reason: &str) -> HarnessError {
    HarnessError::PolicyUnavailable {
        reason: reason.to_string(),
    }
}
