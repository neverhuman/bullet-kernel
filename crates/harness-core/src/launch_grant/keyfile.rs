//! Operator-held launch-grant signing key on disk:
//! `<data-dir>/authority/launch-grant.key`, 64 raw bytes, mode 0600, owned by
//! the current user, never a symlink, never overwritten.

use super::keys::{LaunchGrantSigningKey, SIGNING_KEY_BYTES};
use crate::error::HarnessError;
use std::path::{Path, PathBuf};

/// Key file name below `<data-dir>/authority/`.
pub const LAUNCH_GRANT_KEY_FILE: &str = "launch-grant.key";
const AUTHORITY_DIRECTORY: &str = "authority";

/// Path of the signing key below `data_dir`.
#[must_use]
pub fn signing_key_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(AUTHORITY_DIRECTORY)
        .join(LAUNCH_GRANT_KEY_FILE)
}

/// Generate and persist a new key, refusing to replace an existing one.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for a relative data directory, an existing key file,
/// or a filesystem failure. Only Unix hosts are certified.
pub fn write_new_signing_key(
    data_dir: &Path,
    issuer: &str,
    key_id: &str,
) -> Result<LaunchGrantSigningKey, HarnessError> {
    #[cfg(not(unix))]
    {
        let _ = (data_dir, issuer, key_id);
        Err(invalid("operator key custody is certified only on Unix"))
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if !data_dir.is_absolute() {
            return Err(invalid("data directory must be absolute"));
        }
        let directory = data_dir.join(AUTHORITY_DIRECTORY);
        if !directory.exists() {
            std::fs::create_dir_all(&directory)
                .map_err(|error| io("create authority dir", &error))?;
        }
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|error| io("authority dir metadata", &error))?;
        if !metadata.file_type().is_dir() {
            return Err(invalid("authority path is not a directory"));
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| io("restrict authority dir", &error))?;
        let path = directory.join(LAUNCH_GRANT_KEY_FILE);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(invalid(
                "signing key already exists; refusing to overwrite operator key material",
            ));
        }
        let key = LaunchGrantSigningKey::generate(issuer, key_id)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| io("create key file without replacement", &error))?;
        file.write_all(key.secret_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| io("write key file", &error))?;
        std::fs::File::open(&directory)
            .and_then(|handle| handle.sync_all())
            .map_err(|error| io("sync authority dir", &error))?;
        Ok(key)
    }
}

/// Load the operator key, refusing anything but an absolute, non-symlink,
/// regular, 0600, self-owned, exactly 64-byte file.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for every custody violation.
pub fn load_signing_key(
    data_dir: &Path,
    issuer: &str,
    key_id: &str,
) -> Result<LaunchGrantSigningKey, HarnessError> {
    #[cfg(not(unix))]
    {
        let _ = (data_dir, issuer, key_id);
        Err(invalid("operator key custody is certified only on Unix"))
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        if !data_dir.is_absolute() {
            return Err(invalid("data directory must be absolute"));
        }
        let path = signing_key_path(data_dir);
        let linkless =
            std::fs::symlink_metadata(&path).map_err(|error| io("signing key metadata", &error))?;
        if linkless.file_type().is_symlink() || !linkless.file_type().is_file() {
            return Err(invalid("signing key must be a regular file, not a symlink"));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| io("open signing key", &error))?;
        let opened = file
            .metadata()
            .map_err(|error| io("opened signing key metadata", &error))?;
        if !opened.file_type().is_file()
            || opened.dev() != linkless.dev()
            || opened.ino() != linkless.ino()
        {
            return Err(invalid("signing key identity changed while opening"));
        }
        if opened.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid("signing key mode must be exactly 0600"));
        }
        if opened.uid() != current_uid() {
            return Err(invalid("signing key must be owned by the current user"));
        }
        if opened.len() != SIGNING_KEY_BYTES as u64 {
            return Err(invalid("signing key must be exactly 64 raw bytes"));
        }
        let mut bytes = Vec::with_capacity(SIGNING_KEY_BYTES + 1);
        file.take(SIGNING_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io("read signing key", &error))?;
        if bytes.len() != SIGNING_KEY_BYTES {
            return Err(invalid("signing key must be exactly 64 raw bytes"));
        }
        LaunchGrantSigningKey::from_bytes(issuer, key_id, &bytes)
    }
}

/// Effective owner of this process as reported by procfs; unreadable procfs
/// yields a sentinel that matches no file owner, so custody fails closed.
#[cfg(unix)]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX)
}

fn invalid(reason: &str) -> HarnessError {
    HarnessError::LaunchGrantInvalid {
        reason: reason.to_string(),
    }
}

fn io(context: &str, error: &std::io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}
