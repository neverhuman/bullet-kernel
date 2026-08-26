//! Exact executable admission for the BulletGit daemon.

use crate::error::RunnerError;
use sha2::{Digest as Sha2Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_GITD_BYTES: u64 = 256 * 1024 * 1024;

/// An immutable sealed copy of a daemon whose bytes matched the configured digest.
///
/// Linux executes only the sealed memfd, never the mutable source pathname or
/// source inode.
#[derive(Debug)]
pub struct AdmittedGitdBinary {
    path: PathBuf,
    sealed_file: File,
    sha256: String,
}

impl AdmittedGitdBinary {
    /// Canonical operator-configured path used to identify this subject.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lowercase SHA-256 of the exact opened bytes.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn spawn_path(&self) -> Result<PathBuf, RunnerError> {
        #[cfg(target_os = "linux")]
        {
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.sealed_file.as_raw_fd()));
            if !path.exists() {
                return Err(admission(
                    "Linux procfd is unavailable for exact-inode spawn",
                ));
            }
            Ok(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(admission(
                "gitd mutation is unsupported outside the certified Linux profile",
            ))
        }
    }
}

/// Resolve and admit the production daemon from explicit configuration.
///
/// # Errors
///
/// Missing configuration returns `GITD_BINARY_UNPROVISIONED`; every malformed
/// or mismatched executable subject returns `GITD_BINARY_ADMISSION_REFUSED`.
pub fn gitd_binary() -> Result<AdmittedGitdBinary, RunnerError> {
    admit_configured(
        "BULLET_GITD_BIN",
        std::env::var_os("BULLET_GITD_BIN"),
        "BULLET_GITD_SHA256",
        std::env::var_os("BULLET_GITD_SHA256"),
    )
}

/// Resolve and admit the fixture-only daemon in a debug build.
///
/// # Errors
///
/// Release builds always refuse. Debug builds require the same exact path and
/// digest contract as production under fixture-specific variables.
pub fn gitd_fixture_binary() -> Result<AdmittedGitdBinary, RunnerError> {
    fixture_binary_for_build(
        cfg!(debug_assertions),
        std::env::var_os("BULLET_GITD_FIXTURE_BIN"),
        std::env::var_os("BULLET_GITD_FIXTURE_SHA256"),
    )
}

fn fixture_binary_for_build(
    debug_authority_enabled: bool,
    path: Option<OsString>,
    digest: Option<OsString>,
) -> Result<AdmittedGitdBinary, RunnerError> {
    if !debug_authority_enabled {
        return Err(admission(
            "fixture-authority daemon is unavailable in release binaries",
        ));
    }
    admit_configured(
        "BULLET_GITD_FIXTURE_BIN",
        path,
        "BULLET_GITD_FIXTURE_SHA256",
        digest,
    )
}

fn unprovisioned(variable: &str) -> RunnerError {
    RunnerError::GitdBinaryUnprovisioned {
        variable: variable.to_string(),
    }
}

fn admission(reason: impl Into<String>) -> RunnerError {
    RunnerError::GitdBinaryAdmission {
        reason: reason.into(),
    }
}

fn admit_configured(
    path_variable: &str,
    path_value: Option<OsString>,
    digest_variable: &str,
    digest_value: Option<OsString>,
) -> Result<AdmittedGitdBinary, RunnerError> {
    let path_value = path_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unprovisioned(path_variable))?;
    let digest_value = digest_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unprovisioned(digest_variable))?;
    let expected_sha256 = digest_value
        .into_string()
        .map_err(|_| admission(format!("{digest_variable} must be UTF-8 lowercase SHA-256")))?;
    if !is_lower_hex(&expected_sha256, 64) {
        return Err(admission(format!(
            "{digest_variable} must be exactly 64 lowercase hexadecimal characters"
        )));
    }
    admit_path(PathBuf::from(path_value), expected_sha256)
}

fn admit_path(path: PathBuf, expected_sha256: String) -> Result<AdmittedGitdBinary, RunnerError> {
    if !path.is_absolute() {
        return Err(admission("gitd executable path must be absolute"));
    }
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| admission(format!("gitd executable metadata failed: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_GITD_BYTES {
        return Err(admission(
            "gitd executable must be a bounded non-symlink regular file",
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| admission(format!("canonicalize gitd executable failed: {error}")))?;
    if canonical != path {
        return Err(admission("gitd executable path must already be canonical"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(admission("gitd executable has no execute bit"));
    }
    #[cfg(not(target_os = "linux"))]
    return Err(admission(
        "gitd mutation is unsupported outside the certified Linux profile",
    ));

    #[cfg(target_os = "linux")]
    let mut source_file = {
        use rustix::fs::{open, Mode, OFlags};
        let fd = open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| admission(format!("open exact gitd executable failed: {error}")))?;
        File::from(fd)
    };

    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{
            fchmod, fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, Mode, SealFlags,
        };

        let opened = source_file
            .metadata()
            .map_err(|error| admission(format!("opened gitd metadata failed: {error}")))?;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || metadata.len() != opened.len()
            || !opened.file_type().is_file()
        {
            return Err(admission("gitd executable identity changed while opening"));
        }
        let sealed_fd = memfd_create(
            "bullet-gitd-admitted",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|error| admission(format!("create sealed gitd image failed: {error}")))?;
        let mut sealed_file = File::from(sealed_fd);
        let (actual_sha256, copied_length) =
            copy_native_elf_and_hash(&mut source_file, &mut sealed_file)?;
        let after = source_file
            .metadata()
            .map_err(|error| admission(format!("post-hash gitd metadata failed: {error}")))?;
        if opened.dev() != after.dev() || opened.ino() != after.ino() || opened.len() != after.len()
        {
            return Err(admission("gitd executable changed while hashing"));
        }
        if actual_sha256 != expected_sha256 {
            return Err(admission(
                "gitd executable SHA-256 does not match admission",
            ));
        }
        fchmod(&sealed_file, Mode::from_raw_mode(0o500))
            .map_err(|error| admission(format!("mark sealed gitd executable failed: {error}")))?;
        let required_seals =
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        fcntl_add_seals(&sealed_file, required_seals)
            .map_err(|error| admission(format!("seal exact gitd image failed: {error}")))?;
        let observed_seals = fcntl_get_seals(&sealed_file)
            .map_err(|error| admission(format!("read back gitd seals failed: {error}")))?;
        if !observed_seals.contains(required_seals) {
            return Err(admission("sealed gitd image is missing mandatory seals"));
        }
        sealed_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| admission(format!("rewind sealed gitd image failed: {error}")))?;
        let (sealed_sha256, sealed_length) = sha256_and_count(&mut sealed_file)?;
        if sealed_sha256 != expected_sha256
            || sealed_sha256 != actual_sha256
            || sealed_length != copied_length
        {
            return Err(admission(
                "sealed gitd image does not match the admitted hash and length",
            ));
        }
        Ok(AdmittedGitdBinary {
            path,
            sealed_file,
            sha256: sealed_sha256,
        })
    }
}

fn copy_native_elf_and_hash(
    source: &mut File,
    destination: &mut File,
) -> Result<(String, u64), RunnerError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    let mut header = [0_u8; 20];
    let mut header_length = 0_usize;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| admission(format!("read gitd executable failed: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| admission("gitd size overflow"))?)
            .ok_or_else(|| admission("gitd size overflow"))?;
        if total > MAX_GITD_BYTES {
            return Err(admission("gitd executable exceeds the byte bound"));
        }
        if header_length < header.len() {
            let copied = (header.len() - header_length).min(count);
            header[header_length..header_length + copied].copy_from_slice(&buffer[..copied]);
            header_length += copied;
        }
        hasher.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|error| admission(format!("copy exact gitd image failed: {error}")))?;
    }
    if !is_native_elf_header(&header) {
        return Err(admission(
            "gitd executable must be a native ELF64 little-endian image for this target",
        ));
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn is_native_elf_header(header: &[u8; 20]) -> bool {
    if header[..4] != [0x7f, b'E', b'L', b'F'] || header[4] != 2 || header[5] != 1 {
        return false;
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    #[cfg(target_arch = "x86_64")]
    return machine == 62;
    #[cfg(target_arch = "aarch64")]
    return machine == 183;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    false
}

fn sha256_and_count(reader: &mut File) -> Result<(String, u64), RunnerError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| admission(format!("read sealed gitd image failed: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| admission("gitd size overflow"))?)
            .ok_or_else(|| admission("gitd size overflow"))?;
        if total > MAX_GITD_BYTES {
            return Err(admission("sealed gitd image exceeds the byte bound"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
fn sha256_reader(reader: &mut File) -> Result<String, RunnerError> {
    sha256_and_count(reader).map(|(digest, _)| digest)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn sha256(path: &Path) -> String {
        let mut file = File::open(path).expect("open fixture");
        sha256_reader(&mut file).expect("hash fixture")
    }

    async fn assert_refused_without_execution(
        result: Result<AdmittedGitdBinary, RunnerError>,
        marker: &Path,
        expected_code: &str,
    ) {
        match result {
            Err(error) => assert_eq!(error.reason_code(), expected_code),
            Ok(binary) => {
                let session = crate::gitd::GitdSession::spawn_with(
                    binary,
                    [marker.as_os_str()],
                    serde_json::json!({}),
                )
                .await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Ok(mut session) = session {
                    let _ = session.kill().await;
                }
                assert!(!marker.exists(), "invalid daemon subject executed");
                panic!("invalid daemon subject was admitted");
            }
        }
        assert!(!marker.exists(), "refused daemon subject executed");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_subjects_never_execute_canary() {
        std::fs::create_dir_all("target").expect("target");
        let temp = tempfile::Builder::new()
            .prefix("gitd-admission.")
            .tempdir_in("target")
            .expect("tempdir");
        let executable = temp.path().join("gitd");
        std::fs::copy("/usr/bin/touch", &executable).expect("copy executable canary");
        let digest = sha256(&executable);
        let marker = temp.path().join("invalid-subject-ran");

        for result in [
            admit_configured("PATH_VAR", None, "DIGEST_VAR", None),
            admit_configured(
                "PATH_VAR",
                Some(OsString::new()),
                "DIGEST_VAR",
                Some(OsString::from(digest.clone())),
            ),
            admit_configured(
                "PATH_VAR",
                Some(executable.clone().into_os_string()),
                "DIGEST_VAR",
                None,
            ),
        ] {
            assert_refused_without_execution(result, &marker, "GITD_BINARY_UNPROVISIONED").await;
        }

        let relative = if executable.is_absolute() {
            executable
                .strip_prefix(std::env::current_dir().expect("cwd"))
                .expect("temp is beneath cwd")
                .to_path_buf()
        } else {
            executable.clone()
        };
        assert_refused_without_execution(
            admit_path(relative, digest.clone()),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;

        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&executable, permissions).expect("permissions");
        assert_refused_without_execution(
            admit_path(executable.clone(), digest.clone()),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).expect("permissions");

        let link = temp.path().join("gitd-link");
        symlink(&executable, &link).expect("symlink");
        for result in [
            admit_path(link, digest),
            admit_path(executable.clone(), "0".repeat(64)),
            admit_configured(
                "PATH_VAR",
                Some(executable.into_os_string()),
                "DIGEST_VAR",
                Some(OsString::from("A".repeat(64))),
            ),
        ] {
            assert_refused_without_execution(result, &marker, "GITD_BINARY_ADMISSION_REFUSED")
                .await;
        }

        let script = temp.path().join("gitd-script");
        std::fs::write(&script, b"#!/bin/sh\ntouch \"$1\"\n").expect("write script");
        let mut permissions = std::fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).expect("script permissions");
        let script_digest = sha256(&script);
        assert_refused_without_execution(
            admit_path(script, script_digest),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sealed_image_survives_same_inode_overwrite() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = temp.path().join("gitd");
        std::fs::copy("/usr/bin/touch", &executable).expect("copy touch");
        let digest = sha256(&executable);
        let admitted = admit_path(executable.clone(), digest).expect("admit touch inode");
        let before = std::fs::metadata(&executable).expect("before metadata");
        let mut replacement = vec![0_u8; usize::try_from(before.len()).expect("bounded length")];
        let false_bytes = std::fs::read("/bin/false").expect("read false");
        assert!(false_bytes.len() <= replacement.len());
        replacement[..false_bytes.len()].copy_from_slice(&false_bytes);
        std::fs::write(&executable, replacement).expect("overwrite same inode");
        let after = std::fs::metadata(&executable).expect("after metadata");
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_ne!(admitted.sha256(), sha256(&executable));

        let procfd = admitted.spawn_path().expect("sealed procfd");
        let write_attempt = std::fs::OpenOptions::new().write(true).open(&procfd);
        if let Ok(mut reopened) = write_attempt {
            assert!(
                reopened.write_all(b"x").is_err(),
                "sealed memfd was writable"
            );
        }
        let marker = temp.path().join("original-inode-ran");
        let mut session = crate::gitd::GitdSession::spawn_with(
            admitted,
            [marker.as_os_str()],
            serde_json::json!({}),
        )
        .await
        .expect("spawn sealed image");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(marker.is_file(), "substituted pathname was executed");
        let _ = session.kill().await;
    }

    #[test]
    fn fixture_resolver_refuses_when_release_builds_disable_debug_authority() {
        let error = fixture_binary_for_build(false, None, None).unwrap_err();
        assert_eq!(error.reason_code(), "GITD_BINARY_ADMISSION_REFUSED");
    }
}
