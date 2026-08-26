//! Exact executable admission for the component-only verifier fixture.

use sha2::{Digest as Sha2Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

const PATH_ENV: &str = "BULLET_VERIFIER_FIXTURE_BIN";
const DIGEST_ENV: &str = "BULLET_VERIFIER_FIXTURE_SHA256";
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct AdmittedVerifierFixture {
    sealed_file: File,
}

impl AdmittedVerifierFixture {
    pub(super) fn spawn_path(&self) -> Result<PathBuf, String> {
        let path = PathBuf::from(format!("/proc/self/fd/{}", self.sealed_file.as_raw_fd()));
        if !path.exists() {
            return Err(refusal("Linux procfd is unavailable for exact-inode spawn"));
        }
        Ok(path)
    }
}

pub(super) fn verifier_fixture_binary() -> Result<AdmittedVerifierFixture, String> {
    configured_for_build(
        cfg!(debug_assertions),
        std::env::var_os(PATH_ENV),
        std::env::var_os(DIGEST_ENV),
    )
}

fn configured_for_build(
    fixture_enabled: bool,
    path_value: Option<OsString>,
    digest_value: Option<OsString>,
) -> Result<AdmittedVerifierFixture, String> {
    if !fixture_enabled {
        return Err(refusal(
            "the verifier fixture is unavailable in release binaries",
        ));
    }
    let path = path_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unprovisioned(PATH_ENV))?;
    let digest = digest_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unprovisioned(DIGEST_ENV))?
        .into_string()
        .map_err(|_| refusal("fixture digest must be UTF-8 lowercase SHA-256"))?;
    if !is_lower_hex(&digest, 64) {
        return Err(refusal(
            "fixture digest must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    admit_path(PathBuf::from(path), &digest)
}

fn unprovisioned(variable: &str) -> String {
    format!("VERIFIER_FIXTURE_BINARY_UNPROVISIONED: {variable} is required")
}

fn refusal(reason: impl AsRef<str>) -> String {
    format!(
        "VERIFIER_FIXTURE_BINARY_ADMISSION_REFUSED: {}",
        reason.as_ref()
    )
}

fn admit_path(path: PathBuf, expected_sha256: &str) -> Result<AdmittedVerifierFixture, String> {
    if !path.is_absolute() {
        return Err(refusal("fixture executable path must be absolute"));
    }
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| refusal(format!("fixture executable metadata failed: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_EXECUTABLE_BYTES
        || metadata.nlink() != 1
    {
        return Err(refusal(
            "fixture executable must be a bounded single-link non-symlink regular file",
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| refusal(format!("canonicalize fixture executable failed: {error}")))?;
    if canonical != path {
        return Err(refusal("fixture executable path must already be canonical"));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(refusal("fixture executable has no execute bit"));
    }
    let mut source_file = {
        use rustix::fs::{open, Mode, OFlags};
        let fd = open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| refusal(format!("open exact fixture executable failed: {error}")))?;
        File::from(fd)
    };
    let opened = source_file
        .metadata()
        .map_err(|error| refusal(format!("opened fixture metadata failed: {error}")))?;
    if metadata.dev() != opened.dev()
        || metadata.ino() != opened.ino()
        || metadata.len() != opened.len()
        || opened.nlink() != 1
        || !opened.file_type().is_file()
    {
        return Err(refusal("fixture executable identity changed while opening"));
    }

    use rustix::fs::{
        fchmod, fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, Mode, SealFlags,
    };
    let sealed_fd = memfd_create(
        "bullet-verifier-fixture-admitted",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|error| refusal(format!("create sealed fixture image failed: {error}")))?;
    let mut sealed_file = File::from(sealed_fd);
    let (actual_sha256, copied_length) =
        copy_native_elf_and_hash(&mut source_file, &mut sealed_file)?;
    let after = source_file
        .metadata()
        .map_err(|error| refusal(format!("post-hash fixture metadata failed: {error}")))?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || after.nlink() != 1
    {
        return Err(refusal("fixture executable changed while hashing"));
    }
    if actual_sha256 != expected_sha256 {
        return Err(refusal(
            "fixture executable SHA-256 does not match admission",
        ));
    }
    fchmod(&sealed_file, Mode::from_raw_mode(0o500))
        .map_err(|error| refusal(format!("mark sealed fixture executable failed: {error}")))?;
    let required_seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
    fcntl_add_seals(&sealed_file, required_seals)
        .map_err(|error| refusal(format!("seal exact fixture image failed: {error}")))?;
    let observed_seals = fcntl_get_seals(&sealed_file)
        .map_err(|error| refusal(format!("read back fixture seals failed: {error}")))?;
    if !observed_seals.contains(required_seals) {
        return Err(refusal("sealed fixture image is missing mandatory seals"));
    }
    sealed_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| refusal(format!("rewind sealed fixture image failed: {error}")))?;
    let (sealed_sha256, sealed_length) = sha256_and_count(&mut sealed_file)?;
    if sealed_sha256 != expected_sha256
        || sealed_sha256 != actual_sha256
        || sealed_length != copied_length
    {
        return Err(refusal(
            "sealed fixture image does not match the admitted hash and length",
        ));
    }
    Ok(AdmittedVerifierFixture { sealed_file })
}

fn copy_native_elf_and_hash(
    source: &mut File,
    destination: &mut File,
) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    let mut header = [0_u8; 20];
    let mut header_length = 0_usize;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| refusal(format!("read fixture executable failed: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| refusal("fixture size overflow"))?)
            .ok_or_else(|| refusal("fixture size overflow"))?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(refusal("fixture executable exceeds the byte bound"));
        }
        if header_length < header.len() {
            let copied = (header.len() - header_length).min(count);
            header[header_length..header_length + copied].copy_from_slice(&buffer[..copied]);
            header_length += copied;
        }
        hasher.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|error| refusal(format!("copy exact fixture image failed: {error}")))?;
    }
    if !is_native_elf_header(&header) {
        return Err(refusal(
            "fixture executable must be a native ELF64 little-endian image for this target",
        ));
    }
    Ok((hex_digest(hasher.finalize().as_slice()), total))
}

fn sha256_and_count(reader: &mut File) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| refusal(format!("read sealed fixture image failed: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| refusal("fixture size overflow"))?)
            .ok_or_else(|| refusal("fixture size overflow"))?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(refusal("sealed fixture image exceeds the byte bound"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((hex_digest(hasher.finalize().as_slice()), total))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, hard_link};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::process::Command;

    fn executable_fixture(directory: &Path, name: &str, source: &str) -> PathBuf {
        let path = directory.join(name);
        fs::copy(source, &path).expect("copy native executable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod fixture");
        path
    }

    fn sha256(path: &Path) -> String {
        let mut file = File::open(path).expect("open fixture");
        sha256_and_count(&mut file).expect("hash fixture").0
    }

    #[test]
    fn missing_malformed_and_release_subjects_refuse() {
        let unavailable = configured_for_build(false, None, None).unwrap_err();
        assert!(unavailable.contains("ADMISSION_REFUSED"));
        let missing_path =
            configured_for_build(true, None, Some(OsString::from("0".repeat(64)))).unwrap_err();
        assert!(missing_path.contains(PATH_ENV));
        let missing_digest =
            configured_for_build(true, Some(OsString::from("/bin/false")), None).unwrap_err();
        assert!(missing_digest.contains(DIGEST_ENV));
        let malformed = configured_for_build(
            true,
            Some(OsString::from("/bin/false")),
            Some(OsString::from("A".repeat(64))),
        )
        .unwrap_err();
        assert!(malformed.contains("64 lowercase hexadecimal"));
    }

    #[test]
    fn relative_symlink_hardlink_and_wrong_digest_refuse() {
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
        let digest = sha256(&executable);
        assert!(admit_path(PathBuf::from("fixture"), &digest).is_err());

        let alias = directory.path().join("alias");
        symlink(&executable, &alias).expect("symlink");
        assert!(admit_path(alias, &digest).is_err());

        let linked = directory.path().join("linked");
        hard_link(&executable, &linked).expect("hardlink");
        assert!(admit_path(linked.clone(), &digest).is_err());
        fs::remove_file(executable).expect("remove first link");
        assert!(admit_path(linked, &"0".repeat(64)).is_err());
    }

    #[test]
    fn noncanonical_parent_refuses() {
        let directory = tempfile::tempdir().expect("tempdir");
        let real = directory.path().join("real");
        fs::create_dir(&real).expect("real directory");
        let executable = executable_fixture(&real, "fixture", "/bin/sh");
        let digest = sha256(&executable);
        let parent_alias = directory.path().join("parent-alias");
        symlink(&real, &parent_alias).expect("parent symlink");
        assert!(admit_path(parent_alias.join("fixture"), &digest).is_err());
    }

    #[test]
    fn sealed_image_survives_same_path_substitution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
        let digest = sha256(&executable);
        let admitted = admit_path(executable.clone(), &digest).expect("admit fixture");
        fs::copy("/bin/false", &executable).expect("substitute source path");
        let marker = directory.path().join("sealed-ran");
        let status = Command::new(admitted.spawn_path().expect("sealed procfd"))
            .args(["-c", "printf sealed > \"$1\"", "bullet-fixture"])
            .arg(&marker)
            .status()
            .expect("spawn sealed image");
        assert!(status.success());
        assert_eq!(fs::read_to_string(marker).expect("marker"), "sealed");
    }
}
