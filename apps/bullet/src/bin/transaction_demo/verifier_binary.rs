//! Exact executable admission for the component-only verifier fixture.

#[cfg(target_os = "linux")]
use sha2::{Digest as Sha2Digest, Sha256};
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::{File, Metadata};
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
const FD_ENV: &str = "BULLET_VERIFIER_FIXTURE_FD";
#[cfg(target_os = "linux")]
const DIGEST_ENV: &str = "BULLET_VERIFIER_FIXTURE_SHA256";
#[cfg(target_os = "linux")]
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct AdmittedVerifierFixture {
    #[cfg(target_os = "linux")]
    sealed_file: File,
}

impl AdmittedVerifierFixture {
    pub(super) fn spawn_path(&self) -> Result<PathBuf, String> {
        #[cfg(target_os = "linux")]
        {
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.sealed_file.as_raw_fd()));
            if !path.exists() {
                return Err(refusal("Linux procfd is unavailable for exact-inode spawn"));
            }
            Ok(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(non_linux_refusal())
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn verifier_fixture_binary() -> Result<AdmittedVerifierFixture, String> {
    configured_for_build(
        cfg!(debug_assertions),
        std::env::var_os(FD_ENV),
        std::env::var_os(DIGEST_ENV),
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn verifier_fixture_binary() -> Result<AdmittedVerifierFixture, String> {
    Err(non_linux_refusal())
}

#[cfg(not(target_os = "linux"))]
fn non_linux_refusal() -> String {
    refusal("verifier fixture execution requires Linux sealed-memfd admission")
}

#[cfg(target_os = "linux")]
fn configured_for_build(
    fixture_enabled: bool,
    fd_value: Option<OsString>,
    digest_value: Option<OsString>,
) -> Result<AdmittedVerifierFixture, String> {
    if !fixture_enabled {
        return Err(refusal(
            "the verifier fixture is unavailable in release binaries",
        ));
    }
    let fd_text = fd_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unprovisioned(FD_ENV))?
        .into_string()
        .map_err(|_| refusal("fixture descriptor must be a UTF-8 canonical decimal integer"))?;
    let fd = fd_text
        .parse::<i32>()
        .map_err(|_| refusal("fixture descriptor must be a UTF-8 canonical decimal integer"))?;
    if fd < 3 || fd.to_string() != fd_text {
        return Err(refusal(
            "fixture descriptor must be a canonical decimal integer greater than two",
        ));
    }
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
    admit_inherited_fd(fd, &digest)
}

#[cfg(target_os = "linux")]
fn unprovisioned(variable: &str) -> String {
    format!("VERIFIER_FIXTURE_BINARY_UNPROVISIONED: {variable} is required")
}

fn refusal(reason: impl AsRef<str>) -> String {
    format!(
        "VERIFIER_FIXTURE_BINARY_ADMISSION_REFUSED: {}",
        reason.as_ref()
    )
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "linux")]
impl SourceIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(target_os = "linux")]
fn admit_inherited_fd(fd: i32, expected_sha256: &str) -> Result<AdmittedVerifierFixture, String> {
    admit_inherited_fd_with_hook(fd, expected_sha256, || {})
}

#[cfg(target_os = "linux")]
fn admit_inherited_fd_with_hook(
    fd: i32,
    expected_sha256: &str,
    before_copy: impl FnOnce(),
) -> Result<AdmittedVerifierFixture, String> {
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    let inherited_metadata = std::fs::metadata(&descriptor_path).map_err(|error| {
        refusal(format!(
            "inspect inherited fixture descriptor failed: {error}"
        ))
    })?;
    let inherited = SourceIdentity::from_metadata(&inherited_metadata);
    admit_source_metadata(&inherited_metadata, inherited)?;
    let mut source_file = {
        use rustix::fs::{open, Mode, OFlags};
        let duplicate = open(
            &descriptor_path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| refusal(format!("open inherited fixture descriptor failed: {error}")))?;
        File::from(duplicate)
    };
    let before_metadata = source_file
        .metadata()
        .map_err(|error| refusal(format!("inherited fixture metadata failed: {error}")))?;
    let before = SourceIdentity::from_metadata(&before_metadata);
    admit_source_metadata(&before_metadata, before)?;
    if before != inherited {
        return Err(refusal(
            "inherited fixture descriptor identity changed while duplicating",
        ));
    }
    source_file.seek(SeekFrom::Start(0)).map_err(|error| {
        refusal(format!(
            "rewind inherited fixture descriptor failed: {error}"
        ))
    })?;
    before_copy();

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
    if SourceIdentity::from_metadata(&after) != before {
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

#[cfg(target_os = "linux")]
fn admit_source_metadata(metadata: &Metadata, identity: SourceIdentity) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || identity.size == 0
        || identity.size > MAX_EXECUTABLE_BYTES
        || identity.links == 0
        || identity.uid != rustix::process::geteuid().as_raw()
        || identity.mode & 0o111 == 0
    {
        return Err(refusal(
            "inherited fixture descriptor must be caller-owned, bounded, linked, regular, and executable",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, hard_link};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
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

    fn admit_file(file: &File, digest: &str) -> Result<AdmittedVerifierFixture, String> {
        admit_inherited_fd(file.as_raw_fd(), digest)
    }

    #[test]
    fn missing_malformed_and_release_subjects_refuse() {
        let unavailable = configured_for_build(false, None, None).unwrap_err();
        assert!(unavailable.contains("ADMISSION_REFUSED"));
        let missing_fd =
            configured_for_build(true, None, Some(OsString::from("0".repeat(64)))).unwrap_err();
        assert!(missing_fd.contains(FD_ENV));
        let missing_digest =
            configured_for_build(true, Some(OsString::from("3")), None).unwrap_err();
        assert!(missing_digest.contains(DIGEST_ENV));
        let malformed = configured_for_build(
            true,
            Some(OsString::from("3")),
            Some(OsString::from("A".repeat(64))),
        )
        .unwrap_err();
        assert!(malformed.contains("64 lowercase hexadecimal"));
        for invalid in ["/bin/false", "03", "-1", "2", "2147483648"] {
            let error = configured_for_build(
                true,
                Some(OsString::from(invalid)),
                Some(OsString::from("0".repeat(64))),
            )
            .unwrap_err();
            assert!(error.contains("descriptor"), "{invalid}: {error}");
        }
    }

    #[test]
    fn closed_directory_non_executable_oversize_and_wrong_digest_refuse() {
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
        let digest = sha256(&executable);
        let file = File::open(&executable).expect("open fixture");
        assert!(admit_file(&file, &"0".repeat(64)).is_err());

        let closed_fd = file.as_raw_fd();
        drop(file);
        assert!(admit_inherited_fd(closed_fd, &digest).is_err());

        let directory_fd = File::open(directory.path()).expect("open directory");
        assert!(admit_file(&directory_fd, &digest).is_err());
        let (socket, _peer) = UnixStream::pair().expect("socket pair");
        assert!(admit_inherited_fd(socket.as_raw_fd(), &digest).is_err());

        let empty = directory.path().join("empty");
        File::create(&empty).expect("create empty fixture");
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).expect("chmod empty");
        assert!(admit_file(&File::open(&empty).expect("open empty"), &digest).is_err());

        let unlinked_path = executable_fixture(directory.path(), "unlinked", "/bin/sh");
        let unlinked = File::open(&unlinked_path).expect("open unlinked fixture");
        fs::remove_file(unlinked_path).expect("unlink retained fixture");
        assert!(admit_file(&unlinked, &digest).is_err());

        let non_native = directory.path().join("non-native");
        fs::write(&non_native, b"not a native ELF executable").expect("write non-native fixture");
        fs::set_permissions(&non_native, fs::Permissions::from_mode(0o700))
            .expect("chmod non-native fixture");
        let non_native_file = File::open(&non_native).expect("open non-native fixture");
        assert!(admit_file(&non_native_file, &sha256(&non_native)).is_err());

        let non_executable = executable_fixture(directory.path(), "non-exec", "/bin/sh");
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o600))
            .expect("remove execute bit");
        let non_executable_file = File::open(&non_executable).expect("open non-executable");
        assert!(admit_file(&non_executable_file, &sha256(&non_executable)).is_err());

        let oversized = directory.path().join("oversized");
        let oversized_file = File::create(&oversized).expect("create oversized fixture");
        oversized_file
            .set_len(MAX_EXECUTABLE_BYTES + 1)
            .expect("make sparse oversized fixture");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o700))
            .expect("make oversized fixture executable");
        assert!(admit_file(&oversized_file, &digest).is_err());
    }

    #[test]
    fn two_link_fixture_is_sealed_before_sibling_link_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
        let linked = directory.path().join("cargo-linked-fixture");
        hard_link(&executable, &linked).expect("hardlink fixture");
        let digest = sha256(&executable);
        let mut inherited = File::open(&linked).expect("open inherited fixture");
        assert_eq!(inherited.metadata().expect("metadata").nlink(), 2);
        inherited
            .seek(SeekFrom::End(0))
            .expect("advance inherited source offset");
        let admitted = configured_for_build(
            true,
            Some(OsString::from(inherited.as_raw_fd().to_string())),
            Some(OsString::from(digest)),
        )
        .expect("admit two-link fixture through canonical fd grammar");
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

    #[test]
    fn sibling_link_mutation_after_identity_binding_refuses() {
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
        let sibling = directory.path().join("sibling");
        hard_link(&executable, &sibling).expect("hardlink fixture");
        let digest = sha256(&executable);
        let inherited = File::open(&executable).expect("open inherited fixture");
        let error = admit_inherited_fd_with_hook(inherited.as_raw_fd(), &digest, || {
            fs::copy("/bin/false", &sibling).expect("mutate sibling link");
        })
        .unwrap_err();
        assert!(error.contains("changed while hashing"));
    }
}
