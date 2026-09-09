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
    admit_source_shape(&inherited_metadata, inherited)?;
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
    admit_source_shape(&before_metadata, before)?;
    if before != inherited {
        return Err(refusal(
            "inherited fixture descriptor identity changed while duplicating",
        ));
    }
    admit_source_provenance(&source_file, before)?;
    source_file.seek(SeekFrom::Start(0)).map_err(|error| {
        refusal(format!(
            "rewind inherited fixture descriptor failed: {error}"
        ))
    })?;
    before_copy();

    use rustix::fs::{fchmod, fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, Mode};
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
    let required_seals = mandatory_seals();
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
fn admit_source_shape(metadata: &Metadata, identity: SourceIdentity) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || identity.size == 0
        || identity.size > MAX_EXECUTABLE_BYTES
        || identity.uid != rustix::process::geteuid().as_raw()
        || identity.mode & 0o111 == 0
    {
        return Err(refusal(
            "inherited fixture descriptor must be caller-owned, bounded, regular, and executable",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn admit_source_provenance(source: &File, identity: SourceIdentity) -> Result<(), String> {
    if identity.links != 0 {
        return Ok(());
    }
    let observed = rustix::fs::fcntl_get_seals(source)
        .map_err(|_| refusal("unlinked fixture descriptor must be a mandatory-sealed memfd"))?;
    if !observed.contains(mandatory_seals()) {
        return Err(refusal(
            "unlinked fixture descriptor must be a mandatory-sealed memfd",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mandatory_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::SEAL
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
mod tests;
