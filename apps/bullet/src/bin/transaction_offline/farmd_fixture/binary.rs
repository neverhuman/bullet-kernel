//! Immutable Linux executable image for the debug-only farmd fixture.

use super::fail;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 256 * 1024 * 1024;

pub(super) struct AdmittedFarmdBinary {
    image: File,
    digest: String,
}

impl AdmittedFarmdBinary {
    pub(super) fn open(path: &Path, expected: &str) -> Result<Self, String> {
        if !lower_hex(expected, 64) {
            return Err(fail("synthetic bullet-farmd digest differs"));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(fail(
                "synthetic farmd execution requires Linux sealed-memfd admission",
            ));
        }
        #[cfg(target_os = "linux")]
        Self::open_linux(path, expected)
    }

    #[cfg(target_os = "linux")]
    fn open_linux(path: &Path, expected: &str) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err(fail("synthetic bullet-farmd path is not absolute"));
        }
        let observed = fs::symlink_metadata(path)
            .map_err(|error| fail(format!("inspect synthetic bullet-farmd: {error}")))?;
        require_source(&observed)?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| fail(format!("canonicalize synthetic bullet-farmd: {error}")))?;
        if canonical != path {
            return Err(fail("synthetic bullet-farmd path is not canonical"));
        }
        let before = Identity::from(&observed);
        let source_fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| fail(format!("open synthetic bullet-farmd: {error}")))?;
        let mut source = File::from(source_fd);
        let opened = source
            .metadata()
            .map_err(|error| fail(format!("stat opened synthetic bullet-farmd: {error}")))?;
        if Identity::from(&opened) != before {
            return Err(fail(
                "synthetic bullet-farmd identity changed while opening",
            ));
        }
        let image_fd = rustix::fs::memfd_create(
            "bullet-farmd-synthetic-admitted",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|error| fail(format!("create sealed synthetic farmd image: {error}")))?;
        let mut image = File::from(image_fd);
        let (actual, length) = copy_elf(&mut source, &mut image)?;
        let after = source
            .metadata()
            .map_err(|error| fail(format!("restat synthetic bullet-farmd: {error}")))?;
        if Identity::from(&after) != before {
            return Err(fail("synthetic bullet-farmd changed while copying"));
        }
        if actual != expected {
            return Err(fail("synthetic bullet-farmd digest differs"));
        }
        rustix::fs::fchmod(&image, rustix::fs::Mode::from_raw_mode(0o500))
            .map_err(|error| fail(format!("mark sealed farmd executable: {error}")))?;
        let seals = mandatory_seals();
        rustix::fs::fcntl_add_seals(&image, seals)
            .map_err(|error| fail(format!("seal synthetic farmd image: {error}")))?;
        require_seals(&image)?;
        image
            .seek(SeekFrom::Start(0))
            .map_err(|error| fail(format!("rewind sealed farmd image: {error}")))?;
        let (sealed_digest, sealed_length) = hash(&mut image)?;
        if sealed_digest != actual || sealed_length != length {
            return Err(fail("sealed synthetic farmd image changed after admission"));
        }
        Ok(Self {
            image,
            digest: sealed_digest,
        })
    }

    pub(super) fn spawn_path(&self) -> Result<PathBuf, String> {
        #[cfg(not(target_os = "linux"))]
        return Err(fail(
            "synthetic farmd execution requires Linux sealed-memfd admission",
        ));
        #[cfg(target_os = "linux")]
        {
            require_seals(&self.image)?;
            if !lower_hex(&self.digest, 64) {
                return Err(fail("sealed synthetic farmd digest is invalid"));
            }
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.image.as_raw_fd()));
            if !path.exists() {
                return Err(fail("sealed synthetic farmd procfd is unavailable"));
            }
            Ok(path)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    uid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl From<&Metadata> for Identity {
    fn from(value: &Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            length: value.len(),
            links: value.nlink(),
            mode: value.mode(),
            uid: value.uid(),
            modified_seconds: value.mtime(),
            modified_nanoseconds: value.mtime_nsec(),
            changed_seconds: value.ctime(),
            changed_nanoseconds: value.ctime_nsec(),
        }
    }
}

fn require_source(metadata: &Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_BYTES
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(fail(
            "synthetic bullet-farmd must be caller-owned, bounded, regular, and executable",
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
fn require_seals(file: &File) -> Result<(), String> {
    let actual = rustix::fs::fcntl_get_seals(file)
        .map_err(|error| fail(format!("read sealed farmd image seals: {error}")))?;
    if !actual.contains(mandatory_seals()) {
        return Err(fail("sealed synthetic farmd image lacks mandatory seals"));
    }
    Ok(())
}

fn copy_elf(source: &mut File, image: &mut File) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut header = [0_u8; 20];
    let mut header_length = 0_usize;
    let mut total = 0_u64;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| fail(format!("read synthetic farmd image: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| fail("farmd size overflow"))?)
            .ok_or_else(|| fail("farmd size overflow"))?;
        if total > MAX_BYTES {
            return Err(fail("synthetic farmd image exceeds byte bound"));
        }
        if header_length < header.len() {
            let copied = (header.len() - header_length).min(count);
            header[header_length..header_length + copied].copy_from_slice(&buffer[..copied]);
            header_length += copied;
        }
        hasher.update(&buffer[..count]);
        image
            .write_all(&buffer[..count])
            .map_err(|error| fail(format!("copy synthetic farmd image: {error}")))?;
    }
    if !native_elf(&header) {
        return Err(fail("synthetic bullet-farmd is not a native ELF64 image"));
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn hash(file: &mut File) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| fail(format!("read sealed farmd image: {error}")))?;
        if count == 0 {
            break;
        }
        total += u64::try_from(count).map_err(|_| fail("sealed farmd size overflow"))?;
        if total > MAX_BYTES {
            return Err(fail("sealed synthetic farmd image exceeds byte bound"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn native_elf(header: &[u8; 20]) -> bool {
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

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn copy(path: &str, destination: &Path) -> String {
        fs::copy(path, destination).expect("copy executable");
        let bytes = fs::read(destination).expect("read executable");
        format!("{:x}", Sha256::digest(bytes))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_replacement_cannot_change_executed_image() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("farmd");
        let digest = copy("/usr/bin/true", &path);
        let admitted = AdmittedFarmdBinary::open(&path, &digest).expect("admit true");
        fs::remove_file(&path).expect("unlink admitted path");
        copy("/usr/bin/false", &path);
        let status = Command::new(admitted.spawn_path().expect("procfd"))
            .status()
            .expect("spawn admitted image");
        assert!(status.success(), "replacement pathname was executed");
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(admitted.spawn_path().expect("procfd"))
                .is_err(),
            "sealed image reopened writable"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_subjects_refuse() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("farmd");
        let digest = copy("/usr/bin/true", &path);
        assert!(AdmittedFarmdBinary::open(&path, &"0".repeat(64)).is_err());
        let link = root.path().join("link");
        symlink(&path, &link).expect("symlink");
        assert!(AdmittedFarmdBinary::open(&link, &digest).is_err());
        assert!(AdmittedFarmdBinary::open(root.path(), &digest).is_err());
    }
}
