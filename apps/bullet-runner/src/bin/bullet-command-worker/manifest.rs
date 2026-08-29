//! Exact immutable executable bundle admission for the component worker.

use super::error::{WorkerContext, WorkerError};
use bullet_harness_core::launch_grant::canonical_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST_SCHEMA: &str = "bullet.command-worker-binary-manifest.v1";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinarySubject {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryManifest {
    schema_version: String,
    transaction_offline: BinarySubject,
    farmd: BinarySubject,
    runner: BinarySubject,
    gitd: BinarySubject,
    verifier: BinarySubject,
}

#[derive(Debug)]
pub(super) struct AdmittedBinary {
    original: PathBuf,
    sealed: File,
    sha256: String,
}

impl AdmittedBinary {
    pub(super) fn procfd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.sealed.as_raw_fd()))
    }

    pub(super) fn inherited_fd(&self) -> i32 {
        self.sealed.as_raw_fd()
    }

    pub(super) fn original(&self) -> &Path {
        &self.original
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug)]
pub(super) struct AdmittedManifest {
    pub(super) transaction_offline: AdmittedBinary,
    pub(super) farmd: AdmittedBinary,
    pub(super) runner: AdmittedBinary,
    pub(super) gitd: AdmittedBinary,
    pub(super) verifier: AdmittedBinary,
    sha256: String,
}

impl AdmittedManifest {
    pub(super) fn admit(path: &Path) -> Result<Self, WorkerError> {
        let bytes = read_manifest(path)?;
        let manifest: BinaryManifest = serde_json::from_slice(&bytes)
            .worker("BINARY_MANIFEST_INVALID", "decode closed binary manifest")?;
        if manifest.schema_version != MANIFEST_SCHEMA
            || canonical_json(&manifest).ok() != Some(bytes.clone())
        {
            return Err(WorkerError::input(
                "BINARY_MANIFEST_INVALID",
                "binary manifest must use the admitted schema and canonical JSON",
            ));
        }
        let sha256 = sha256_bytes(&bytes);
        Ok(Self {
            transaction_offline: admit_binary(
                "transaction_offline",
                &manifest.transaction_offline,
            )?,
            farmd: admit_binary("farmd", &manifest.farmd)?,
            runner: admit_binary("runner", &manifest.runner)?,
            gitd: admit_binary("gitd", &manifest.gitd)?,
            verifier: admit_binary("verifier", &manifest.verifier)?,
            sha256,
        })
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }
}

fn read_manifest(path: &Path) -> Result<Vec<u8>, WorkerError> {
    if !path.is_absolute() {
        return Err(WorkerError::input(
            "BINARY_MANIFEST_INVALID",
            "manifest path is not absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .worker("BINARY_MANIFEST_INVALID", "inspect binary manifest")?;
    let canonical = path
        .canonicalize()
        .worker("BINARY_MANIFEST_INVALID", "canonicalize manifest")?;
    if canonical != path
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
        || metadata.permissions().mode() & 0o022 != 0
        || !trusted_owner(metadata.uid())
    {
        return Err(WorkerError::input(
            "BINARY_MANIFEST_INVALID",
            "manifest is not a canonical bounded protected regular file",
        ));
    }
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .worker("BINARY_MANIFEST_INVALID", "open exact binary manifest")?;
    let mut file = File::from(fd);
    let opened = file
        .metadata()
        .worker("BINARY_MANIFEST_INVALID", "inspect opened binary manifest")?;
    if identity(&metadata) != identity(&opened) {
        return Err(WorkerError::input(
            "BINARY_MANIFEST_INVALID",
            "binary manifest identity changed while opening",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .worker("BINARY_MANIFEST_INVALID", "read binary manifest")?;
    let after = file
        .metadata()
        .worker("BINARY_MANIFEST_INVALID", "reinspect binary manifest")?;
    if identity(&opened) != identity(&after) || bytes.len() as u64 != opened.len() {
        return Err(WorkerError::input(
            "BINARY_MANIFEST_INVALID",
            "manifest identity or length changed while reading",
        ));
    }
    Ok(bytes)
}

fn admit_binary(name: &str, subject: &BinarySubject) -> Result<AdmittedBinary, WorkerError> {
    if !subject.path.is_absolute() || !lower_hex(&subject.sha256) {
        return Err(binary_refusal(name, "path or SHA-256 is malformed"));
    }
    let before = std::fs::symlink_metadata(&subject.path)
        .map_err(|error| binary_refusal(name, format!("metadata: {error}")))?;
    let canonical = subject
        .path
        .canonicalize()
        .map_err(|error| binary_refusal(name, format!("canonicalize: {error}")))?;
    if canonical != subject.path || !admitted_metadata(&before) {
        return Err(binary_refusal(
            name,
            "subject is not a canonical protected native executable",
        ));
    }
    let fd = rustix::fs::open(
        &subject.path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| binary_refusal(name, format!("open exact subject: {error}")))?;
    let mut source = File::from(fd);
    let opened = source
        .metadata()
        .map_err(|error| binary_refusal(name, format!("opened metadata: {error}")))?;
    if identity(&before) != identity(&opened) {
        return Err(binary_refusal(
            name,
            "subject identity changed while opening",
        ));
    }
    let sealed_fd = rustix::fs::memfd_create(name, rustix::fs::MemfdFlags::ALLOW_SEALING)
        .map_err(|error| binary_refusal(name, format!("create sealed image: {error}")))?;
    let mut sealed = File::from(sealed_fd);
    let (digest, length, header) =
        copy_hash(&mut source, &mut sealed).map_err(|error| binary_refusal(name, error))?;
    let after = source
        .metadata()
        .map_err(|error| binary_refusal(name, format!("post-hash metadata: {error}")))?;
    if identity(&opened) != identity(&after) || digest != subject.sha256 || !native_elf(&header) {
        return Err(binary_refusal(
            name,
            "subject drifted, digest mismatched, or was not native ELF",
        ));
    }
    rustix::fs::fchmod(&sealed, rustix::fs::Mode::from_raw_mode(0o500))
        .map_err(|error| binary_refusal(name, format!("chmod sealed image: {error}")))?;
    let required = rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::SEAL;
    rustix::fs::fcntl_add_seals(&sealed, required)
        .map_err(|error| binary_refusal(name, format!("seal image: {error}")))?;
    if !rustix::fs::fcntl_get_seals(&sealed)
        .map_err(|error| binary_refusal(name, format!("read seals: {error}")))?
        .contains(required)
    {
        return Err(binary_refusal(name, "sealed image lacks mandatory seals"));
    }
    sealed
        .seek(SeekFrom::Start(0))
        .map_err(|error| binary_refusal(name, format!("rewind: {error}")))?;
    let (sealed_digest, sealed_length, _) = copy_hash(&mut sealed, &mut std::io::sink())
        .map_err(|error| binary_refusal(name, error))?;
    if sealed_digest != digest || sealed_length != length {
        return Err(binary_refusal(name, "sealed image readback mismatched"));
    }
    Ok(AdmittedBinary {
        original: subject.path.clone(),
        sealed,
        sha256: digest,
    })
}

fn admitted_metadata(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.len() > 0
        && metadata.len() <= MAX_BINARY_BYTES
        && metadata.permissions().mode() & 0o111 != 0
        && metadata.permissions().mode() & 0o022 == 0
        && trusted_owner(metadata.uid())
}

fn identity(metadata: &Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn copy_hash<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
) -> Result<(String, u64, [u8; 20]), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    let mut header = [0_u8; 20];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("read: {error}"))?;
        if count == 0 {
            break;
        }
        if total == 0 {
            header[..count.min(20)].copy_from_slice(&buffer[..count.min(20)]);
        }
        total = total
            .checked_add(count as u64)
            .ok_or("binary size overflow")?;
        if total > MAX_BINARY_BYTES {
            return Err("binary exceeds byte bound".into());
        }
        hasher.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|error| format!("write sealed image: {error}"))?;
    }
    Ok((hex::encode(hasher.finalize()), total, header))
}

fn native_elf(header: &[u8; 20]) -> bool {
    header[..6] == [0x7f, b'E', b'L', b'F', 2, 1]
        && u16::from_le_bytes([header[18], header[19]])
            == if cfg!(target_arch = "aarch64") {
                183
            } else {
                62
            }
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn binary_refusal(name: &str, detail: impl std::fmt::Display) -> WorkerError {
    WorkerError::input(
        "BINARY_SUBJECT_ADMISSION_REFUSED",
        format!("{name}: {detail}"),
    )
}

#[cfg(test)]
#[path = "manifest/tests.rs"]
mod tests;
