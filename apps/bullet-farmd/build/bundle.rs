//! Portal bundle verifier shared by `build.rs` and `tests/portal_bundle.rs`.
//!
//! A `dist` directory is admitted only when its own
//! `.bullet-portal-bundle-v1.json` manifest (produced by
//! `bullet-portal`'s `npm run bundle:generate`) is exact canonical JSON, its
//! framed BLAKE3 root binds its own body, its source subject is an
//! algorithm-tagged Git OID from a clean checkout, and every listed file is
//! present with exactly the recorded size and BLAKE3 digest. Any extra entry,
//! symlink, missing file, or drift is a typed [`Refusal`]. The bytes returned
//! are the bytes that were digested.

pub mod manifest;
pub mod records;

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Manifest file name inside `dist`.
pub const MANIFEST_NAME: &str = ".bullet-portal-bundle-v1.json";
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Typed verification refusal: a stable code plus a safe detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable machine-readable reason code.
    pub code: &'static str,
    /// Human-readable detail; never a secret.
    pub detail: String,
}

impl Refusal {
    /// Build a refusal from a stable code and a detail.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

/// One verified file; `body` is exactly what the manifest digest covers.
pub struct VerifiedFile {
    /// Bundle-relative path (`index.html` or `assets/<name>`).
    pub path: String,
    /// MIME type bound by the manifest.
    pub mime: &'static str,
    /// Lowercase BLAKE3 hex digest of `body`.
    pub digest_hex: String,
    /// Verified file bytes.
    pub body: Vec<u8>,
}

/// A `dist` directory whose manifest, root, and every file re-verified.
pub struct VerifiedBundle {
    /// Framed BLAKE3 root, `blake3:<hex>`.
    pub root: String,
    /// Algorithm-tagged source commit OID.
    pub commit_oid: String,
    /// Algorithm-tagged source tree OID.
    pub tree_oid: String,
    /// Verified files in manifest order.
    pub files: Vec<VerifiedFile>,
}

/// Verify `dist` against its own manifest and return the verified bytes.
///
/// # Errors
///
/// Returns a typed [`Refusal`] for a missing or non-canonical manifest, a root
/// that does not bind its body, a malformed source or tool subject, a symlink,
/// an entry the manifest does not list, or any size or digest drift.
pub fn verify(dist: &Path) -> Result<VerifiedBundle, Refusal> {
    if !dist.is_absolute() {
        return Err(Refusal::new(
            "PORTAL_DIST_NOT_ABSOLUTE",
            "the Portal dist path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(dist)
        .map_err(|error| Refusal::new("BUNDLE_MISSING", format!("{}: {error}", dist.display())))?;
    if !metadata.is_dir() {
        return Err(Refusal::new(
            "BUNDLE_ROOT_INVALID",
            "dist must be a real directory",
        ));
    }
    let raw = read_bounded(
        &dist.join(MANIFEST_NAME),
        MAX_MANIFEST_BYTES,
        "MANIFEST_MISSING",
    )?;
    let manifest = manifest::parse(&raw)?;
    check_directory(dist, &manifest.files)?;
    let files = manifest
        .files
        .iter()
        .map(|record| read_verified(dist, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedBundle {
        root: manifest.root,
        commit_oid: manifest.commit_oid,
        tree_oid: manifest.tree_oid,
        files,
    })
}

/// Refuse any `dist` entry the manifest does not list, and any symlink.
fn check_directory(dist: &Path, records: &[records::FileRecord]) -> Result<(), Refusal> {
    let listed = |candidate: &str| records.iter().any(|record| record.path == candidate);
    for (name, metadata) in list_directory(dist)? {
        if name == MANIFEST_NAME {
            continue;
        }
        if metadata.is_dir() {
            if name != "assets" {
                return Err(unexpected_entry(&name));
            }
            for (asset, asset_metadata) in list_directory(&dist.join("assets"))? {
                let relative = format!("assets/{asset}");
                if !asset_metadata.is_file() || !listed(&relative) {
                    return Err(unexpected_entry(&relative));
                }
            }
        } else if !metadata.is_file() || !listed(&name) {
            return Err(unexpected_entry(&name));
        }
    }
    Ok(())
}

fn list_directory(directory: &Path) -> Result<Vec<(String, fs::Metadata)>, Refusal> {
    let entries = fs::read_dir(directory).map_err(|error| {
        Refusal::new(
            "BUNDLE_READ_FAILED",
            format!("{}: {error}", directory.display()),
        )
    })?;
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| Refusal::new("BUNDLE_READ_FAILED", error.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| unexpected_entry("<non-UTF-8 name>"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| Refusal::new("BUNDLE_READ_FAILED", error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(Refusal::new(
                "SYMLINK_REJECTED",
                format!("bundle symlink rejected: {name}"),
            ));
        }
        listed.push((name, metadata));
    }
    Ok(listed)
}

fn unexpected_entry(relative: &str) -> Refusal {
    Refusal::new(
        "UNEXPECTED_BUNDLE_ENTRY",
        format!("dist entry is not in the manifest: {relative}"),
    )
}

fn read_verified(dist: &Path, record: &records::FileRecord) -> Result<VerifiedFile, Refusal> {
    let body = read_bounded(
        &dist.join(&record.path),
        MAX_FILE_BYTES,
        "BUNDLE_FILE_MISSING",
    )?;
    if body.len() as u64 != record.size {
        return Err(Refusal::new(
            "FILE_SIZE_MISMATCH",
            format!("{} does not have its manifest size", record.path),
        ));
    }
    let digest_hex = blake3::hash(&body).to_hex().to_string();
    if digest_hex != record.digest_hex {
        return Err(Refusal::new(
            "FILE_DIGEST_MISMATCH",
            format!("{} does not match its manifest digest", record.path),
        ));
    }
    Ok(VerifiedFile {
        path: record.path.clone(),
        mime: record.mime,
        digest_hex,
        body,
    })
}

/// Read a regular, non-symlink file of at most `maximum` bytes.
fn read_bounded(path: &Path, maximum: u64, missing: &'static str) -> Result<Vec<u8>, Refusal> {
    let file = open_regular(path)
        .map_err(|error| Refusal::new(missing, format!("{}: {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| Refusal::new("BUNDLE_READ_FAILED", error.to_string()))?;
    if !metadata.is_file() {
        return Err(Refusal::new(
            "NON_REGULAR_FILE",
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > maximum {
        return Err(Refusal::new(
            "FILE_SIZE_EXCEEDED",
            format!("{} exceeds {maximum} bytes", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Refusal::new("BUNDLE_READ_FAILED", error.to_string()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(Refusal::new(
            "FILE_CHANGED_DURING_READ",
            format!("{} changed while reading", path.display()),
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular(path: &Path) -> std::io::Result<fs::File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("symlink rejected"));
    }
    fs::File::open(path)
}
