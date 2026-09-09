//! Descriptor-bound, create-once custody for one synthetic selection receipt.

use std::path::Path;

const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 64;
const REFUSAL: &str = "SYNTHETIC_RECEIPT_STORAGE_REFUSED";

/// Create one immutable-by-contract receipt and return its exact durable readback.
pub(super) fn create_once(path: &Path, canonical_bytes: &[u8]) -> Result<Vec<u8>, String> {
    require_bounded_bytes(canonical_bytes)?;
    #[cfg(target_os = "linux")]
    {
        linux::create_once(path, canonical_bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(refused("receipt storage requires Linux"))
    }
}

/// Reopen one receipt and require the exact canonical bytes originally expected.
pub(super) fn reopen_exact(path: &Path, canonical_bytes: &[u8]) -> Result<Vec<u8>, String> {
    require_bounded_bytes(canonical_bytes)?;
    #[cfg(target_os = "linux")]
    {
        linux::reopen_exact(path, canonical_bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(refused("receipt storage requires Linux"))
    }
}

fn require_bounded_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_err(|_| refused("receipt length overflow"))?
            > MAX_RECEIPT_BYTES
    {
        return Err(refused("receipt bytes must be within 1 byte and 1 MiB"));
    }
    Ok(())
}

fn refused(detail: impl AsRef<str>) -> String {
    format!("{REFUSAL}: {}", detail.as_ref())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{refused, MAX_PATH_BYTES, MAX_PATH_COMPONENTS, MAX_RECEIPT_BYTES};
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::ffi::OsStr;
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, Path};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ParentIdentity {
        device: u64,
        inode: u64,
        owner: u32,
        mode: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ReceiptIdentity {
        device: u64,
        inode: u64,
        links: u64,
        length: u64,
        owner: u32,
        mode: u32,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    struct AdmittedParent<'a> {
        descriptor: File,
        path: &'a Path,
        target: &'a OsStr,
        identity: ParentIdentity,
        owner: u32,
    }

    pub(super) fn create_once(path: &Path, expected: &[u8]) -> Result<Vec<u8>, String> {
        create_once_with_hook(path, expected, |_| Ok(()))
    }

    pub(super) fn reopen_exact(path: &Path, expected: &[u8]) -> Result<Vec<u8>, String> {
        let parent = admit_parent(path)?;
        let mut file = open_existing(&parent)?;
        let (bytes, identity) = read_exact(&mut file, parent.owner, expected)?;
        admit_path_identity(path, parent.owner, identity)?;
        require_reopened_identity(&parent, identity)?;
        revalidate_parent(&parent)?;
        Ok(bytes)
    }

    pub(super) fn create_once_with_hook(
        path: &Path,
        expected: &[u8],
        after_readback: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Vec<u8>, String> {
        let parent = admit_parent(path)?;
        require_absent(path)?;
        revalidate_parent(&parent)?;
        let descriptor = openat(
            &parent.descriptor,
            parent.target,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| refused(format!("exclusive receipt creation failed: {error}")))?;
        let mut file = File::from(descriptor);
        admit_new_file(&file.metadata().map_err(io_refusal)?, parent.owner)?;
        file.write_all(expected)
            .map_err(|error| refused(format!("receipt write failed: {error}")))?;
        file.sync_all()
            .map_err(|error| refused(format!("receipt file sync failed: {error}")))?;
        let (bytes, identity) = read_exact(&mut file, parent.owner, expected)?;
        after_readback(path)?;
        admit_path_identity(path, parent.owner, identity)?;
        require_reopened_identity(&parent, identity)?;
        revalidate_parent(&parent)?;
        parent
            .descriptor
            .sync_all()
            .map_err(|error| refused(format!("receipt parent sync failed: {error}")))?;
        revalidate_parent(&parent)?;
        admit_path_identity(path, parent.owner, identity)?;
        Ok(bytes)
    }

    fn admit_parent(path: &Path) -> Result<AdmittedParent<'_>, String> {
        validate_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| refused("receipt path has no parent"))?;
        let target = path
            .file_name()
            .ok_or_else(|| refused("receipt path has no file name"))?;
        let before = fs::symlink_metadata(parent_path)
            .map_err(|error| refused(format!("inspect receipt parent: {error}")))?;
        let owner = rustix::process::geteuid().as_raw();
        let identity = require_parent_metadata(&before, owner)?;
        let canonical = fs::canonicalize(parent_path)
            .map_err(|error| refused(format!("canonicalize receipt parent: {error}")))?;
        if canonical != parent_path {
            return Err(refused("receipt parent must already be canonical"));
        }
        let descriptor = open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| refused(format!("open receipt parent: {error}")))?;
        let opened = require_parent_metadata(&descriptor.metadata().map_err(io_refusal)?, owner)?;
        if opened != identity {
            return Err(refused("receipt parent changed while opening"));
        }
        let admitted = AdmittedParent {
            descriptor,
            path: parent_path,
            target,
            identity,
            owner,
        };
        revalidate_parent(&admitted)?;
        Ok(admitted)
    }

    fn validate_path(path: &Path) -> Result<(), String> {
        if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
            return Err(refused("receipt path must be bounded and absolute"));
        }
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(refused("receipt path must begin at the filesystem root"));
        }
        let mut count = 0_usize;
        for component in components {
            if !matches!(component, Component::Normal(_)) {
                return Err(refused("receipt path must not contain dot components"));
            }
            count += 1;
        }
        if count == 0 || count > MAX_PATH_COMPONENTS {
            return Err(refused("receipt path component count is invalid"));
        }
        Ok(())
    }

    fn require_parent_metadata(metadata: &Metadata, owner: u32) -> Result<ParentIdentity, String> {
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(refused(
                "receipt parent must be caller-owned directory at exact mode 0700",
            ));
        }
        Ok(ParentIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode(),
        })
    }

    fn revalidate_parent(parent: &AdmittedParent<'_>) -> Result<(), String> {
        let descriptor = require_parent_metadata(
            &parent.descriptor.metadata().map_err(io_refusal)?,
            parent.owner,
        )?;
        let pathname = fs::symlink_metadata(parent.path)
            .map_err(|error| refused(format!("reinspect receipt parent: {error}")))?;
        if descriptor != parent.identity
            || require_parent_metadata(&pathname, parent.owner)? != parent.identity
        {
            return Err(refused("receipt parent identity changed"));
        }
        Ok(())
    }

    fn require_absent(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(refused("receipt target already exists or is a symlink")),
            Err(error) => Err(refused(format!("inspect receipt target: {error}"))),
        }
    }

    fn admit_new_file(metadata: &Metadata, owner: u32) -> Result<(), String> {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != 0
        {
            return Err(refused(
                "new receipt must be empty, caller-owned, single-link regular mode 0600",
            ));
        }
        Ok(())
    }

    fn open_existing(parent: &AdmittedParent<'_>) -> Result<File, String> {
        openat(
            &parent.descriptor,
            parent.target,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| refused(format!("open retained receipt: {error}")))
    }

    fn read_exact(
        file: &mut File,
        owner: u32,
        expected: &[u8],
    ) -> Result<(Vec<u8>, ReceiptIdentity), String> {
        let before = admit_receipt(&file.metadata().map_err(io_refusal)?, owner)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| refused(format!("rewind receipt: {error}")))?;
        let mut bytes = Vec::with_capacity(usize::try_from(before.length).unwrap_or(0));
        Read::by_ref(file)
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| refused(format!("bounded receipt read failed: {error}")))?;
        if u64::try_from(bytes.len()).ok() != Some(before.length) || bytes != expected {
            return Err(refused(
                "receipt readback differs from exact canonical bytes",
            ));
        }
        let after = admit_receipt(&file.metadata().map_err(io_refusal)?, owner)?;
        if after != before {
            return Err(refused("receipt changed during same-descriptor readback"));
        }
        Ok((bytes, before))
    }

    fn admit_receipt(metadata: &Metadata, owner: u32) -> Result<ReceiptIdentity, String> {
        let identity = ReceiptIdentity::from(metadata);
        if !metadata.file_type().is_file()
            || identity.owner != owner
            || identity.mode & 0o7777 != 0o600
            || identity.links != 1
            || identity.length == 0
            || identity.length > MAX_RECEIPT_BYTES
        {
            return Err(refused(
                "receipt must be caller-owned, bounded, single-link regular mode 0600",
            ));
        }
        Ok(identity)
    }

    fn admit_path_identity(
        path: &Path,
        owner: u32,
        expected: ReceiptIdentity,
    ) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| refused(format!("inspect receipt pathname: {error}")))?;
        if metadata.file_type().is_symlink()
            || admit_receipt(&metadata, owner)? != expected
            || metadata.dev() != expected.device
            || metadata.ino() != expected.inode
        {
            return Err(refused(
                "receipt pathname does not identify the opened descriptor",
            ));
        }
        Ok(())
    }

    fn require_reopened_identity(
        parent: &AdmittedParent<'_>,
        expected: ReceiptIdentity,
    ) -> Result<(), String> {
        let reopened = open_existing(parent)?;
        if admit_receipt(&reopened.metadata().map_err(io_refusal)?, parent.owner)? != expected {
            return Err(refused("receipt pathname changed before reopen"));
        }
        Ok(())
    }

    impl From<&Metadata> for ReceiptIdentity {
        fn from(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                links: metadata.nlink(),
                length: metadata.len(),
                owner: metadata.uid(),
                mode: metadata.mode(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }

    fn io_refusal(error: std::io::Error) -> String {
        refused(error.to_string())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const RECEIPT: &[u8] = br#"{"evidence_class":"COMPONENT_PROOF","schema_version":"test.v1"}"#;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("chmod root");
        root
    }

    #[test]
    fn create_once_is_private_durable_and_exactly_reopenable() {
        let root = root();
        let path = root.path().join("receipt.json");
        assert_eq!(create_once(&path, RECEIPT).expect("create"), RECEIPT);
        assert_eq!(reopen_exact(&path, RECEIPT).expect("reopen"), RECEIPT);
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    }

    #[test]
    fn existing_and_symlink_targets_never_overwrite() {
        let root = root();
        let existing = root.path().join("existing.json");
        fs::write(&existing, b"do-not-overwrite").expect("existing");
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(create_once(&existing, RECEIPT).is_err());
        assert_eq!(fs::read(&existing).expect("unchanged"), b"do-not-overwrite");

        let source = root.path().join("source.json");
        fs::write(&source, b"source-stays").expect("source");
        let link = root.path().join("receipt.json");
        symlink(&source, &link).expect("symlink");
        assert!(create_once(&link, RECEIPT).is_err());
        assert!(reopen_exact(&link, RECEIPT).is_err());
        assert_eq!(
            fs::read(&source).expect("source unchanged"),
            b"source-stays"
        );
    }

    #[test]
    fn hardlink_refuses_without_cleanup() {
        let root = root();
        let path = root.path().join("receipt.json");
        create_once(&path, RECEIPT).expect("create");
        let linked = root.path().join("linked.json");
        fs::hard_link(&path, &linked).expect("hard link");
        assert!(reopen_exact(&path, RECEIPT).is_err());
        assert!(path.exists() && linked.exists());
        assert_eq!(fs::read(&path).expect("receipt retained"), RECEIPT);
        assert_eq!(fs::read(&linked).expect("link retained"), RECEIPT);
    }

    #[test]
    fn truncation_refuses_without_repair_or_deletion() {
        let root = root();
        let path = root.path().join("receipt.json");
        create_once(&path, RECEIPT).expect("create");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("truncate");
        file.write_all(b"{").expect("write truncation");
        file.sync_all().expect("sync truncation");
        assert!(reopen_exact(&path, RECEIPT).is_err());
        assert_eq!(fs::read(&path).expect("retained truncation"), b"{");
    }

    #[test]
    fn pathname_substitution_during_create_refuses_and_preserves_both_files() {
        let root = root();
        let path = root.path().join("receipt.json");
        let original = root.path().join("original.json");
        let result = linux::create_once_with_hook(&path, RECEIPT, |created| {
            fs::rename(created, &original)
                .map_err(|error| format!("rename admitted receipt: {error}"))?;
            fs::write(created, RECEIPT)
                .map_err(|error| format!("write substitute receipt: {error}"))?;
            fs::set_permissions(created, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("chmod substitute receipt: {error}"))?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&original).expect("original retained"), RECEIPT);
        assert_eq!(fs::read(&path).expect("substitute retained"), RECEIPT);
    }

    #[test]
    fn path_parent_and_byte_bounds_refuse_before_creation() {
        let root = root();
        let path = root.path().join("receipt.json");
        assert!(create_once(Path::new("relative.json"), RECEIPT).is_err());
        assert!(create_once(&path, b"").is_err());
        assert!(create_once(&path, &vec![b'x'; MAX_RECEIPT_BYTES as usize + 1]).is_err());
        assert!(!path.exists());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).expect("chmod root");
        assert!(create_once(&path, RECEIPT).is_err());
        assert!(!path.exists());
    }
}
