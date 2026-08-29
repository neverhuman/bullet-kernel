//! Descriptor-bound reads for retained synthetic-selection artifact inputs.

use std::path::Path;

const REFUSAL: &str = "SYNTHETIC_PRIVATE_ARTIFACT_REFUSED";

/// Read one caller-owned retained artifact without reopening a checked pathname.
pub(super) fn read(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    {
        linux::read(path, max_bytes, label)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, max_bytes, label);
        Err(refused("private artifact reads require Linux"))
    }
}

fn refused(detail: impl AsRef<str>) -> String {
    format!("{REFUSAL}: {}", detail.as_ref())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::refused;
    use rustix::fs::{open, Mode, OFlags};
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Identity {
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

    impl Identity {
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

    pub(super) fn read(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
        read_with_hook(path, max_bytes, label, |_| Ok(()))
    }

    fn read_with_hook(
        path: &Path,
        max_bytes: u64,
        label: &str,
        after_open: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Vec<u8>, String> {
        if max_bytes == 0 || max_bytes == u64::MAX {
            return Err(refusal(label, "maximum byte bound is invalid"));
        }
        let owner = rustix::process::geteuid().as_raw();
        let pathname_before = inspect_path(path, owner, max_bytes, label)?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| refusal(label, format!("open no-follow descriptor: {error}")))?;
        let mut file = File::from(descriptor);
        let descriptor_before = inspect_descriptor(&file, owner, max_bytes, label)?;
        if descriptor_before != pathname_before {
            return Err(refusal(label, "pathname changed while opening"));
        }

        after_open(path)?;

        let descriptor_before_read = inspect_descriptor(&file, owner, max_bytes, label)?;
        if descriptor_before_read != descriptor_before {
            return Err(refusal(label, "descriptor changed before read"));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| refusal(label, format!("rewind descriptor: {error}")))?;
        let capacity = usize::try_from(descriptor_before.length)
            .map_err(|_| refusal(label, "artifact length cannot fit memory"))?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut file)
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| refusal(label, format!("bounded descriptor read: {error}")))?;
        if u64::try_from(bytes.len()).ok() != Some(descriptor_before.length) {
            return Err(refusal(label, "artifact length changed during read"));
        }
        let descriptor_after = inspect_descriptor(&file, owner, max_bytes, label)?;
        if descriptor_after != descriptor_before {
            return Err(refusal(label, "descriptor identity changed during read"));
        }
        let pathname_after = inspect_path(path, owner, max_bytes, label)?;
        if pathname_after != descriptor_before {
            return Err(refusal(label, "pathname identity changed after read"));
        }
        Ok(bytes)
    }

    fn inspect_path(
        path: &Path,
        owner: u32,
        max_bytes: u64,
        label: &str,
    ) -> Result<Identity, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| refusal(label, format!("inspect pathname: {error}")))?;
        admit(&metadata, owner, max_bytes, label)
    }

    fn inspect_descriptor(
        file: &File,
        owner: u32,
        max_bytes: u64,
        label: &str,
    ) -> Result<Identity, String> {
        let metadata = file
            .metadata()
            .map_err(|error| refusal(label, format!("inspect descriptor: {error}")))?;
        admit(&metadata, owner, max_bytes, label)
    }

    fn admit(
        metadata: &Metadata,
        owner: u32,
        max_bytes: u64,
        label: &str,
    ) -> Result<Identity, String> {
        let identity = Identity::from(metadata);
        if !metadata.file_type().is_file()
            || identity.owner != owner
            || identity.mode & 0o7777 != 0o600
            || identity.links != 1
            || identity.length == 0
            || identity.length > max_bytes
        {
            return Err(refusal(
                label,
                "artifact must be caller-owned single-link regular mode 0600 within bounds",
            ));
        }
        Ok(identity)
    }

    fn refusal(label: &str, detail: impl AsRef<str>) -> String {
        refused(format!("{label}: {}", detail.as_ref()))
    }

    #[cfg(test)]
    mod tests {
        use super::read_with_hook;
        use std::fs;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn private_file(root: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = root.join(name);
            fs::write(&path, bytes).expect("write private artifact");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("chmod private artifact");
            path
        }

        #[test]
        fn reads_stable_private_artifact() {
            let root = tempfile::tempdir().expect("private root");
            let path = private_file(root.path(), "journal", b"original");

            assert_eq!(
                super::read(&path, 64, "journal").expect("stable read"),
                b"original"
            );
        }

        #[test]
        fn rejects_regular_pathname_substitution_after_open_and_retains_both_subjects() {
            let root = tempfile::tempdir().expect("private root");
            let path = private_file(root.path(), "journal", b"original");
            let retained = root.path().join("journal-retained");
            let replacement = b"replacement";

            let error = read_with_hook(&path, 64, "journal", |target| {
                fs::rename(target, &retained).map_err(|error| error.to_string())?;
                private_file(root.path(), "journal", replacement);
                Ok(())
            })
            .expect_err("substituted pathname must refuse");

            assert!(error.starts_with("SYNTHETIC_PRIVATE_ARTIFACT_REFUSED: journal: "));
            assert_eq!(fs::read(&retained).expect("retained original"), b"original");
            assert_eq!(fs::read(&path).expect("retained replacement"), replacement);
        }

        #[test]
        fn rejects_symlink_pathname_substitution_after_open_and_retains_both_subjects() {
            let root = tempfile::tempdir().expect("private root");
            let path = private_file(root.path(), "recovery", b"original");
            let retained = root.path().join("recovery-retained");
            let replacement = private_file(root.path(), "replacement", b"replacement");

            let error = read_with_hook(&path, 64, "recovery", |target| {
                fs::rename(target, &retained).map_err(|error| error.to_string())?;
                symlink(&replacement, target).map_err(|error| error.to_string())?;
                Ok(())
            })
            .expect_err("symlinked pathname must refuse");

            assert!(error.starts_with("SYNTHETIC_PRIVATE_ARTIFACT_REFUSED: recovery: "));
            assert_eq!(fs::read(&retained).expect("retained original"), b"original");
            assert_eq!(
                fs::read(&replacement).expect("retained replacement"),
                b"replacement"
            );
        }
    }
}
