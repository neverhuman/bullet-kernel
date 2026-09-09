//! Descriptor-bound inspection of one structurally valid runtime passport.

#[cfg(target_os = "linux")]
use super::{as_changed, changed, custody, manifest, ProviderRuntimePassportV1, RuntimeFileV1};
use super::{
    decode_expected_passport, RuntimeInspectionObservationV1, RuntimePassportError,
    RUNTIME_INSPECTION_EVIDENCE_CLASS,
};

/// Retained, non-cloneable descriptors for one inspected runtime.
pub struct InspectedProviderRuntimeV1 {
    passport_id: String,
    entrypoint: String,
    #[cfg(target_os = "linux")]
    state: linux::InspectionState,
}

impl InspectedProviderRuntimeV1 {
    /// Exact full-width passport subject.
    #[must_use]
    pub fn passport_id(&self) -> &str {
        &self.passport_id
    }

    /// Exact root-relative entrypoint.
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Emit a deliberately component-only, non-serializable observation.
    #[must_use]
    pub fn component_observation(&self) -> RuntimeInspectionObservationV1<'_> {
        RuntimeInspectionObservationV1 {
            passport_id: &self.passport_id,
            entrypoint: &self.entrypoint,
            evidence_class: RUNTIME_INSPECTION_EVIDENCE_CLASS,
        }
    }

    /// Re-enumerate and re-hash the retained runtime subject.
    ///
    /// # Errors
    ///
    /// `RUNTIME_PASSPORT_CHANGED` if any custody, identity, closure, size, or
    /// byte fact differs from the prepared subject.
    pub fn revalidate(&self) -> Result<(), RuntimePassportError> {
        #[cfg(target_os = "linux")]
        return self.state.revalidate();
        #[cfg(not(target_os = "linux"))]
        Err(RuntimePassportError::PlatformUnsupported)
    }
}

/// Inspect canonical passport bytes only after exact external-id agreement.
///
/// # Errors
///
/// Returns one stable runtime-passport refusal. No filesystem I/O occurs
/// before canonical decoding and full-width id comparison succeed.
pub fn inspect_provider_runtime(
    passport_canonical_bytes: &[u8],
    expected_passport_id: &str,
) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
    let decoded = decode_expected_passport(passport_canonical_bytes, expected_passport_id)?;
    #[cfg(target_os = "linux")]
    {
        let (passport, actual) = decoded;
        linux::inspect_production(passport, actual)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = decoded;
        Err(RuntimePassportError::PlatformUnsupported)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{open, openat2, Dir, Mode, OFlags, ResolveFlags};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};

    const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
    const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);

    type Identity = (u64, u64);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Snapshot(Identity, u32, u32, u64, u64, (i64, i64), (i64, i64));

    struct Held {
        descriptor: File,
        identity: Identity,
        snapshot: Option<Snapshot>,
    }

    struct Holdings {
        root: Held,
        directories: BTreeMap<String, Held>,
        files: BTreeMap<String, Held>,
    }

    struct Expectations<'a> {
        directories: BTreeSet<String>,
        files: BTreeMap<String, &'a RuntimeFileV1>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum HookPoint {
        BeforeOpen,
        DuringRead,
    }

    pub(super) struct InspectionState {
        passport: ProviderRuntimePassportV1,
        anchor: File,
        root_relative: PathBuf,
        expected_uid: u32,
        holdings: Holdings,
    }

    pub(super) fn inspect_production(
        passport: ProviderRuntimePassportV1,
        passport_id: String,
    ) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        let root_relative = PathBuf::from(&passport.deployment_root[1..]);
        inspect_source(
            passport,
            passport_id,
            Path::new("/"),
            &root_relative,
            0,
            &mut |_, _| {},
        )
    }

    impl InspectionState {
        pub(super) fn revalidate(&self) -> Result<(), RuntimePassportError> {
            let expected = expectations(&self.passport).map_err(as_changed)?;
            verify_retained(&self.holdings, &expected, self.expected_uid).map_err(as_changed)?;
            let root = open_root(&self.anchor, &self.root_relative).map_err(as_changed)?;
            let fresh =
                scan(root, &expected, self.expected_uid, &mut |_, _| {}).map_err(as_changed)?;
            compare_holdings(&self.holdings, &fresh)
        }
    }

    fn inspect_source(
        passport: ProviderRuntimePassportV1,
        passport_id: String,
        anchor_path: &Path,
        root_relative: &Path,
        expected_uid: u32,
        hook: &mut dyn FnMut(HookPoint, &str),
    ) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        let expected = expectations(&passport)?;
        let anchor = open(
            anchor_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| custody(format!("open fixed runtime anchor: {error}")))?;
        let root = open_root(&anchor, root_relative)?;
        let holdings = scan(root, &expected, expected_uid, hook)?;
        let fresh_root = open_root(&anchor, root_relative).map_err(as_changed)?;
        let fresh =
            scan(fresh_root, &expected, expected_uid, &mut |_, _| {}).map_err(as_changed)?;
        compare_holdings(&holdings, &fresh)?;
        let entrypoint = passport.entrypoint.clone();
        Ok(InspectedProviderRuntimeV1 {
            passport_id,
            entrypoint,
            state: InspectionState {
                passport,
                anchor,
                root_relative: root_relative.to_path_buf(),
                expected_uid,
                holdings,
            },
        })
    }

    #[cfg(test)]
    pub(super) fn inspect_test_source(
        passport: ProviderRuntimePassportV1,
        id: String,
        anchor: &Path,
        root: &Path,
        uid: u32,
        hook: &mut dyn FnMut(HookPoint, &str),
    ) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        inspect_source(passport, id, anchor, root, uid, hook)
    }

    fn expectations(
        passport: &ProviderRuntimePassportV1,
    ) -> Result<Expectations<'_>, RuntimePassportError> {
        let mut directories = BTreeSet::new();
        let mut files = BTreeMap::new();
        for file in &passport.files {
            files.insert(file.path.clone(), file);
            let parts: Vec<&str> = file.path.split('/').collect();
            for end in 1..parts.len() {
                directories.insert(parts[..end].join("/"));
            }
        }
        if directories.iter().any(|path| files.contains_key(path)) {
            return Err(manifest("a manifest file is also an implicit directory"));
        }
        Ok(Expectations { directories, files })
    }

    fn open_root(anchor: &File, relative: &Path) -> Result<File, RuntimePassportError> {
        openat2(
            anchor,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE,
        )
        .map(File::from)
        .map_err(|error| custody(format!("open fixed immutable runtime root: {error}")))
    }

    fn scan(
        root: File,
        expected: &Expectations<'_>,
        uid: u32,
        hook: &mut dyn FnMut(HookPoint, &str),
    ) -> Result<Holdings, RuntimePassportError> {
        let root_identity = admit_directory(&root, uid, "deployment root")?;
        let mut directories = BTreeMap::new();
        let mut files = BTreeMap::new();
        walk(&root, "", expected, uid, hook, &mut directories, &mut files)?;
        if directories.keys().ne(expected.directories.iter())
            || files.keys().ne(expected.files.keys())
        {
            return Err(manifest("runtime directory or member is missing"));
        }
        Ok(Holdings {
            root: Held {
                descriptor: root,
                identity: root_identity,
                snapshot: None,
            },
            directories,
            files,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        parent: &File,
        parent_path: &str,
        expected: &Expectations<'_>,
        uid: u32,
        hook: &mut dyn FnMut(HookPoint, &str),
        directories: &mut BTreeMap<String, Held>,
        files: &mut BTreeMap<String, Held>,
    ) -> Result<(), RuntimePassportError> {
        let entries = Dir::read_from(parent)
            .map_err(|error| manifest(format!("enumerate runtime directory: {error}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| manifest(format!("enumerate runtime directory: {error}")))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name_text = std::str::from_utf8(name)
                .map_err(|_| manifest("runtime contains a non-UTF-8 extra entry"))?;
            let path = if parent_path.is_empty() {
                name_text.to_string()
            } else {
                format!("{parent_path}/{name_text}")
            };
            hook(HookPoint::BeforeOpen, &path);
            let name_path = Path::new(OsStr::from_bytes(name));
            if expected.directories.contains(&path) {
                let child = openat2(
                    parent,
                    name_path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    RESOLVE,
                )
                .map(File::from)
                .map_err(|error| manifest(format!("open manifest directory {path}: {error}")))?;
                let identity = admit_directory(&child, uid, &path)?;
                if identity.1 != entry.ino() {
                    return Err(changed(format!("directory {path} changed before open")));
                }
                walk(&child, &path, expected, uid, hook, directories, files)?;
                directories.insert(
                    path,
                    Held {
                        descriptor: child,
                        identity,
                        snapshot: None,
                    },
                );
            } else if let Some(file) = expected.files.get(&path) {
                let child = openat2(
                    parent,
                    name_path,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                    RESOLVE,
                )
                .map(File::from)
                .map_err(|error| manifest(format!("open manifest member {path}: {error}")))?;
                let snapshot = admit_file(&child, file, uid)?;
                if snapshot.0 .1 != entry.ino() {
                    return Err(changed(format!("member {path} changed before open")));
                }
                hook(HookPoint::DuringRead, &path);
                verify_file_bytes(&child, file, snapshot)?;
                files.insert(
                    path,
                    Held {
                        descriptor: child,
                        identity: snapshot.0,
                        snapshot: Some(snapshot),
                    },
                );
            } else {
                return Err(manifest(format!("runtime contains extra entry {path}")));
            }
        }
        Ok(())
    }

    fn admit_directory(
        file: &File,
        uid: u32,
        path: &str,
    ) -> Result<Identity, RuntimePassportError> {
        let metadata = file
            .metadata()
            .map_err(|error| custody(format!("inspect runtime directory {path}: {error}")))?;
        if !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != IMMUTABLE_DIRECTORY_MODE
        {
            return Err(custody(format!(
                "directory {path} must be fixed-owner exact 0555"
            )));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    fn admit_file(
        file: &File,
        expected: &RuntimeFileV1,
        uid: u32,
    ) -> Result<Snapshot, RuntimePassportError> {
        let metadata = file
            .metadata()
            .map_err(|error| manifest(format!("inspect member {}: {error}", expected.path)))?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != expected.mode
        {
            return Err(custody(format!(
                "member {} type, owner, links, or mode differs",
                expected.path
            )));
        }
        if metadata.size() != expected.size {
            return Err(manifest(format!("member {} size differs", expected.path)));
        }
        Ok(snapshot(&metadata))
    }

    fn verify_file_bytes(
        file: &File,
        expected: &RuntimeFileV1,
        before: Snapshot,
    ) -> Result<(), RuntimePassportError> {
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut offset = 0_u64;
        loop {
            let read = file
                .read_at(&mut buffer, offset)
                .map_err(|error| manifest(format!("read member {}: {error}", expected.path)))?;
            if read == 0 {
                break;
            }
            offset = offset
                .checked_add(read as u64)
                .ok_or_else(|| manifest("runtime member read length overflowed"))?;
            if offset > expected.size {
                return Err(manifest(format!(
                    "member {} grew during read",
                    expected.path
                )));
            }
            hasher.update(&buffer[..read]);
        }
        let after = file
            .metadata()
            .map_err(|error| changed(format!("re-stat member {}: {error}", expected.path)))?;
        if snapshot(&after) != before {
            return Err(changed(format!(
                "member {} changed during read",
                expected.path
            )));
        }
        if offset != expected.size || hasher.finalize().to_hex().as_str() != expected.blake3 {
            return Err(manifest(format!("member {} bytes differ", expected.path)));
        }
        Ok(())
    }

    fn verify_retained(
        holdings: &Holdings,
        expected: &Expectations<'_>,
        uid: u32,
    ) -> Result<(), RuntimePassportError> {
        if admit_directory(&holdings.root.descriptor, uid, "deployment root")?
            != holdings.root.identity
        {
            return Err(changed("retained runtime root identity changed"));
        }
        for (path, directory) in &holdings.directories {
            if admit_directory(&directory.descriptor, uid, path)? != directory.identity {
                return Err(changed(format!(
                    "retained directory {path} identity changed"
                )));
            }
        }
        for (path, member) in &holdings.files {
            let expected = expected
                .files
                .get(path)
                .ok_or_else(|| changed("retained member left the expected manifest"))?;
            let snapshot = admit_file(&member.descriptor, expected, uid)?;
            if snapshot.0 != member.identity || Some(snapshot) != member.snapshot {
                return Err(changed(format!("retained member {path} identity changed")));
            }
            verify_file_bytes(&member.descriptor, expected, snapshot)?;
        }
        Ok(())
    }

    fn compare_holdings(left: &Holdings, right: &Holdings) -> Result<(), RuntimePassportError> {
        if left.root.identity != right.root.identity
            || left.directories.len() != right.directories.len()
            || left.files.len() != right.files.len()
            || left.directories.iter().any(|(path, held)| {
                right
                    .directories
                    .get(path)
                    .is_none_or(|fresh| fresh.identity != held.identity)
            })
            || left.files.iter().any(|(path, held)| {
                right.files.get(path).is_none_or(|fresh| {
                    fresh.identity != held.identity || fresh.snapshot != held.snapshot
                })
            })
        {
            return Err(changed(
                "runtime descriptor identities changed between scans",
            ));
        }
        Ok(())
    }

    fn snapshot(metadata: &std::fs::Metadata) -> Snapshot {
        Snapshot(
            (metadata.dev(), metadata.ino()),
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.size(),
            (metadata.mtime(), metadata.mtime_nsec()),
            (metadata.ctime(), metadata.ctime_nsec()),
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
