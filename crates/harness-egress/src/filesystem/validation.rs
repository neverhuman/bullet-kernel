#[path = "validation_support.rs"]
mod validation_support;
use validation_support::*;

use super::{FilesystemFileV0, FilesystemSandboxProfileV0, PreparedFilesystemSandbox};
use crate::error::EgressError;
use std::fs::{self, File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
/// Ceiling for a passport-declared provider bound: the runtime-passport
/// contract's own per-file maximum (512 MiB). A passport may admit less,
/// never more.
const MAX_PASSPORT_PROVIDER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SCHEMA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_FILES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl From<&Metadata> for Identity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

pub(super) struct OpenedFile {
    role: &'static str,
    path: PathBuf,
    file: File,
    identity: Identity,
    digest: String,
}

impl OpenedFile {
    pub(super) fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub(super) fn descriptor_number(&self) -> i32 {
        self.file.as_raw_fd()
    }

    fn revalidate(&self) -> Result<(), EgressError> {
        let named = fs::symlink_metadata(&self.path)
            .map_err(|_| changed(self.role, "named path is unavailable"))?;
        let retained = self
            .file
            .metadata()
            .map_err(|_| changed(self.role, "retained descriptor is unavailable"))?;
        if !named.file_type().is_file()
            || Identity::from(&named) != self.identity
            || Identity::from(&retained) != self.identity
        {
            return Err(changed(
                self.role,
                "identity, owner, mode, or link count drifted",
            ));
        }
        if digest(&self.file)? != self.digest {
            return Err(changed(self.role, "content digest drifted"));
        }
        Ok(())
    }
}

pub(super) struct OpenedDirectory {
    role: &'static str,
    path: PathBuf,
    file: File,
    identity: Identity,
}

impl OpenedDirectory {
    pub(super) fn descriptor_number(&self) -> i32 {
        self.file.as_raw_fd()
    }

    fn revalidate(&self) -> Result<(), EgressError> {
        let named = fs::symlink_metadata(&self.path)
            .map_err(|_| changed(self.role, "named path is unavailable"))?;
        let retained = self
            .file
            .metadata()
            .map_err(|_| changed(self.role, "retained descriptor is unavailable"))?;
        if !named.file_type().is_dir()
            || Identity::from(&named) != self.identity
            || Identity::from(&retained) != self.identity
        {
            return Err(changed(self.role, "identity, owner, or mode drifted"));
        }
        Ok(())
    }
}

pub(super) fn prepare(
    profile: FilesystemSandboxProfileV0,
) -> Result<PreparedFilesystemSandbox, EgressError> {
    validate_destinations(&profile)?;
    if profile.credential.is_some() {
        return Err(denied(
            "V0 credential paths are disabled pending brokered sealed-FD custody",
        ));
    }
    let current_uid = fs::metadata("/proc/self")
        .map_err(|err| EgressError::io("inspect current uid", &err))?
        .uid();
    if profile.runtime_files.len() > MAX_RUNTIME_FILES {
        return Err(denied("too many runtime files"));
    }
    let clone_directory =
        open_private_directory("clone directory", &profile.clone_directory, current_uid)?;
    let scratch_directory =
        open_private_directory("scratch directory", &profile.scratch_directory, current_uid)?;
    if overlaps(&profile.clone_directory, &profile.scratch_directory) {
        return Err(denied("clone and scratch directories overlap"));
    }
    let bubblewrap = open_file(
        "bubblewrap",
        &profile.bubblewrap,
        current_uid,
        true,
        FileOwner::Root,
        MAX_EXECUTABLE_BYTES,
    )?;
    let provider_max_bytes = match profile.provider_max_bytes {
        // A passport-declared bound must be explicit and sane: never zero,
        // never above the runtime contract's own per-file ceiling.
        Some(bytes) if bytes > 0 && bytes <= MAX_PASSPORT_PROVIDER_BYTES => bytes,
        Some(_) => return Err(denied("provider size bound is outside the admitted range")),
        None => MAX_EXECUTABLE_BYTES,
    };
    let provider = open_file(
        "provider",
        &profile.provider,
        current_uid,
        true,
        FileOwner::Root,
        provider_max_bytes,
    )?;
    let proposal_schema = open_file(
        "proposal schema",
        &profile.proposal_schema,
        current_uid,
        false,
        FileOwner::RootOrRunnerAuthored,
        MAX_SCHEMA_BYTES,
    )?;
    let ca_bundle = open_file(
        "CA bundle",
        &profile.ca_bundle,
        current_uid,
        false,
        FileOwner::Root,
        MAX_CA_BYTES,
    )?;
    let credential = None;
    let prepared_home = match &profile.prepared_home {
        Some(path) => {
            if overlaps(path, &profile.clone_directory)
                || overlaps(path, &profile.scratch_directory)
            {
                return Err(denied("prepared HOME overlaps clone or scratch"));
            }
            Some(open_private_directory("prepared HOME", path, current_uid)?)
        }
        None => None,
    };
    let runtime_files = profile
        .runtime_files
        .iter()
        .map(|runtime| {
            open_file(
                "runtime file",
                &runtime.source,
                current_uid,
                false,
                FileOwner::Root,
                MAX_EXECUTABLE_BYTES,
            )
            .map(|opened| (runtime.destination.clone(), opened))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut private_dirs = vec![&profile.clone_directory, &profile.scratch_directory];
    if let Some(home) = &profile.prepared_home {
        private_dirs.push(home);
    }
    reject_private_directory_sources(
        [&bubblewrap, &provider, &proposal_schema, &ca_bundle]
            .into_iter()
            .chain(credential.iter())
            .chain(runtime_files.iter().map(|(_, file)| file)),
        &private_dirs,
    )?;
    let provider_argv0 = profile
        .provider
        .path
        .file_name()
        .ok_or_else(|| denied("provider path has no file name"))?
        .to_os_string();
    Ok(PreparedFilesystemSandbox {
        profile,
        bubblewrap,
        provider,
        clone_directory,
        proposal_schema,
        ca_bundle,
        credential,
        prepared_home,
        runtime_files,
        scratch_directory,
        provider_argv0,
    })
}

pub(super) fn revalidate(prepared: &PreparedFilesystemSandbox) -> Result<(), EgressError> {
    prepared.bubblewrap.revalidate()?;
    prepared.provider.revalidate()?;
    prepared.clone_directory.revalidate()?;
    prepared.proposal_schema.revalidate()?;
    prepared.ca_bundle.revalidate()?;
    if let Some(credential) = &prepared.credential {
        credential.revalidate()?;
    }
    if let Some(home) = &prepared.prepared_home {
        home.revalidate()?;
    }
    for (_, file) in &prepared.runtime_files {
        file.revalidate()?;
    }
    prepared.scratch_directory.revalidate()
}

/// Who may own an admitted file. Root custody is the default for artifacts
/// staged by the operator. `RootOrRunnerAuthored` additionally admits a file
/// the runner itself wrote from a compiled-in constant, where integrity comes
/// from the exact content digest rather than filesystem custody: such a file
/// must be owned by the runner uid, owner-private (mode exactly 0600), and
/// its ancestor chain must be unwritable by group/other and owned by root or
/// the runner uid. Any other owner refuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FileOwner {
    Root,
    RootOrRunnerAuthored,
}

fn open_file(
    role: &'static str,
    admitted: &FilesystemFileV0,
    current_uid: u32,
    executable: bool,
    owner: FileOwner,
    max_bytes: u64,
) -> Result<OpenedFile, EgressError> {
    validate_canonical(role, &admitted.path)?;
    if admitted.blake3.len() != 64
        || !admitted
            .blake3
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(denied("file digest is not lowercase BLAKE3 hex"));
    }
    let named = fs::symlink_metadata(&admitted.path)
        .map_err(|_| denied(format!("{role} is unavailable")))?;
    if !named.file_type().is_file() || named.nlink() != 1 {
        return Err(denied(format!(
            "{role} is not an ordinary single-link file"
        )));
    }
    if named.len() == 0 || named.len() > max_bytes {
        return Err(denied(format!("{role} size is outside the admitted bound")));
    }
    let permissions = named.mode() & 0o7777;
    match owner {
        FileOwner::Root => {
            if named.uid() != 0 {
                return Err(denied(format!("{role} owner is not root")));
            }
            if permissions & 0o022 != 0 || (executable && permissions & 0o111 == 0) {
                return Err(denied(format!("{role} mode is mutable or not executable")));
            }
            validate_parent_custody(role, &admitted.path)?;
        }
        FileOwner::RootOrRunnerAuthored if named.uid() == 0 => {
            if permissions & 0o022 != 0 || (executable && permissions & 0o111 == 0) {
                return Err(denied(format!("{role} mode is mutable or not executable")));
            }
            validate_parent_custody(role, &admitted.path)?;
        }
        FileOwner::RootOrRunnerAuthored => {
            if executable {
                return Err(denied(format!(
                    "{role} cannot be runner-authored and executable"
                )));
            }
            if named.uid() != current_uid {
                return Err(denied(format!("{role} owner is not the runner uid")));
            }
            if permissions != 0o600 {
                return Err(denied(format!("{role} mode is not owner-private 0600")));
            }
            validate_owner_parent_custody(role, &admitted.path, current_uid)?;
        }
    }
    let file =
        File::open(&admitted.path).map_err(|err| EgressError::io(&format!("open {role}"), &err))?;
    make_inheritable(&file, role)?;
    let retained = file
        .metadata()
        .map_err(|err| EgressError::io(&format!("inspect {role}"), &err))?;
    let identity = Identity::from(&named);
    if Identity::from(&retained) != identity {
        return Err(denied(format!("{role} changed while opening")));
    }
    let actual_digest = digest(&file)?;
    if actual_digest != admitted.blake3 {
        return Err(denied(format!("{role} content digest is not admitted")));
    }
    Ok(OpenedFile {
        role,
        path: admitted.path.clone(),
        file,
        identity,
        digest: actual_digest,
    })
}

fn reject_private_directory_sources<'a>(
    files: impl Iterator<Item = &'a OpenedFile>,
    directories: &[&PathBuf],
) -> Result<(), EgressError> {
    for file in files {
        if directories
            .iter()
            .any(|directory| file.path.starts_with(directory))
        {
            return Err(denied("admitted source overlaps a private directory"));
        }
    }
    Ok(())
}

fn open_private_directory(
    role: &'static str,
    path: &Path,
    current_uid: u32,
) -> Result<OpenedDirectory, EgressError> {
    validate_canonical(role, path)?;
    if forbidden_directory(path) {
        return Err(denied(format!(
            "{role} is a forbidden broad host directory"
        )));
    }
    let named = fs::symlink_metadata(path).map_err(|_| denied(format!("{role} is unavailable")))?;
    if !named.file_type().is_dir() || named.uid() != current_uid || named.mode() & 0o7777 != 0o700 {
        return Err(denied(format!("{role} is not an owner-private directory")));
    }
    let file = File::open(path).map_err(|err| EgressError::io(&format!("open {role}"), &err))?;
    make_inheritable(&file, role)?;
    let retained = file
        .metadata()
        .map_err(|err| EgressError::io(&format!("inspect {role}"), &err))?;
    let identity = Identity::from(&named);
    if Identity::from(&retained) != identity {
        return Err(denied(format!("{role} changed while opening")));
    }
    Ok(OpenedDirectory {
        role,
        path: path.to_path_buf(),
        file,
        identity,
    })
}
