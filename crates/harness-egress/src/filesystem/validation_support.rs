use super::super::{
    FilesystemSandboxProfileV0, CA_DESTINATION, CLONE_DESTINATION, CREDENTIAL_DESTINATION,
    PROVIDER_DESTINATION, SCHEMA_DESTINATION, SCRATCH_DESTINATION,
};
use crate::error::{EgressCode, EgressError};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub(super) fn validate_canonical(role: &str, path: &Path) -> Result<(), EgressError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(denied(format!("{role} path is not exact absolute")));
    }
    let canonical = fs::canonicalize(path).map_err(|_| denied(format!("{role} is unavailable")))?;
    if canonical != path {
        return Err(denied(format!("{role} path contains a symlink or alias")));
    }
    Ok(())
}

pub(super) fn validate_parent_custody(role: &str, path: &Path) -> Result<(), EgressError> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| denied(format!("{role} parent is unavailable")))?;
        let mode = metadata.mode() & 0o777;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || mode & 0o022 != 0 {
            return Err(denied(format!("{role} parent custody is mutable")));
        }
    }
    Ok(())
}

/// Ancestor rule for a runner-authored file: every ancestor is a directory,
/// owned by root or by the runner uid, and never group/other-writable — the
/// chain discipline sshd applies to key files. One exemption: a root-owned
/// world-writable directory carrying the sticky bit (the `/tmp` pattern),
/// where only root or an entry's owner may replace it and the admitted file
/// sits inside an owner-private directory whose digest is re-verified at open
/// and revalidated on use.
pub(super) fn validate_owner_parent_custody(
    role: &str,
    path: &Path,
    current_uid: u32,
) -> Result<(), EgressError> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| denied(format!("{role} parent is unavailable")))?;
        let mode = metadata.mode() & 0o7777;
        let sticky_tmp = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || (metadata.uid() != 0 && metadata.uid() != current_uid)
            || (mode & 0o022 != 0 && !sticky_tmp)
        {
            return Err(denied(format!("{role} parent custody is mutable")));
        }
    }
    Ok(())
}

pub(super) fn validate_destinations(
    profile: &FilesystemSandboxProfileV0,
) -> Result<(), EgressError> {
    let mut destinations = vec![
        PathBuf::from(PROVIDER_DESTINATION),
        PathBuf::from(SCHEMA_DESTINATION),
        PathBuf::from(CA_DESTINATION),
        PathBuf::from(CLONE_DESTINATION),
        PathBuf::from(SCRATCH_DESTINATION),
    ];
    if profile.credential.is_some() {
        destinations.push(PathBuf::from(CREDENTIAL_DESTINATION));
    }
    for runtime in &profile.runtime_files {
        let destination = &runtime.destination;
        let admitted_prefix = ["/runtime/bin", "/lib", "/lib64", "/usr/lib"]
            .iter()
            .any(|prefix| destination.starts_with(prefix) && destination != Path::new(prefix));
        if !destination.is_absolute()
            || !admitted_prefix
            || destination
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(denied(
                "runtime destination is outside the closed allowlist",
            ));
        }
        destinations.push(destination.clone());
    }
    for (index, destination) in destinations.iter().enumerate() {
        if destinations
            .iter()
            .skip(index + 1)
            .any(|other| overlaps(destination, other))
        {
            return Err(denied("mount destinations duplicate or overlap"));
        }
    }
    Ok(())
}

pub(super) fn forbidden_directory(path: &Path) -> bool {
    const FORBIDDEN: &[&str] = &[
        "/",
        "/etc",
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/proc",
        "/sys",
        "/dev",
        "/var",
        "/home/ubuntu/bullet",
    ];
    FORBIDDEN
        .iter()
        .any(|candidate| path == Path::new(candidate))
        || (path.starts_with("/home") && path.components().count() == 3)
}

pub(super) fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(super) fn digest(file: &File) -> Result<String, EgressError> {
    let mut reader = file
        .try_clone()
        .map_err(|err| EgressError::io("clone admitted file", &err))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|err| EgressError::io("seek admitted file", &err))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| EgressError::io("hash admitted file", &err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn make_inheritable(file: &File, role: &str) -> Result<(), EgressError> {
    rustix::io::fcntl_setfd(file, rustix::io::FdFlags::empty())
        .map_err(|err| EgressError::new(EgressCode::IoFailed, format!("retain {role}: {err}")))
}

pub(super) fn denied(detail: impl Into<String>) -> EgressError {
    EgressError::new(EgressCode::FilesystemDenied, detail)
}

pub(super) fn changed(role: &str, detail: &str) -> EgressError {
    EgressError::new(EgressCode::FilesystemChanged, format!("{role}: {detail}"))
}
