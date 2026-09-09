use super::{
    admission, corrupt, lock_name, operation, response_lost, AuthorityHighWaterError,
    AuthorityHighWaterV1, FaultPoint, MAX_RECORD_BYTES,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use tempfile::Builder;

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(super) struct LockedParent {
    parent: File,
    public_parent: PathBuf,
    parent_identity: FileIdentity,
    descriptor_parent: PathBuf,
    record_path: PathBuf,
    effective_uid: u32,
    _lock: File,
}

impl LockedParent {
    pub(super) fn open(record: &Path) -> Result<Self, AuthorityHighWaterError> {
        let public_parent = record.parent().expect("validated parent").to_path_buf();
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|error| operation("OPEN_ROOT", error))?;
        let relative_parent = public_parent
            .strip_prefix(Path::new("/"))
            .expect("validated absolute parent");
        let relative_parent = if relative_parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative_parent
        };
        let parent = rustix::fs::openat2(
            &root,
            relative_parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(|error| operation("OPEN_PARENT", error))?;
        let effective_uid = std::fs::metadata("/proc/self")
            .map_err(|error| operation("EFFECTIVE_UID", error))?
            .uid();
        admit_parent(&parent, effective_uid)?;
        let parent_identity = identity(
            &parent
                .metadata()
                .map_err(|error| operation("STAT", error))?,
        );
        let descriptor_parent = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
        let lock_path = descriptor_parent.join(lock_name(record));
        let lock = open_lock(&lock_path, effective_uid, &parent)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|error| operation("LOCK", error))?;
        admit_file_path(&lock, &lock_path, effective_uid, "lock")?;
        let record_path = descriptor_parent.join(record.file_name().expect("validated file name"));
        let locked = Self {
            parent,
            public_parent,
            parent_identity,
            descriptor_parent,
            record_path,
            effective_uid,
            _lock: lock,
        };
        locked.revalidate_parent()?;
        Ok(locked)
    }

    fn revalidate_parent(&self) -> Result<(), AuthorityHighWaterError> {
        let metadata = std::fs::symlink_metadata(&self.public_parent)
            .map_err(|error| operation("REVALIDATE_PARENT", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.parent_identity.device
            || metadata.ino() != self.parent_identity.inode
        {
            return Err(admission("authority high-water parent identity changed"));
        }
        admit_parent(&self.parent, self.effective_uid)
    }
}

pub(super) fn load(path: &Path) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
    let locked = LockedParent::open(path)?;
    locked.revalidate_parent()?;
    read_record(&locked.record_path, locked.effective_uid)
}

pub(super) fn advance(
    path: &Path,
    requested: AuthorityHighWaterV1,
    fault: FaultPoint,
) -> Result<AuthorityHighWaterV1, AuthorityHighWaterError> {
    let locked = LockedParent::open(path)?;
    locked.revalidate_parent()?;
    if let Some(current) = read_record(&locked.record_path, locked.effective_uid)? {
        if requested.values().regresses_from(current.values()) {
            return Err(AuthorityHighWaterError::Rollback {
                current: current.values(),
                requested: requested.values(),
            });
        }
        if requested == current {
            return Ok(current);
        }
    }
    publish_record(&locked, &requested, fault)?;
    Ok(requested)
}

fn open_lock(path: &Path, uid: u32, parent: &File) -> Result<File, AuthorityHighWaterError> {
    let options = || {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        options
    };
    let (lock, created) = match options().create_new(true).open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            options()
                .open(path)
                .map_err(|error| operation("OPEN_LOCK", error))?,
            false,
        ),
        Err(error) => return Err(operation("OPEN_LOCK", error)),
    };
    admit_file(&lock, uid, "lock")?;
    if created {
        lock.sync_all()
            .and_then(|()| parent.sync_all())
            .map_err(|error| operation("SYNC_LOCK", error))?;
    }
    Ok(lock)
}

fn read_record(
    path: &Path,
    uid: u32,
) -> Result<Option<AuthorityHighWaterV1>, AuthorityHighWaterError> {
    let mut input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(operation("OPEN_RECORD", error)),
    };
    admit_file_path(&input, path, uid, "record")?;
    let length = input
        .metadata()
        .map_err(|error| operation("STAT_RECORD", error))?
        .len();
    if length == 0 || length > MAX_RECORD_BYTES {
        return Err(corrupt(
            "authority high-water record length is outside 1..=4096",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    (&mut input)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| operation("READ_RECORD", error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
        return Err(corrupt("authority high-water record exceeds 4096 bytes"));
    }
    admit_file_path(&input, path, uid, "record")?;
    let record: AuthorityHighWaterV1 =
        serde_json::from_slice(&bytes).map_err(|error| corrupt(error.to_string()))?;
    record.validate()?;
    Ok(Some(record))
}

fn publish_record(
    locked: &LockedParent,
    record: &AuthorityHighWaterV1,
    _fault: FaultPoint,
) -> Result<(), AuthorityHighWaterError> {
    let mut bytes = serde_json::to_vec(record).map_err(|error| corrupt(error.to_string()))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
        return Err(corrupt(
            "encoded authority high-water record exceeds 4096 bytes",
        ));
    }
    let mut staged = Builder::new()
        .prefix(".bullet-authority-high-water-")
        .tempfile_in(&locked.descriptor_parent)
        .map_err(|error| operation("CREATE_TEMP", error))?;
    staged
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| operation("CHMOD_TEMP", error))?;
    admit_file(staged.as_file(), locked.effective_uid, "staged record")?;
    staged
        .write_all(&bytes)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| operation("SYNC_TEMP", error))?;
    #[cfg(test)]
    if _fault == FaultPoint::BeforePublish {
        return Err(operation(
            "TEST_BEFORE_PUBLISH",
            "injected prepublication failure",
        ));
    }
    locked.revalidate_parent()?;
    let published = staged
        .persist(&locked.record_path)
        .map_err(|error| operation("PUBLISH", error.error))?;
    published
        .sync_all()
        .map_err(|error| response_lost(error.to_string()))?;
    locked
        .revalidate_parent()
        .map_err(|error| response_lost(error.to_string()))?;
    locked
        .parent
        .sync_all()
        .map_err(|error| response_lost(error.to_string()))?;
    let observed = read_record(&locked.record_path, locked.effective_uid)
        .map_err(|error| response_lost(error.to_string()))?;
    if observed.as_ref() != Some(record) {
        return Err(response_lost("published record read-back mismatch"));
    }
    #[cfg(test)]
    if _fault == FaultPoint::AfterReadback {
        return Err(response_lost(
            "injected response loss after durable read-back",
        ));
    }
    Ok(())
}

fn admit_parent(parent: &File, uid: u32) -> Result<(), AuthorityHighWaterError> {
    let metadata = parent
        .metadata()
        .map_err(|error| operation("STAT_PARENT", error))?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(admission(
            "authority high-water parent must be an owner-only 0700 directory",
        ));
    }
    Ok(())
}

fn admit_file(file: &File, uid: u32, kind: &str) -> Result<(), AuthorityHighWaterError> {
    let metadata = file
        .metadata()
        .map_err(|error| operation("STAT_FILE", error))?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(admission(format!(
            "authority high-water {kind} must be an owner-only 0600 single-link regular file"
        )));
    }
    Ok(())
}

fn admit_file_path(
    file: &File,
    path: &Path,
    uid: u32,
    kind: &str,
) -> Result<(), AuthorityHighWaterError> {
    admit_file(file, uid, kind)?;
    let descriptor = file
        .metadata()
        .map_err(|error| operation("STAT_FILE", error))?;
    let entry = std::fs::symlink_metadata(path).map_err(|error| operation("STAT_ENTRY", error))?;
    if entry.file_type().is_symlink()
        || entry.dev() != descriptor.dev()
        || entry.ino() != descriptor.ino()
    {
        return Err(admission(format!(
            "authority high-water {kind} pathname does not identify its admitted descriptor"
        )));
    }
    Ok(())
}

fn identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
