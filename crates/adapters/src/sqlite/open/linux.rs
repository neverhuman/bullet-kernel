use super::store;
use bullet_application::LedgerError;
use rusqlite::{Connection, OpenFlags};
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_COMPONENTS: usize = 64;
const SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

struct Directory {
    descriptor: File,
    public_path: PathBuf,
    identity: Identity,
}

pub(super) struct Guard {
    boundary: Vec<Directory>,
    database: File,
    database_name: OsString,
    database_path: PathBuf,
    database_identity: Identity,
    effective_uid: u32,
    created: bool,
}

pub(super) fn connection(path: &Path) -> Result<(Connection, Guard), LedgerError> {
    let absolute = normalized_absolute(path)?;
    let effective_uid = effective_uid()?;
    let boundary = walk_boundary(&absolute, effective_uid)?;
    let database_name = absolute
        .file_name()
        .ok_or_else(|| store("SQLite database path must name a file"))?
        .to_os_string();
    let parent_dir = parent(&boundary);
    let existing = open_optional(&parent_dir.descriptor, &database_name).map_err(store)?;
    let guard = match existing {
        Some(database) => {
            admit_file(&database, &absolute, effective_uid, "database")?;
            inspect_sidecars(parent_dir, &database_name, effective_uid)?;
            let database_identity = identity(&database.metadata().map_err(store)?);
            Guard {
                boundary,
                database,
                database_name,
                database_path: absolute,
                database_identity,
                effective_uid,
                created: false,
            }
        }
        None => create_database(boundary, absolute, database_name, effective_uid)?,
    };
    if let Err(error) = revalidate(&guard) {
        return Err(failure_with_cleanup(None, guard, error));
    }
    let connection = match Connection::open_with_flags(
        &guard.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ) {
        Ok(connection) => connection,
        Err(error) => return Err(failure_with_cleanup(None, guard, store(error))),
    };
    if let Err(error) = revalidate(&guard) {
        return Err(failure_with_cleanup(Some(connection), guard, error));
    }
    Ok((connection, guard))
}

fn effective_uid() -> Result<u32, LedgerError> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(store)?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_ascii_whitespace().nth(1))
        .ok_or_else(|| store("Linux proc status omitted the effective UID"))?;
    value.parse().map_err(store)
}

fn create_database(
    boundary: Vec<Directory>,
    absolute: PathBuf,
    database_name: OsString,
    effective_uid: u32,
) -> Result<Guard, LedgerError> {
    let parent_dir = parent(&boundary);
    let before = inspect_sidecars(parent_dir, &database_name, effective_uid)?;
    if before.iter().any(|present| *present) {
        return Err(store(
            "SQLite orphan sidecar exists without a main database",
        ));
    }
    let database = match open_file(&parent_dir.descriptor, &database_name, true) {
        Ok(database) => database,
        Err(error) if error == rustix::io::Errno::EXIST => {
            let database = open_optional(&parent_dir.descriptor, &database_name)
                .map_err(store)?
                .ok_or_else(|| store("SQLite database creation raced with disappearance"))?;
            admit_file(&database, &absolute, effective_uid, "database")?;
            inspect_sidecars(parent_dir, &database_name, effective_uid)?;
            let database_identity = identity(&database.metadata().map_err(store)?);
            return Ok(Guard {
                boundary,
                database,
                database_name,
                database_path: absolute,
                database_identity,
                effective_uid,
                created: false,
            });
        }
        Err(error) => return Err(store(error)),
    };
    let identity = identity(&database.metadata().map_err(store)?);
    let guard = Guard {
        boundary,
        database,
        database_name,
        database_path: absolute,
        database_identity: identity,
        effective_uid,
        created: true,
    };
    if let Err(error) = admit_file(
        &guard.database,
        &guard.database_path,
        effective_uid,
        "database",
    ) {
        return Err(failure_with_cleanup(None, guard, error));
    }
    let sidecars =
        match inspect_sidecars(parent(&guard.boundary), &guard.database_name, effective_uid) {
            Ok(sidecars) => sidecars,
            Err(error) => return Err(failure_with_cleanup(None, guard, error)),
        };
    if sidecars.iter().any(|present| *present) {
        return Err(failure_with_cleanup(
            None,
            guard,
            store("SQLite sidecar appeared before the new database was opened"),
        ));
    }
    Ok(guard)
}

pub(super) fn postflight(guard: &Guard) -> Result<(), LedgerError> {
    revalidate(guard)
}

fn revalidate(guard: &Guard) -> Result<(), LedgerError> {
    revalidate_boundary(&guard.boundary, guard.effective_uid)?;
    let observed = admit_file(
        &guard.database,
        &guard.database_path,
        guard.effective_uid,
        "database",
    )?;
    if observed != guard.database_identity {
        return Err(store("SQLite database inode changed after admission"));
    }
    inspect_sidecars(
        parent(&guard.boundary),
        &guard.database_name,
        guard.effective_uid,
    )?;
    Ok(())
}

pub(super) fn cleanup(guard: Guard) -> Result<(), LedgerError> {
    revalidate_boundary(&guard.boundary, guard.effective_uid)?;
    if !guard.created {
        return Ok(());
    }
    let parent = parent(&guard.boundary);
    let sidecars = inspect_sidecars(parent, &guard.database_name, guard.effective_uid)?;
    if sidecars.iter().any(|present| *present) {
        return Err(store("SQLite cleanup refused while a sidecar exists"));
    }
    let observed = admit_file(
        &guard.database,
        &guard.database_path,
        guard.effective_uid,
        "database",
    )?;
    if observed != guard.database_identity {
        return Err(store("SQLite cleanup database inode changed"));
    }
    if guard.database.metadata().map_err(store)?.len() != 0 {
        return Err(store("SQLite cleanup database is nonempty"));
    }
    rustix::fs::unlinkat(&parent.descriptor, &guard.database_name, AtFlags::empty())
        .map_err(store)?;
    parent.descriptor.sync_all().map_err(store)
}

fn failure_with_cleanup(
    connection: Option<Connection>,
    guard: Guard,
    original: LedgerError,
) -> LedgerError {
    drop(connection);
    match cleanup(guard) {
        Ok(()) => original,
        Err(cleanup) => store(format!("{original}; SQLite cleanup refused: {cleanup}")),
    }
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, LedgerError> {
    validate_components(path)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(store)?.join(path)
    };
    validate_components(&absolute)?;
    Ok(absolute)
}

fn validate_components(path: &Path) -> Result<(), LedgerError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.ends_with(b"/") {
        return Err(store("SQLite path must be nonempty and name a file"));
    }
    let body = bytes.strip_prefix(b"/").unwrap_or(bytes);
    let mut count = 0;
    for component in body.split(|byte| *byte == b'/') {
        count += 1;
        if component.is_empty() || component == b"." || component == b".." || component.contains(&0)
        {
            return Err(store(
                "SQLite path contains an empty or non-normal component",
            ));
        }
    }
    if count > MAX_COMPONENTS {
        return Err(store(
            "SQLite path exceeds the 64-component admission limit",
        ));
    }
    Ok(())
}

fn walk_boundary(path: &Path, effective_uid: u32) -> Result<Vec<Directory>, LedgerError> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(store)?;
    let mut boundary = vec![directory(root, PathBuf::from("/"), false, effective_uid)?];
    let components: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect();
    for (index, component) in components[..components.len() - 1].iter().enumerate() {
        let prior = parent(&boundary);
        let descriptor = rustix::fs::openat2(
            &prior.descriptor,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE,
        )
        .map(File::from)
        .map_err(store)?;
        let public = prior.public_path.join(component);
        let immediate = index + 2 == components.len();
        boundary.push(directory(descriptor, public, immediate, effective_uid)?);
    }
    Ok(boundary)
}

fn directory(
    descriptor: File,
    public_path: PathBuf,
    immediate: bool,
    effective_uid: u32,
) -> Result<Directory, LedgerError> {
    admit_directory(&descriptor, immediate, effective_uid)?;
    let admitted_identity = identity(&descriptor.metadata().map_err(store)?);
    let entry = std::fs::symlink_metadata(&public_path).map_err(store)?;
    if entry.file_type().is_symlink() || identity(&entry) != admitted_identity {
        return Err(store("SQLite ancestor pathname changed during admission"));
    }
    Ok(Directory {
        descriptor,
        public_path,
        identity: admitted_identity,
    })
}

fn revalidate_boundary(boundary: &[Directory], effective_uid: u32) -> Result<(), LedgerError> {
    for (index, directory) in boundary.iter().enumerate() {
        admit_directory(
            &directory.descriptor,
            index + 1 == boundary.len(),
            effective_uid,
        )?;
        let entry = std::fs::symlink_metadata(&directory.public_path).map_err(store)?;
        if entry.file_type().is_symlink() || identity(&entry) != directory.identity {
            return Err(store(
                "SQLite ancestor pathname no longer identifies its descriptor",
            ));
        }
    }
    Ok(())
}

fn admit_directory(file: &File, immediate: bool, effective_uid: u32) -> Result<(), LedgerError> {
    let metadata = file.metadata().map_err(store)?;
    if !metadata.is_dir()
        || !directory_policy(metadata.uid(), metadata.mode(), immediate, effective_uid)
    {
        return Err(store(if immediate {
            "SQLite immediate state parent must be euid-owned exact 0700"
        } else {
            "SQLite ancestor must be root/euid-owned and non-group/other-writable"
        }));
    }
    Ok(())
}

fn directory_policy(uid: u32, mode: u32, immediate: bool, effective_uid: u32) -> bool {
    if immediate {
        return uid == effective_uid && mode & 0o7777 == 0o700;
    }
    let owner_admitted = uid == 0 || uid == effective_uid;
    let ordinary = mode & 0o022 == 0;
    // A root-owned sticky directory such as /tmp is the sole writable
    // ancestor exception. Sticky ownership plus admission of the next child
    // prevents a different UID from replacing that child pathname.
    let sticky_root = uid == 0 && mode & 0o1000 != 0;
    owner_admitted && (ordinary || sticky_root)
}

fn inspect_sidecars(
    parent: &Directory,
    database_name: &OsStr,
    effective_uid: u32,
) -> Result<[bool; 3], LedgerError> {
    let mut present = [false; 3];
    for (index, suffix) in SIDECARS.iter().enumerate() {
        let name = sidecar_name(database_name, suffix);
        if let Some(file) = open_optional(&parent.descriptor, &name).map_err(store)? {
            admit_file(
                &file,
                &parent.public_path.join(name),
                effective_uid,
                "sidecar",
            )?;
            present[index] = true;
        }
    }
    Ok(present)
}

fn open_optional(parent: &File, name: &OsStr) -> rustix::io::Result<Option<File>> {
    match open_file(parent, name, false) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(error),
    }
}

fn open_file(parent: &File, name: &OsStr, create_new: bool) -> rustix::io::Result<File> {
    let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let mut mode = Mode::empty();
    if create_new {
        flags |= OFlags::CREATE | OFlags::EXCL;
        mode = Mode::from_bits_retain(0o600);
    }
    rustix::fs::openat2(parent, Path::new(name), flags, mode, RESOLVE).map(File::from)
}

fn admit_file(
    file: &File,
    path: &Path,
    effective_uid: u32,
    kind: &str,
) -> Result<Identity, LedgerError> {
    let descriptor = file.metadata().map_err(store)?;
    if !descriptor.is_file()
        || descriptor.uid() != effective_uid
        || descriptor.nlink() != 1
        || descriptor.mode() & 0o7777 != 0o600
    {
        return Err(store(format!(
            "SQLite {kind} must be euid-owned exact 0600 single-link regular file"
        )));
    }
    let entry = std::fs::symlink_metadata(path).map_err(store)?;
    let admitted_identity = identity(&descriptor);
    if entry.file_type().is_symlink() || identity(&entry) != admitted_identity {
        return Err(store(format!(
            "SQLite {kind} pathname does not identify its admitted descriptor"
        )));
    }
    Ok(admitted_identity)
}

fn parent(boundary: &[Directory]) -> &Directory {
    boundary.last().expect("root boundary is always retained")
}

fn sidecar_name(database: &OsStr, suffix: &str) -> OsString {
    let mut name = database.to_os_string();
    name.push(suffix);
    name
}

fn identity(metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(test)]
pub(super) fn was_created(guard: &Guard) -> bool {
    guard.created
}

#[cfg(test)]
pub(super) fn assert_policy_contract() {
    let euid = 1000;
    assert!(directory_policy(0, 0o755, false, euid));
    assert!(directory_policy(euid, 0o700, true, euid));
    assert!(directory_policy(0, 0o1777, false, euid));
    assert!(!directory_policy(euid, 0o770, false, euid));
    assert!(!directory_policy(2000, 0o700, false, euid));
    assert!(!directory_policy(0, 0o700, true, euid));
}
