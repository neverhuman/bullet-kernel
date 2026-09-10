//! Linux private credential custody, serialized across CLI clients with a dirfd.

use crate::coding::http;
use rustix::fd::OwnedFd;
use rustix::fs::{
    flock, fstat, fsync, open, openat, renameat, unlinkat, AtFlags, FileType, FlockOperation, Mode,
    OFlags,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    pub(crate) schema_version: u32,
    pub(crate) farmd: String,
    pub(crate) origin: String,
    pub(crate) cookie: String,
    pub(crate) csrf: String,
}

impl Credentials {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("AUTH_STORE_SCHEMA_UNSUPPORTED".into());
        }
        http::parse_loopback(&self.farmd)?;
        http::parse_loopback(&self.origin)?;
        http::validate_secret(
            self.cookie
                .strip_prefix("bullet_session=")
                .ok_or("AUTH_COOKIE_INVALID")?,
            "ses",
        )?;
        http::validate_secret(&self.csrf, "csrf")
    }
}

pub(crate) struct CredentialStore {
    directory: OwnedFd,
    _lock: OwnedFd,
    path: PathBuf,
}

impl CredentialStore {
    pub(crate) fn load_command(
        &self,
        id: &bullet_domain::CommandId,
    ) -> Result<Option<serde_json::Value>, String> {
        self.require_current_path()?;
        let name = format!("{}.json", id.as_str());
        let fd = match openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("COMMAND_JOURNAL_UNSAFE".into()),
        };
        private_metadata(&fd, false)?;
        let file = File::from(fd);
        let mut bytes = Vec::new();
        (&file)
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| "COMMAND_JOURNAL_READ_FAILED")?;
        if bytes.len() > 1_048_576 {
            return Err("COMMAND_JOURNAL_TOO_LARGE".into());
        }
        let record = serde_json::from_slice(&bytes)
            .map_err(|_| "COMMAND_JOURNAL_CORRUPT: preserve the original request record")?;
        // A previous writer may have died after writing but before either sync.
        file.sync_all()
            .map_err(|_| "COMMAND_JOURNAL_SYNC_UNKNOWN")?;
        fsync(&self.directory).map_err(|_| "COMMAND_JOURNAL_SYNC_UNKNOWN")?;
        self.require_current_path()?;
        Ok(Some(record))
    }

    pub(crate) fn record_command(
        &self,
        id: &bullet_domain::CommandId,
        record: &serde_json::Value,
    ) -> Result<(), String> {
        self.require_current_path()?;
        let bytes = serde_json::to_vec(record).map_err(|_| "COMMAND_JOURNAL_ENCODING_FAILED")?;
        if bytes.len() > 1_048_576 {
            return Err("COMMAND_JOURNAL_TOO_LARGE".into());
        }
        let name = format!("{}.json", id.as_str());
        let fd = openat(
            &self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "COMMAND_JOURNAL_EXISTS_OR_UNSAFE")?;
        private_metadata(&fd, false)?;
        let mut file = File::from(fd);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "COMMAND_JOURNAL_WRITE_FAILED: preserve the original record")?;
        fsync(&self.directory).map_err(|_| "COMMAND_JOURNAL_SYNC_UNKNOWN")?;
        self.require_current_path()
    }

    pub(crate) fn require_no_pending(&self) -> Result<(), String> {
        match rustix::fs::statat(
            &self.directory,
            "session.pending",
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err(
                "AUTH_STORE_PENDING: preserve existing pending credentials before recovery".into(),
            ),
        }
    }

    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let directory = private_directory(path)?;
        private_metadata(&directory, true)?;
        let lock = openat(
            &directory,
            ".auth.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "AUTH_LOCK_UNSAFE")?;
        private_metadata(&lock, false)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "AUTH_BUSY: another client owns the credential store")?;
        Ok(Self {
            directory,
            _lock: lock,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn load(&self) -> Result<Option<Credentials>, String> {
        let descriptor = match openat(
            &self.directory,
            "session.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("AUTH_STORE_UNSAFE".into()),
        };
        private_metadata(&descriptor, false)?;
        let mut bytes = Vec::new();
        File::from(descriptor)
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| "AUTH_STORE_READ_FAILED")?;
        if bytes.len() > 8192 {
            return Err("AUTH_STORE_TOO_LARGE".into());
        }
        let credentials: Credentials =
            serde_json::from_slice(&bytes).map_err(|_| "AUTH_STORE_INVALID")?;
        credentials.validate()?;
        Ok(Some(credentials))
    }

    pub(crate) fn save(&self, credentials: &Credentials) -> Result<(), String> {
        self.require_current_path()?;
        credentials.validate()?;
        if self.load()?.is_some() {
            return Err("AUTH_ALREADY_STORED".into());
        }
        let bytes = serde_json::to_vec(credentials).map_err(|_| "AUTH_STORE_ENCODING_FAILED")?;
        let descriptor = openat(
            &self.directory,
            "session.pending",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "AUTH_STORE_PENDING: preserve existing pending credentials before recovery")?;
        private_metadata(&descriptor, false)?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "AUTH_STORE_WRITE_FAILED: preserve session.pending")?;
        renameat(
            &self.directory,
            "session.pending",
            &self.directory,
            "session.json",
        )
        .map_err(|_| "AUTH_STORE_RENAME_FAILED: preserve session.pending")?;
        fsync(&self.directory)
            .map_err(|_| "AUTH_STORE_SYNC_UNKNOWN: check auth status before retrying")?;
        self.require_current_path()?;
        Ok(())
    }

    fn require_current_path(&self) -> Result<(), String> {
        let current = open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "AUTH_STORE_PATH_CHANGED: preserve the original state directory")?;
        let a = fstat(&current).map_err(|_| "AUTH_STORE_STAT_FAILED")?;
        let b = fstat(&self.directory).map_err(|_| "AUTH_STORE_STAT_FAILED")?;
        if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
            return Err("AUTH_STORE_PATH_CHANGED: preserve the original state directory".into());
        }
        Ok(())
    }

    pub(crate) fn forget(&self) -> Result<(), String> {
        match unlinkat(&self.directory, "session.json", AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err("AUTH_STORE_REMOVE_FAILED".into()),
        }
        fsync(&self.directory).map_err(|_| "AUTH_STORE_SYNC_UNKNOWN")?;
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<OwnedFd, String> {
    if !path.is_absolute() {
        return Err("AUTH_STATE_DIRECTORY_MUST_BE_ABSOLUTE".into());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = open("/", flags, Mode::empty()).map_err(|_| "AUTH_DIRECTORY_UNSAFE")?;
    for part in path.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err("AUTH_DIRECTORY_UNSAFE".into());
        };
        let stat = fstat(&parent).map_err(|_| "AUTH_STORE_STAT_FAILED")?;
        // A root-owned sticky directory such as /tmp protects owned children.
        let sticky_root = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
        if (stat.st_uid != 0 && stat.st_uid != rustix::process::geteuid().as_raw())
            || (stat.st_mode & 0o022 != 0 && !sticky_root)
        {
            return Err("AUTH_DIRECTORY_ANCESTOR_UNSAFE".into());
        }
        match rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err("AUTH_DIRECTORY_CREATE_FAILED".into()),
        };
        let child =
            openat(&parent, name, flags, Mode::empty()).map_err(|_| "AUTH_DIRECTORY_UNSAFE")?;
        // Also sync entries concurrently created by another client before its lock.
        fsync(&child)
            .and_then(|()| fsync(&parent))
            .map_err(|_| "AUTH_DIRECTORY_SYNC_FAILED")?;
        parent = child;
    }
    Ok(parent)
}

fn private_metadata(fd: &OwnedFd, directory: bool) -> Result<(), String> {
    let stat = fstat(fd).map_err(|_| "AUTH_STORE_STAT_FAILED")?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    let expected = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let mode = if directory { 0o700 } else { 0o600 };
    if kind != expected
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != mode
        || (!directory && stat.st_nlink != 1)
    {
        return Err("AUTH_STORE_UNSAFE: require an owned private directory and single-link 0600 regular files".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn private_temp() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn credentials() -> Credentials {
        Credentials {
            schema_version: 1,
            farmd: "http://127.0.0.1:7420".into(),
            origin: "http://127.0.0.1:7420".into(),
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        }
    }

    #[test]
    fn credentials_survive_client_restart_privately_and_exclude_concurrent_writers() {
        let temp = private_temp();
        let dir = temp.path().join("operator");
        let store = CredentialStore::open(&dir).unwrap();
        assert!(CredentialStore::open(&dir).is_err());
        store.save(&credentials()).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("session.json")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(store.save(&credentials()).is_err());
        drop(store);
        let reopened = CredentialStore::open(&dir).unwrap();
        assert_eq!(
            reopened.load().unwrap().unwrap().cookie,
            credentials().cookie
        );
        reopened.forget().unwrap();
        assert!(reopened.load().unwrap().is_none());
    }

    #[test]
    fn public_files_symlinks_hardlinks_and_corrupt_credentials_are_refused() {
        let temp = private_temp();
        let dir = temp.path().join("operator");
        let store = CredentialStore::open(&dir).unwrap();
        let path = dir.join("session.json");
        store.save(&credentials()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, dir.join("copy")).unwrap();
        assert!(store.load().is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(dir.join("copy"), &path).unwrap();
        assert!(store.load().is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"secret malformed input").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store
            .load()
            .err()
            .unwrap()
            .starts_with("AUTH_STORE_INVALID"));
        drop(store);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(CredentialStore::open(&dir).is_err());
    }

    #[test]
    fn symlink_ancestors_and_displaced_state_directory_are_refused() {
        let temp = private_temp();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, temp.path().join("alias")).unwrap();
        assert!(CredentialStore::open(&temp.path().join("alias/operator")).is_err());
        let dir = temp.path().join("operator");
        let store = CredentialStore::open(&dir).unwrap();
        std::fs::rename(&dir, temp.path().join("displaced")).unwrap();
        assert!(store
            .save(&credentials())
            .unwrap_err()
            .starts_with("AUTH_STORE_PATH_CHANGED"));
        assert!(!temp.path().join("displaced/session.json").exists());
    }

    #[test]
    fn command_journal_survives_reopen_and_never_overwrites_original_request() {
        let temp = private_temp();
        let dir = temp.path().join("operator");
        let store = CredentialStore::open(&dir).unwrap();
        let id = bullet_domain::CommandId::from_seed("same request");
        let record = serde_json::json!({"payload":"original"});
        store.record_command(&id, &record).unwrap();
        assert!(store
            .record_command(&id, &serde_json::json!({"payload":"changed"}))
            .is_err());
        drop(store);
        let store = CredentialStore::open(&dir).unwrap();
        assert_eq!(store.load_command(&id).unwrap(), Some(record));
        std::fs::write(dir.join(format!("{}.json", id.as_str())), b"partial").unwrap();
        assert!(store
            .load_command(&id)
            .unwrap_err()
            .starts_with("COMMAND_JOURNAL_CORRUPT"));
    }
}
