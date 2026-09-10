//! Private local bootstrap custody. No secret-bearing diagnostics or implicit rotation.
use rustix::fd::OwnedFd;
use rustix::fs::{fstat, fsync, open, openat, FileType, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path};

fn parent(path: &Path) -> Result<(OwnedFd, &std::ffi::OsStr), String> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("BOOTSTRAP_PATH_INVALID: require an absolute ordinary path".into());
    }
    let name = path.file_name().ok_or("BOOTSTRAP_PATH_INVALID")?;
    let directory = path.parent().ok_or("BOOTSTRAP_PATH_INVALID")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = open("/", flags, Mode::empty()).map_err(|_| "BOOTSTRAP_DIRECTORY_UNSAFE")?;
    for part in directory.components().skip(1) {
        let Component::Normal(part) = part else {
            return Err("BOOTSTRAP_DIRECTORY_UNSAFE".into());
        };
        let stat = fstat(&fd).map_err(|_| "BOOTSTRAP_STAT_FAILED")?;
        let sticky_root = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
        if (stat.st_uid != 0 && stat.st_uid != rustix::process::geteuid().as_raw())
            || (stat.st_mode & 0o022 != 0 && !sticky_root)
        {
            return Err("BOOTSTRAP_ANCESTOR_UNSAFE".into());
        }
        fd = openat(&fd, part, flags, Mode::empty()).map_err(|_| "BOOTSTRAP_DIRECTORY_UNSAFE")?;
    }
    private(&fd, true)?;
    Ok((fd, name))
}

fn private(fd: &OwnedFd, directory: bool) -> Result<(), String> {
    let stat = fstat(fd).map_err(|_| "BOOTSTRAP_STAT_FAILED")?;
    let kind = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let mode = if directory { 0o700 } else { 0o600 };
    if FileType::from_raw_mode(stat.st_mode) != kind
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != mode
        || (!directory && stat.st_nlink != 1)
    {
        return Err(
            "BOOTSTRAP_CUSTODY_UNSAFE: require owned 0700 parent and single-link 0600 regular file"
                .into(),
        );
    }
    Ok(())
}

fn same_parent(path: &Path, opened: &OwnedFd) -> Result<(), String> {
    let (current, _) = parent(path)?;
    let before = fstat(opened).map_err(|_| "BOOTSTRAP_STAT_FAILED")?;
    let after = fstat(&current).map_err(|_| "BOOTSTRAP_STAT_FAILED")?;
    if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
        return Err("BOOTSTRAP_DIRECTORY_CHANGED".into());
    }
    Ok(())
}

pub(super) fn read(path: &Path) -> Result<String, String> {
    let (parent, name) = parent(path)?;
    let fd = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "BOOTSTRAP_FILE_UNAVAILABLE")?;
    private(&fd, false)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take(71)
        .read_to_end(&mut bytes)
        .map_err(|_| "BOOTSTRAP_READ_FAILED")?;
    if bytes.len() > 70 {
        return Err("BOOTSTRAP_TOKEN_INVALID".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "BOOTSTRAP_TOKEN_INVALID")?;
    let token = text.strip_suffix('\n').unwrap_or(text);
    let hex = token
        .strip_prefix("boot_")
        .ok_or("BOOTSTRAP_TOKEN_INVALID")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("BOOTSTRAP_TOKEN_INVALID".into());
    }
    same_parent(path, &parent)?;
    Ok(token.to_owned())
}

pub(super) fn provision(path: &Path) -> Result<(), String> {
    let (parent, name) = parent(path)?;
    let fd = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| "BOOTSTRAP_CREATE_REFUSED: destination must be absent")?;
    private(&fd, false)?;
    let token =
        bullet_farmd::auth::random_token("boot").map_err(|_| "BOOTSTRAP_ENTROPY_UNAVAILABLE")?;
    let mut file = File::from(fd);
    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "BOOTSTRAP_WRITE_FAILED: preserve the file and reconcile")?;
    fsync(&parent).map_err(|_| "BOOTSTRAP_SYNC_FAILED: preserve the file and reconcile")?;
    same_parent(path, &parent)
}

#[cfg(test)]
#[path = "bootstrap/tests.rs"]
mod tests;
