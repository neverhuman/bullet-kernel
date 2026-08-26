use super::DurableJob;
use crate::error::EffectsError;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const MAX_RECORD_BYTES: u64 = 64 * 1024;

pub(super) enum WriteOutcome {
    Created,
    Existing(DurableJob),
}

pub(super) fn ensure_directory(path: &Path) -> Result<bool, EffectsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(invalid(format!(
                "unsafe queue directory {}",
                path.display()
            )));
        }
        Ok(metadata) => {
            verify_private_directory(path, &metadata)?;
            return Ok(false);
        }
        Err(err) if err.kind() != io::ErrorKind::NotFound => {
            return Err(io_error("inspect queue directory", err));
        }
        Err(_) => {}
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_error("create queue directory", err)),
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|err| io_error("verify queue directory", err))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid(format!(
            "unsafe queue directory {}",
            path.display()
        )));
    }
    verify_private_directory(path, &metadata)?;
    Ok(true)
}

pub(super) fn validate_job(job: &DurableJob) -> Result<(), EffectsError> {
    validate_id(&job.id)?;
    for (name, value, limit) in [
        ("provider", job.provider.as_str(), 128usize),
        ("logical_effect_key", job.logical_effect_key.as_str(), 256),
        ("target_ref", job.target_ref.as_str(), 512),
        ("new_oid", job.new_oid.as_str(), 128),
        ("expected_old_oid", job.expected_old_oid.as_str(), 128),
        ("state", job.state.as_str(), 64),
    ] {
        if value.is_empty()
            || value.len() > limit
            || value.chars().any(|ch| ch.is_control() || ch == '\0')
        {
            return Err(invalid(format!("invalid {name} for {}", job.id)));
        }
    }
    if !is_oid(&job.new_oid) || !is_oid(&job.expected_old_oid) {
        return Err(invalid(format!("invalid Git OID for {}", job.id)));
    }
    if !job.target_ref.starts_with("refs/bullet/candidates/")
        || job
            .target_ref
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(format!("invalid target_ref for {}", job.id)));
    }
    Ok(())
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_id(id: &str) -> Result<(), EffectsError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || id == "."
        || id == ".."
    {
        return Err(invalid(format!("unsafe durable job id {id:?}")));
    }
    Ok(())
}

pub(super) fn require_state(job: &DurableJob, expected: &str) -> Result<(), EffectsError> {
    if job.state == expected {
        Ok(())
    } else {
        Err(invalid(format!(
            "job {} state {} is not {expected}",
            job.id, job.state
        )))
    }
}

pub(super) fn write_new_record(
    path: &Path,
    job: &DurableJob,
) -> Result<WriteOutcome, EffectsError> {
    let mut bytes = serde_json::to_vec(job)
        .map_err(|err| invalid(format!("encode durable job {}: {err}", job.id)))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid(format!("durable job {} is too large", job.id)));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_secure_open(&mut options, true);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return read_record(path).map(WriteOutcome::Existing);
        }
        Err(err) => return Err(io_error("create durable job", err)),
    };
    if let Err(err) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(io_error("persist durable job", err));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("queue record has no phase directory"))?;
    sync_directory(parent)?;
    Ok(WriteOutcome::Created)
}

pub(super) fn read_record_if_present(path: &Path) -> Result<Option<DurableJob>, EffectsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(invalid(format!("unsafe queue record {}", path.display())))
        }
        Ok(_) => read_record(path).map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(io_error("inspect durable job", err)),
    }
}

fn read_record(path: &Path) -> Result<DurableJob, EffectsError> {
    let before = fs::symlink_metadata(path).map_err(|err| io_error("inspect durable job", err))?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_RECORD_BYTES {
        return Err(invalid(format!(
            "unsafe or oversized queue record {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options, false);
    let mut file = options
        .open(path)
        .map_err(|err| io_error("open durable job", err))?;
    verify_open_identity(
        &before,
        &file
            .metadata()
            .map_err(|err| io_error("stat durable job", err))?,
    )?;
    let mut bytes = Vec::with_capacity((before.len() as usize).min(MAX_RECORD_BYTES as usize));
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("read durable job", err))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid(format!(
            "oversized queue record {}",
            path.display()
        )));
    }
    let job: DurableJob = serde_json::from_slice(&bytes)
        .map_err(|err| invalid(format!("decode queue record {}: {err}", path.display())))?;
    validate_job(&job)?;
    let expected_name = format!("{}.json", job.id);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(invalid(format!(
            "queue filename does not bind job {}",
            job.id
        )));
    }
    Ok(job)
}

pub(super) fn remove_record(path: &Path) -> Result<(), EffectsError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error("remove transitioned durable job", err)),
    }
}

pub(super) fn sync_directory(path: &Path) -> Result<(), EffectsError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| io_error("sync queue directory", err))
}

#[cfg(unix)]
fn configure_secure_open(options: &mut OpenOptions, writable: bool) {
    use std::os::unix::fs::OpenOptionsExt;
    if writable {
        options.mode(0o600);
    }
}

#[cfg(not(unix))]
fn configure_secure_open(_options: &mut OpenOptions, _writable: bool) {}

#[cfg(unix)]
fn verify_open_identity(before: &fs::Metadata, opened: &fs::Metadata) -> Result<(), EffectsError> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() == opened.dev()
        && before.ino() == opened.ino()
        && opened.is_file()
        && opened.mode() & 0o077 == 0
    {
        Ok(())
    } else {
        Err(invalid("queue record changed while opening"))
    }
}

#[cfg(unix)]
fn verify_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), EffectsError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(invalid(format!(
            "queue directory {} must not grant group/other access",
            path.display()
        )))
    }
}

#[cfg(not(unix))]
fn verify_private_directory(_path: &Path, _metadata: &fs::Metadata) -> Result<(), EffectsError> {
    Ok(())
}

#[cfg(not(unix))]
fn verify_open_identity(_before: &fs::Metadata, opened: &fs::Metadata) -> Result<(), EffectsError> {
    if opened.is_file() {
        Ok(())
    } else {
        Err(invalid("queue record is not a regular file"))
    }
}

pub(super) fn invalid(detail: impl Into<String>) -> EffectsError {
    EffectsError::DurableQueueInvalid(detail.into())
}

pub(super) fn io_error(context: &str, err: io::Error) -> EffectsError {
    EffectsError::Io(format!("{context}: {err}"))
}
