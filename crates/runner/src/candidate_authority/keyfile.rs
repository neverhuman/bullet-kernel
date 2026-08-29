use crate::error::RunnerError;
use bullet_harness_core::{decode_strict_json, CandidatePreparationVerificationKey, HarnessError};
use serde::Deserialize;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const MAX_RECORD_BYTES: u64 = 4096;
const ISSUER: &str = "kernel-local";
const KEY_ID: &str = "candidate-preparation-1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRecord {
    schema_version: String,
    issuer: String,
    key_id: String,
    public_key_hex: String,
}

pub(super) fn load(path: &Path) -> Result<CandidatePreparationVerificationKey, RunnerError> {
    if !path.is_absolute() {
        return Err(invalid("Candidate verification-key path must be absolute"));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| invalid(format!("canonicalize Candidate verification key: {error}")))?;
    if canonical != path {
        return Err(invalid(
            "Candidate verification-key path must already be canonical",
        ));
    }
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("Candidate verification-key metadata: {error}")))?;
    admit_metadata(&before)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| invalid(format!("open Candidate verification key: {error}")))?;
    let mut file = File::from(fd);
    let opened = file.metadata().map_err(|error| {
        invalid(format!(
            "opened Candidate verification-key metadata: {error}"
        ))
    })?;
    admit_metadata(&opened)?;
    require_same_identity(&before, &opened)?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("read Candidate verification key: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| invalid(format!("post-read Candidate key metadata: {error}")))?;
    require_same_identity(&opened, &after)?;
    if u64::try_from(bytes.len()).ok() != Some(opened.len()) {
        return Err(invalid(
            "Candidate verification-key bytes changed while reading",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("Candidate verification-key record is not UTF-8"))?;
    let value = decode_strict_json(text)
        .map_err(|error| invalid(format!("strict Candidate key JSON: {error}")))?;
    let record: PublicKeyRecord = serde_json::from_value(value)
        .map_err(|error| invalid(format!("Candidate key record shape: {error}")))?;
    if record.schema_version != "v1alpha1" || record.issuer != ISSUER || record.key_id != KEY_ID {
        return Err(invalid(
            "Candidate key record identity is not v1alpha1/kernel-local/candidate-preparation-1",
        ));
    }
    CandidatePreparationVerificationKey::from_hex(
        &record.issuer,
        &record.key_id,
        &record.public_key_hex,
    )
    .map_err(Into::into)
}

fn admit_metadata(metadata: &Metadata) -> Result<(), RunnerError> {
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RECORD_BYTES
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "Candidate key must be one bounded non-symlink regular file at exact mode 0600",
        ));
    }
    let owner = metadata.uid();
    let service = rustix::process::geteuid().as_raw();
    if owner != 0 && owner != service {
        return Err(invalid(
            "Candidate verification key must be root- or service-owned",
        ));
    }
    Ok(())
}

fn require_same_identity(left: &Metadata, right: &Metadata) -> Result<(), RunnerError> {
    if left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
    {
        Ok(())
    } else {
        Err(invalid(
            "Candidate verification-key identity changed while opening or reading",
        ))
    }
}

fn invalid(reason: impl Into<String>) -> RunnerError {
    HarnessError::CandidatePreparationInvalid {
        reason: reason.into(),
    }
    .into()
}
