//! Bounded read-back of BulletGit's public preservation artifact digests.

use super::{artifacts, invalid, require_private_dir, PreservationSubject};
use crate::error::WorkerError;
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const STATE_DOMAIN: &[u8] = b"bullet-git-preservation-state-v1";
const ARTIFACT_DOMAIN: &[u8] = b"bullet-git-preservation-artifact-v1";
const MAX_ARTIFACT_ENTRIES: usize = 65_536;
const MAX_ARTIFACT_HASH_INPUT: usize = 128 * 1024 * 1024;
const ARTIFACT_ENTRIES: [&str; 5] = [
    "cas",
    "generation",
    "repository.bundle",
    "subject.json",
    "workspace.json",
];

pub(super) fn require_artifact_shape(destination: &Path) -> Result<(), WorkerError> {
    require_private_dir(destination)?;
    let entries = std::fs::read_dir(destination)
        .map_err(invalid)?
        .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(invalid)?;
    let expected = ARTIFACT_ENTRIES.into_iter().map(str::to_owned).collect();
    if entries != expected {
        return Err(invalid("preservation artifact entry set differs"));
    }
    Ok(())
}

pub(super) fn preservation_state_digest(
    subject: &PreservationSubject,
) -> Result<String, WorkerError> {
    state_digest(subject)
}

pub(super) fn artifact_digest(root: &Path) -> Result<String, WorkerError> {
    let mut input = Vec::new();
    hash_field(&mut input, ARTIFACT_DOMAIN)?;
    let mut entries = 0_usize;
    hash_entries(root, root, &mut input, &mut entries)?;
    Ok(Digest::of(&input).to_hex())
}

fn hash_entries(
    root: &Path,
    directory: &Path,
    input: &mut Vec<u8>,
    count: &mut usize,
) -> Result<(), WorkerError> {
    let before = std::fs::symlink_metadata(directory).map_err(invalid)?;
    if !before.file_type().is_dir() {
        return Err(invalid("preservation artifact traversal left a directory"));
    }
    let mut entries = std::fs::read_dir(directory)
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        *count = count.saturating_add(1);
        if *count > MAX_ARTIFACT_ENTRIES {
            return Err(invalid("preservation artifact exceeded its entry bound"));
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(invalid)?
            .to_str()
            .ok_or_else(|| invalid("preservation artifact path is not UTF-8"))?;
        let metadata = std::fs::symlink_metadata(&path).map_err(invalid)?;
        hash_field(input, relative.as_bytes())?;
        if metadata.file_type().is_dir() {
            hash_field(input, b"directory")?;
            hash_field(input, &(metadata.mode() & 0o7777).to_le_bytes())?;
            hash_entries(root, &path, input, count)?;
        } else if metadata.file_type().is_file() {
            hash_file(input, &path, &metadata)?;
        } else if metadata.file_type().is_symlink() {
            hash_field(input, b"symlink")?;
            let target = std::fs::read_link(&path).map_err(invalid)?;
            hash_field(
                input,
                target
                    .to_str()
                    .ok_or_else(|| invalid("preservation symlink target is not UTF-8"))?
                    .as_bytes(),
            )?;
            if artifacts::identity(&metadata)
                != artifacts::identity(&std::fs::symlink_metadata(&path).map_err(invalid)?)
            {
                return Err(invalid("preservation symlink changed while hashing"));
            }
        } else {
            return Err(invalid("preservation artifact contains a special entry"));
        }
    }
    if artifacts::identity(&before)
        != artifacts::identity(&std::fs::symlink_metadata(directory).map_err(invalid)?)
    {
        return Err(invalid(
            "preservation artifact directory changed while hashing",
        ));
    }
    Ok(())
}

fn hash_file(
    input: &mut Vec<u8>,
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), WorkerError> {
    hash_field(input, b"file")?;
    hash_field(input, &(metadata.mode() & 0o7777).to_le_bytes())?;
    hash_field(input, &metadata.len().to_le_bytes())?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(invalid)?;
    let mut file = File::from(descriptor);
    if artifacts::identity(metadata) != artifacts::identity(&file.metadata().map_err(invalid)?) {
        return Err(invalid("preservation artifact changed before hashing"));
    }
    let remaining = MAX_ARTIFACT_HASH_INPUT.saturating_sub(input.len());
    let mut bytes = Vec::new();
    (&mut file)
        .take(remaining.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    if bytes.len() > remaining || bytes.len() as u64 != metadata.len() {
        return Err(invalid("preservation artifact exceeded its byte bound"));
    }
    input.extend_from_slice(&bytes);
    if artifacts::identity(metadata)
        != artifacts::identity(&std::fs::symlink_metadata(path).map_err(invalid)?)
    {
        return Err(invalid("preservation artifact changed while hashing"));
    }
    Ok(())
}

fn hash_field(input: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WorkerError> {
    if input
        .len()
        .checked_add(8)
        .and_then(|length| length.checked_add(bytes.len()))
        .is_none_or(|length| length > MAX_ARTIFACT_HASH_INPUT)
    {
        return Err(invalid(
            "preservation digest preimage exceeded its byte bound",
        ));
    }
    input.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    input.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn read_pretty<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
) -> Result<T, WorkerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(invalid)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return Err(invalid("preserved workspace manifest is not protected"));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(invalid)?;
    let mut file = File::from(descriptor);
    if artifacts::identity(&metadata) != artifacts::identity(&file.metadata().map_err(invalid)?) {
        return Err(invalid("workspace manifest changed before admission"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    let value: T = serde_json::from_slice(&bytes).map_err(invalid)?;
    if bytes.len() as u64 != metadata.len()
        || serde_json::to_vec_pretty(&value).map_err(invalid)? != bytes
        || artifacts::identity(&metadata)
            != artifacts::identity(&std::fs::symlink_metadata(path).map_err(invalid)?)
    {
        return Err(invalid("workspace manifest bytes or identity changed"));
    }
    Ok(value)
}

fn state_digest(value: &impl Serialize) -> Result<String, WorkerError> {
    let bytes = serde_json::to_vec(value).map_err(invalid)?;
    let mut framed = Vec::new();
    hash_field(&mut framed, STATE_DOMAIN)?;
    hash_field(&mut framed, &bytes)?;
    Ok(Digest::of(&framed).to_hex())
}

#[cfg(test)]
pub(super) fn state_digest_for_fixture(value: &impl Serialize) -> Result<String, WorkerError> {
    state_digest(value)
}
