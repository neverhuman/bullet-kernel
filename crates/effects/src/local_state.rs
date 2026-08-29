//! Immutable, restart-safe local forge control records.

use crate::error::EffectsError;
use crate::integration::{CheckReceipt, IntegrationReceipt, IntegrationSubject, ProtectionState};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const STATE_DIR: &str = "bullet-effects-v1";

#[derive(Clone, Debug)]
pub(crate) struct LocalState {
    root: PathBuf,
}

impl LocalState {
    pub(crate) fn open(bare: &Path) -> Result<Self, EffectsError> {
        let root = bare.join(STATE_DIR);
        ensure_directory(&root)?;
        for name in ["protections", "checks", "subjects", "integrations"] {
            ensure_directory(&root.join(name))?;
        }
        Ok(Self { root })
    }

    pub(crate) fn protection_key(target: &str) -> String {
        key("bullet-local-protection-v1", &[target])
    }

    pub(crate) fn check_key(sha: &str, name: &str) -> String {
        key("bullet-local-check-v1", &[sha, name])
    }

    pub(crate) fn subject_id(base: &str, head: &str, target: &str) -> String {
        format!(
            "ins_{}",
            key("bullet-local-integration-subject-v1", &[base, head, target])
        )
    }

    pub(crate) fn read_protection(
        &self,
        target: &str,
    ) -> Result<Option<ProtectionState>, EffectsError> {
        self.read("protections", &Self::protection_key(target))
    }

    pub(crate) fn put_protection(&self, value: &ProtectionState) -> Result<bool, EffectsError> {
        self.put("protections", &Self::protection_key(&value.target), value)
    }

    pub(crate) fn read_check(
        &self,
        sha: &str,
        name: &str,
    ) -> Result<Option<CheckReceipt>, EffectsError> {
        self.read("checks", &Self::check_key(sha, name))
    }

    pub(crate) fn put_check(&self, value: &CheckReceipt) -> Result<bool, EffectsError> {
        self.put("checks", &Self::check_key(&value.sha, &value.name), value)
    }

    pub(crate) fn read_subject(
        &self,
        id: &str,
    ) -> Result<Option<IntegrationSubject>, EffectsError> {
        self.read("subjects", id)
    }

    pub(crate) fn put_subject(&self, value: &IntegrationSubject) -> Result<bool, EffectsError> {
        self.put("subjects", &value.id, value)
    }

    pub(crate) fn read_integration(
        &self,
        subject_id: &str,
    ) -> Result<Option<IntegrationReceipt>, EffectsError> {
        self.read("integrations", subject_id)
    }

    pub(crate) fn put_integration(&self, value: &IntegrationReceipt) -> Result<bool, EffectsError> {
        self.put("integrations", &value.subject_id, value)
    }

    fn path(&self, category: &str, key: &str) -> PathBuf {
        self.root.join(category).join(format!("{key}.json"))
    }

    fn read<T: DeserializeOwned + Serialize>(
        &self,
        category: &str,
        key: &str,
    ) -> Result<Option<T>, EffectsError> {
        let path = self.path(category, key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("inspect state", &path, error)),
        };
        if !metadata.file_type().is_file() {
            return Err(EffectsError::DurableQueueInvalid(format!(
                "local forge state is not a regular file: {}",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(|error| io_error("read state", &path, error))?;
        let value: T = serde_json::from_slice(&bytes).map_err(|error| {
            EffectsError::DurableQueueInvalid(format!(
                "invalid local forge state {}: {error}",
                path.display()
            ))
        })?;
        let canonical = serde_json::to_vec(&value).map_err(|error| {
            EffectsError::DurableQueueInvalid(format!("serialize local forge state: {error}"))
        })?;
        if canonical != bytes {
            return Err(EffectsError::DurableQueueInvalid(format!(
                "non-canonical local forge state: {}",
                path.display()
            )));
        }
        Ok(Some(value))
    }

    fn put<T: DeserializeOwned + Serialize + Eq>(
        &self,
        category: &str,
        key: &str,
        value: &T,
    ) -> Result<bool, EffectsError> {
        if let Some(existing) = self.read::<T>(category, key)? {
            return Ok(existing == *value);
        }
        let path = self.path(category, key);
        let bytes = serde_json::to_vec(value).map_err(|error| {
            EffectsError::DurableQueueInvalid(format!("serialize local forge state: {error}"))
        })?;
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(self.read::<T>(category, key)?.as_ref() == Some(value));
            }
            Err(error) => return Err(io_error("create state", &path, error)),
        };
        file.write_all(&bytes)
            .map_err(|error| io_error("write state", &path, error))?;
        file.sync_all()
            .map_err(|error| io_error("sync state", &path, error))?;
        File::open(path.parent().expect("state file has parent"))
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync state directory", &path, error))?;
        Ok(true)
    }
}

fn key(domain: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn ensure_directory(path: &Path) -> Result<(), EffectsError> {
    fs::create_dir(path)
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| io_error("create state directory", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect state directory", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(EffectsError::DurableQueueInvalid(format!(
            "local forge state is not a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn io_error(operation: &str, path: &Path, error: std::io::Error) -> EffectsError {
    EffectsError::Io(format!("{operation} {}: {error}", path.display()))
}
