//! Exact, read-only OAuth material staging into one unique provider HOME.

use crate::argv::filter_env;
use crate::error::HarnessError;
use crate::ids::synthetic_uuid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_CREDENTIAL_FILES: usize = 4;
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;

/// One individually admitted OAuth file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialGrant {
    /// Absolute canonical source file.
    pub source: PathBuf,
    /// Relative destination below the ephemeral HOME.
    pub target: PathBuf,
    /// Expected lowercase BLAKE3 digest of the exact source bytes.
    pub expected_blake3: String,
}

/// Non-secret receipt for one staged credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReceipt {
    /// Relative target only; the host source is deliberately omitted.
    pub target: String,
    /// Exact staged-byte digest.
    pub blake3: String,
}

/// Unique provider HOME plus its positive child environment.
#[derive(Debug)]
pub struct PreparedProviderHome {
    home: PathBuf,
    env: Vec<(String, String)>,
    credentials: Vec<CredentialReceipt>,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl PreparedProviderHome {
    /// Create an isolated 0700 HOME and copy only exact admitted files.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` for unsafe roots/targets, symlinks, digest
    /// mismatch, excessive material, or a non-Unix containment host.
    pub fn stage<I>(
        runtime_root: &Path,
        allowed_targets: &[PathBuf],
        grants: &[CredentialGrant],
        inherited_env: I,
    ) -> Result<Self, HarnessError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        #[cfg(not(unix))]
        return Err(refused("provider HOME staging is certified only on Unix"));

        #[cfg(unix)]
        {
            if grants.len() > MAX_CREDENTIAL_FILES {
                return Err(refused("too many credential files"));
            }
            validate_grants(allowed_targets, grants)?;
            let canonical_root = canonical_directory(runtime_root, "runtime root")?;
            let home = canonical_root.join(format!("provider-home-{}", synthetic_uuid("home")));
            std::fs::create_dir(&home).map_err(|error| io("create provider HOME", error))?;
            set_mode(&home, 0o700)?;
            sync_directory(&canonical_root)?;

            let mut staged = Self {
                home: home.clone(),
                env: positive_env(inherited_env, &home),
                credentials: Vec::new(),
                files: Vec::new(),
                directories: vec![home.clone()],
            };
            for relative in ["tmp", ".cache", ".config"] {
                let directory = home.join(relative);
                std::fs::create_dir(&directory)
                    .map_err(|error| io("create provider HOME directory", error))?;
                set_mode(&directory, 0o700)?;
                staged.directories.push(directory);
            }
            for grant in grants {
                staged.copy_one(grant)?;
            }
            staged
                .credentials
                .sort_by(|left, right| left.target.cmp(&right.target));
            sync_directory(&home)?;
            Ok(staged)
        }
    }

    /// Exact staged HOME directory. Bind this path into the sandbox; do not
    /// remount the host source.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.home
    }

    /// Exact positive environment for the provider child.
    #[must_use]
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// Non-secret credential receipts.
    #[must_use]
    pub fn credential_receipts(&self) -> &[CredentialReceipt] {
        &self.credentials
    }

    #[cfg(unix)]
    fn copy_one(&mut self, grant: &CredentialGrant) -> Result<(), HarnessError> {
        let metadata = std::fs::symlink_metadata(&grant.source)
            .map_err(|error| io("credential metadata", error))?;
        if !grant.source.is_absolute() || !metadata.file_type().is_file() {
            return Err(refused(
                "credential source must be an absolute regular file",
            ));
        }
        if metadata.len() > MAX_CREDENTIAL_BYTES {
            return Err(refused("credential file exceeds the one MiB limit"));
        }
        let canonical = grant
            .source
            .canonicalize()
            .map_err(|error| io("canonicalize credential", error))?;
        if canonical != grant.source {
            return Err(refused("credential source is not canonical"));
        }
        let input = File::open(&canonical).map_err(|error| io("open credential", error))?;
        let opened = input
            .metadata()
            .map_err(|error| io("opened credential metadata", error))?;
        if !same_file(&metadata, &opened) {
            return Err(refused("credential identity changed while opening"));
        }
        let bytes = read_bounded(input)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        if digest != grant.expected_blake3 {
            return Err(refused("credential digest mismatch"));
        }
        let target = self.home.join(&grant.target);
        self.create_target_parents(&grant.target)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target)
            .map_err(|error| io("create staged credential", error))?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| io("write staged credential", error))?;
        set_mode(&target, 0o400)?;
        output
            .sync_all()
            .map_err(|error| io("sync staged credential mode", error))?;
        if let Some(parent) = target.parent() {
            sync_directory(parent)?;
        }
        self.files.push(target);
        self.credentials.push(CredentialReceipt {
            target: grant.target.to_string_lossy().into_owned(),
            blake3: digest,
        });
        Ok(())
    }

    #[cfg(unix)]
    fn create_target_parents(&mut self, target: &Path) -> Result<(), HarnessError> {
        let mut current = self.home.clone();
        let Some(parent) = target.parent() else {
            return Ok(());
        };
        for component in parent.components() {
            let Component::Normal(segment) = component else {
                return Err(refused("credential target has a non-normal component"));
            };
            current.push(segment);
            if !current.exists() {
                std::fs::create_dir(&current)
                    .map_err(|error| io("create credential directory", error))?;
                set_mode(&current, 0o700)?;
                self.directories.push(current.clone());
            }
            let metadata = std::fs::symlink_metadata(&current)
                .map_err(|error| io("credential directory metadata", error))?;
            if !metadata.file_type().is_dir() {
                return Err(refused("credential target parent is not a directory"));
            }
        }
        Ok(())
    }
}

impl Drop for PreparedProviderHome {
    fn drop(&mut self) {
        for file in self.files.iter().rev() {
            if std::fs::symlink_metadata(file)
                .map(|metadata| metadata.file_type().is_file())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_file(file);
            }
        }
        for directory in self.directories.iter().rev() {
            if std::fs::symlink_metadata(directory)
                .map(|metadata| metadata.file_type().is_dir())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(directory);
            }
        }
    }
}

fn positive_env<I>(vars: I, home: &Path) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: BTreeMap<String, String> = filter_env(vars).into_iter().collect();
    let home = home.to_string_lossy().into_owned();
    env.insert("HOME".into(), home.clone());
    env.insert("TMPDIR".into(), format!("{home}/tmp"));
    env.insert("XDG_CACHE_HOME".into(), format!("{home}/.cache"));
    env.insert("XDG_CONFIG_HOME".into(), format!("{home}/.config"));
    env.into_iter().collect()
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, HarnessError> {
    if !path.is_absolute() {
        return Err(refused(&format!("{label} must be absolute")));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| io(&format!("canonicalize {label}"), error))?;
    if canonical != path || !canonical.is_dir() {
        return Err(refused(&format!("{label} must be a canonical directory")));
    }
    Ok(canonical)
}

fn validate_relative(path: &Path) -> Result<(), HarnessError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(refused(
            "credential target must contain only normal relative components",
        ));
    }
    Ok(())
}

fn validate_grants(
    allowed_targets: &[PathBuf],
    grants: &[CredentialGrant],
) -> Result<(), HarnessError> {
    let allowed: BTreeSet<&Path> = allowed_targets.iter().map(PathBuf::as_path).collect();
    if allowed.len() != allowed_targets.len() {
        return Err(refused("duplicate credential allowlist target"));
    }
    for target in allowed_targets {
        validate_relative(target)?;
    }
    let mut targets = BTreeSet::new();
    for grant in grants {
        validate_relative(&grant.target)?;
        if !allowed.contains(grant.target.as_path()) {
            return Err(refused("credential target is outside its exact allowlist"));
        }
        if !targets.insert(&grant.target) {
            return Err(refused("duplicate credential target"));
        }
        validate_digest(&grant.expected_blake3)?;
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), HarnessError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused(
            "credential digest must be 64 lowercase hex characters",
        ));
    }
    Ok(())
}

fn read_bounded(file: File) -> Result<Vec<u8>, HarnessError> {
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io("read credential", error))?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(refused("credential file exceeds the one MiB limit"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.file_type().is_file()
        && opened.file_type().is_file()
        && before.dev() == opened.dev()
        && before.ino() == opened.ino()
        && before.len() == opened.len()
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), HarnessError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| io("set staged permission", error))
}

fn sync_directory(path: &Path) -> Result<(), HarnessError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| io("sync provider directory", error))
}

fn refused(reason: &str) -> HarnessError {
    HarnessError::AdmissionRefused {
        reason: reason.to_string(),
    }
}

fn io(context: &str, error: std::io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialGrant, PreparedProviderHome};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn write_grant(root: &Path, name: &str, bytes: &[u8]) -> (PathBuf, String) {
        let source = root.join(name);
        std::fs::write(&source, bytes).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
        let source = source.canonicalize().unwrap();
        let digest = blake3::hash(bytes).to_hex().to_string();
        (source, digest)
    }

    #[test]
    fn stages_only_granted_files_and_omits_host_source() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = runtime.canonicalize().unwrap();
        let (source, digest) = write_grant(root.path(), "oauth.json", b"{\"token\":1}");
        let home = PreparedProviderHome::stage(
            &runtime,
            &[PathBuf::from(".claude/oauth.json")],
            &[CredentialGrant {
                source: source.clone(),
                target: PathBuf::from(".claude/oauth.json"),
                expected_blake3: digest.clone(),
            }],
            std::iter::empty(),
        )
        .unwrap();
        assert!(home.path().starts_with(&runtime));
        assert_eq!(
            std::fs::read(home.path().join(".claude/oauth.json")).unwrap(),
            b"{\"token\":1}"
        );
        let receipt = serde_json::to_string(&home.credential_receipts()).unwrap();
        assert!(!receipt.contains(source.to_str().unwrap()));
        assert_eq!(home.credential_receipts()[0].blake3, digest);
    }

    #[test]
    fn digest_mismatch_and_bounds_refuse() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = runtime.canonicalize().unwrap();
        let (source, _) = write_grant(root.path(), "oauth.json", b"secret");
        let error = PreparedProviderHome::stage(
            &runtime,
            &[PathBuf::from("oauth.json")],
            &[CredentialGrant {
                source: source.clone(),
                target: PathBuf::from("oauth.json"),
                expected_blake3: "0".repeat(64),
            }],
            std::iter::empty(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));

        let grants: Vec<CredentialGrant> = (0..5)
            .map(|index| {
                let (path, digest) = write_grant(root.path(), &format!("f{index}"), b"x");
                CredentialGrant {
                    source: path,
                    target: PathBuf::from(format!("f{index}")),
                    expected_blake3: digest,
                }
            })
            .collect();
        let targets: Vec<PathBuf> = grants.iter().map(|grant| grant.target.clone()).collect();
        assert!(
            PreparedProviderHome::stage(&runtime, &targets, &grants, std::iter::empty()).is_err()
        );
    }
}
