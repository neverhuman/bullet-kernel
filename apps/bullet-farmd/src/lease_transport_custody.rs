//! Durable local farmd lease-transport registry and signing-key custody.
//!
//! Parent directories are 0700. The key file is exactly 64 raw bytes at 0600.
//! This is not debug-fixture injection and not an ephemeral process key.

use crate::lease_transport_rpc::{LeasePeerRegistry, RegisteredRunnerPeer};
use bullet_application::lease_transport::KernelLeaseTransport;
use bullet_domain::RunnerId;
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const KEY_BYTES: usize = 64;
const FILE_MODE: u32 = 0o600;
const PARENT_MODE: u32 = 0o700;

/// On-disk peer registry. One farmd identity plus exact Runner incarnations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePeerRegistryFile {
    /// farmd service UID that must own the UDS.
    pub farmd_uid: u32,
    /// Shared socket GID.
    pub socket_gid: u32,
    /// Exact admitted Runner incarnations.
    pub runners: Vec<DurableRegisteredRunner>,
}

/// One exact Runner ID, epoch, and service UID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRegisteredRunner {
    /// `run_<32hex>`.
    pub runner_id: String,
    /// Nonzero generation.
    pub runner_epoch: u64,
    /// Operating-system UID that may present this incarnation.
    pub service_uid: u32,
}

/// Loaded durable transport: registry plus the operator-held key.
pub struct DurableLeaseTransport {
    /// Admitted peer policy.
    pub registry: LeasePeerRegistry,
    /// Kernel-minted lease transport bound to the on-disk key.
    pub transport: KernelLeaseTransport,
    /// Raw 64-byte secret, also used for mutation-permit mint/verify.
    pub key_bytes: Vec<u8>,
}

/// Load one absolute registry file and one absolute 0600 signing key.
///
/// # Errors
///
/// Relative paths, symlink traversal, wrong modes, empty/duplicate registry,
/// or a malformed 64-byte key.
pub fn load_durable_lease_transport(
    registry_path: &Path,
    key_path: &Path,
) -> Result<DurableLeaseTransport, Error> {
    let registry = load_peer_registry(registry_path)?;
    let signing = load_signing_key(key_path)?;
    let key_bytes = signing.secret_bytes().to_vec();
    let transport = KernelLeaseTransport::new(signing)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
    Ok(DurableLeaseTransport {
        registry,
        transport,
        key_bytes,
    })
}

/// Persist a new signing key. Refuses to replace an existing file.
///
/// # Errors
///
/// Relative path, existing key, or filesystem failure.
pub fn write_new_signing_key(path: &Path) -> Result<LeaseTransportSigningKey, Error> {
    if !path.is_absolute() {
        return Err(invalid("lease-transport key path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("lease-transport key needs a parent directory"))?;
    require_or_create_parent(parent)?;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(invalid(
            "lease-transport signing key already exists; refusing to overwrite",
        ));
    }
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1")
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.write_all(key.secret_bytes())?;
    file.sync_all()?;
    Ok(key)
}

/// Persist one peer registry under a 0700 parent as a 0600 file.
///
/// # Errors
///
/// Relative path or filesystem failure.
pub fn write_peer_registry(path: &Path, registry: &DurablePeerRegistryFile) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(invalid("lease-transport registry path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("lease-transport registry needs a parent directory"))?;
    require_or_create_parent(parent)?;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(invalid(
            "lease-transport registry already exists; refusing to overwrite",
        ));
    }
    let bytes = serde_json::to_vec(registry)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_peer_registry(path: &Path) -> Result<LeasePeerRegistry, Error> {
    let bytes = read_private_file(path, "lease-transport registry")?;
    let parsed: DurablePeerRegistryFile = serde_json::from_slice(&bytes)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
    let mut runners = Vec::with_capacity(parsed.runners.len());
    for runner in parsed.runners {
        if runner.runner_epoch == 0 {
            return Err(invalid("registered runner epoch must be nonzero"));
        }
        let runner_id = RunnerId::parse(&runner.runner_id)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
        runners.push(RegisteredRunnerPeer::new(
            runner_id,
            runner.runner_epoch,
            runner.service_uid,
        ));
    }
    LeasePeerRegistry::new(parsed.farmd_uid, parsed.socket_gid, runners)
}

fn load_signing_key(path: &Path) -> Result<LeaseTransportSigningKey, Error> {
    let bytes = read_private_file(path, "lease-transport signing key")?;
    if bytes.len() != KEY_BYTES {
        return Err(invalid(
            "lease-transport signing key must be exactly 64 raw bytes",
        ));
    }
    LeaseTransportSigningKey::from_bytes("kernel-local", "lease-1", &bytes)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))
}

fn read_private_file(path: &Path, label: &str) -> Result<Vec<u8>, Error> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} path must be absolute")));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{label} needs a parent directory")))?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(invalid(format!(
            "{label} parent must be a non-symlink directory"
        )));
    }
    if parent_meta.permissions().mode() & 0o777 != PARENT_MODE {
        return Err(invalid(format!("{label} parent must be mode 0700")));
    }
    let linkless = std::fs::symlink_metadata(path)?;
    if linkless.file_type().is_symlink() || !linkless.file_type().is_file() {
        return Err(invalid(format!(
            "{label} must be a regular file, not a symlink"
        )));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file()
        || opened.dev() != linkless.dev()
        || opened.ino() != linkless.ino()
    {
        return Err(invalid(format!("{label} identity changed while opening")));
    }
    if opened.permissions().mode() & 0o777 != FILE_MODE {
        return Err(invalid(format!("{label} mode must be exactly 0600")));
    }
    if opened.uid() != current_uid() {
        return Err(invalid(format!(
            "{label} must be owned by the current user"
        )));
    }
    let mut bytes = Vec::new();
    file.take(65_536).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn require_or_create_parent(parent: &Path) -> Result<(), Error> {
    if !parent.is_absolute() {
        return Err(invalid("lease-transport custody parent must be absolute"));
    }
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let meta = std::fs::symlink_metadata(parent)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(invalid(
            "lease-transport custody parent must be a non-symlink directory",
        ));
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(PARENT_MODE))?;
    Ok(())
}

fn current_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX)
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn ids() -> (u32, u32) {
        let info = std::fs::metadata("/proc/self").expect("self");
        (info.uid(), info.gid())
    }

    #[test]
    fn durable_registry_and_key_load_and_refuse_hostiles() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("custody");
        std::fs::create_dir_all(&parent).expect("parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(PARENT_MODE))
            .expect("0700");
        let key_path = parent.join("signing.key");
        let registry_path = parent.join("peer-registry.json");
        write_new_signing_key(&key_path).expect("write key");
        let (uid, gid) = ids();
        let runner = RunnerId::from_seed("durable-runner");
        write_peer_registry(
            &registry_path,
            &DurablePeerRegistryFile {
                farmd_uid: uid,
                socket_gid: gid,
                runners: vec![DurableRegisteredRunner {
                    runner_id: runner.to_string(),
                    runner_epoch: 1,
                    service_uid: uid,
                }],
            },
        )
        .expect("write registry");
        load_durable_lease_transport(&registry_path, &key_path).expect("load");
        assert!(write_new_signing_key(&key_path).is_err());
        assert!(load_durable_lease_transport(Path::new("relative.json"), &key_path).is_err());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("644");
        assert!(load_durable_lease_transport(&registry_path, &key_path).is_err());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(FILE_MODE))
            .expect("600");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).expect("755");
        assert!(load_durable_lease_transport(&registry_path, &key_path).is_err());
    }
}
