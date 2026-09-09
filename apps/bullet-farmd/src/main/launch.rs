use super::Args;
use bullet_application::candidate_preparation::CandidatePreparationSigningKey;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) fn provision_lease_transport_key(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return Err("LEASE_TRANSPORT_KEY_PROVISION_FAILED: key path must be absolute".to_string());
    }
    let parent = path.parent().ok_or_else(|| {
        "LEASE_TRANSPORT_KEY_PROVISION_FAILED: key path needs a parent directory".to_string()
    })?;
    if let Ok(metadata) = std::fs::symlink_metadata(parent) {
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(
                "LEASE_TRANSPORT_KEY_PROVISION_FAILED: existing parent must be caller-owned mode 0700"
                    .to_string(),
            );
        }
    }
    bullet_farmd::lease_transport_custody::write_new_signing_key(path)
        .map(|_| ())
        .map_err(|error| format!("LEASE_TRANSPORT_KEY_PROVISION_FAILED: {error}"))
}

#[cfg(unix)]
pub(super) fn read_worker_token(path: &Path) -> Result<String, String> {
    read_worker_token_descriptor(open_worker_token(path)?)
}

#[cfg(unix)]
pub(super) fn open_worker_token(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
pub(super) fn read_worker_token_descriptor(file: std::fs::File) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("token descriptor must refer to a regular file".into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("token file must not be accessible by group or other users".into());
    }
    if metadata.len() > 128 {
        return Err("token file exceeds 128 bytes".into());
    }
    let mut bytes = Vec::with_capacity(128);
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 128 {
        return Err("token file exceeds 128 bytes".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "token file must be UTF-8".to_string())?;
    let token = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if token.contains(['\r', '\n']) {
        return Err("token file must contain exactly one token".into());
    }
    Ok(token.to_string())
}

#[cfg(not(unix))]
pub(super) fn read_worker_token(_path: &Path) -> Result<String, String> {
    Err(
        "worker token files are unavailable without descriptor-safe admission on this platform"
            .into(),
    )
}

pub(super) fn validate_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing non-loopback bind {bind}; local V1 accepts loopback only"
        ))
    }
}

pub(super) struct LeaseTransportLaunch {
    pub(super) socket: PathBuf,
    pub(super) registry: Arc<bullet_farmd::lease_transport_rpc::LeasePeerRegistry>,
    pub(super) transport: Arc<bullet_application::lease_transport::KernelLeaseTransport>,
    pub(super) candidate_key: Option<Arc<CandidatePreparationSigningKey>>,
    pub(super) fixture: bool,
    pub(super) key_bytes: Option<Vec<u8>>,
}

pub(super) fn admit_lease_transport_launch(
    args: &Args,
) -> Result<Option<LeaseTransportLaunch>, String> {
    #[cfg(debug_assertions)]
    let fixture_registration = args.fixture_lease_peer_registration.as_deref();
    #[cfg(not(debug_assertions))]
    let fixture_registration: Option<&str> = None;
    admit_lease_transport(
        args.lease_transport_socket.clone(),
        args.lease_peer_registry.as_deref(),
        args.lease_transport_key.as_deref(),
        fixture_registration,
    )
}

pub(super) fn admit_lease_transport(
    socket: Option<PathBuf>,
    registry_path: Option<&Path>,
    key_path: Option<&Path>,
    fixture_registration: Option<&str>,
) -> Result<Option<LeaseTransportLaunch>, String> {
    let durable = registry_path.is_some() || key_path.is_some();
    let Some(socket) = socket else {
        return if durable {
            Err("LEASE_PEER_REGISTRY_UNAVAILABLE: durable registry/key require --lease-transport-socket".into())
        } else if fixture_registration.is_some() {
            Err("FIXTURE_LEASE_SOCKET_REQUIRED: fixture registration needs --lease-transport-socket".into())
        } else {
            Ok(None)
        };
    };
    if durable && fixture_registration.is_some() {
        return Err(
            "LEASE_PEER_REGISTRY_UNAVAILABLE: durable custody and debug fixture registration cannot be combined"
                .into(),
        );
    }
    if durable {
        let registry_path = registry_path.ok_or_else(|| {
            "LEASE_PEER_REGISTRY_UNAVAILABLE: --lease-peer-registry is required with --lease-transport-key"
                .to_string()
        })?;
        let key_path = key_path.ok_or_else(|| {
            "LEASE_PEER_REGISTRY_UNAVAILABLE: --lease-transport-key is required with --lease-peer-registry"
                .to_string()
        })?;
        let loaded = bullet_farmd::lease_transport_custody::load_durable_lease_transport(
            registry_path,
            key_path,
        )
        .map_err(|error| format!("LEASE_PEER_REGISTRY_UNAVAILABLE: {error}"))?;
        loaded
            .registry
            .preflight_socket_path(&socket)
            .map_err(|error| format!("LEASE_SOCKET_INVALID: {error}"))?;
        let candidate_key = CandidatePreparationSigningKey::from_bytes(
            "kernel-local",
            "candidate-preparation-1",
            &loaded.key_bytes,
        )
        .map_err(|error| format!("CANDIDATE_PREPARATION_KEY_INVALID: {error}"))?;
        return Ok(Some(LeaseTransportLaunch {
            socket,
            registry: Arc::new(loaded.registry),
            transport: Arc::new(loaded.transport),
            candidate_key: Some(Arc::new(candidate_key)),
            fixture: false,
            key_bytes: Some(loaded.key_bytes),
        }));
    }
    if let Some(registration) = fixture_registration {
        let registry = fixture_peer_registry(registration, &socket)?;
        let transport = bullet_application::lease_transport::KernelLeaseTransport::generate()
            .map_err(|error| format!("FIXTURE_LEASE_TRANSPORT: {error}"))?;
        return Ok(Some(LeaseTransportLaunch {
            socket,
            registry: Arc::new(registry),
            transport: Arc::new(transport),
            candidate_key: None,
            fixture: true,
            key_bytes: None,
        }));
    }
    Err(
        "LEASE_PEER_REGISTRY_UNAVAILABLE: durable runner UID registration and pinned farmd identity are not configured"
            .into(),
    )
}

fn fixture_peer_registry(
    registration: &str,
    socket: &Path,
) -> Result<bullet_farmd::lease_transport_rpc::LeasePeerRegistry, String> {
    let (runner, epoch) = registration.rsplit_once(':').ok_or_else(|| {
        "FIXTURE_LEASE_PEER_INVALID: expected <run_<32hex>:<nonzero-epoch>>".to_string()
    })?;
    let runner_id = bullet_domain::RunnerId::parse(runner)
        .map_err(|error| format!("FIXTURE_LEASE_PEER_INVALID: {error}"))?;
    let runner_epoch = epoch
        .parse::<u64>()
        .map_err(|_| "FIXTURE_LEASE_PEER_INVALID: epoch must be an integer".to_string())?;
    if runner_epoch == 0 {
        return Err("FIXTURE_LEASE_PEER_INVALID: epoch must be nonzero".into());
    }
    use std::os::unix::fs::MetadataExt;
    let process = std::fs::metadata("/proc/self")
        .map_err(|error| format!("FIXTURE_LEASE_PEER_IDENTITY_UNAVAILABLE: {error}"))?;
    let registry = bullet_farmd::lease_transport_rpc::LeasePeerRegistry::new(
        process.uid(),
        process.gid(),
        [
            bullet_farmd::lease_transport_rpc::RegisteredRunnerPeer::new(
                runner_id,
                runner_epoch,
                process.uid(),
            ),
        ],
    )
    .map_err(|error| format!("FIXTURE_LEASE_PEER_INVALID: {error}"))?;
    registry
        .preflight_socket_path(socket)
        .map_err(|error| format!("FIXTURE_LEASE_SOCKET_INVALID: {error}"))?;
    Ok(registry)
}
