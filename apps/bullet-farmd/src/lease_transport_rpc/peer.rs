use bullet_domain::RunnerId;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

const PARENT_MODE: u32 = 0o710;
pub(super) const SOCKET_MODE: u32 = 0o660;

/// One exact Runner incarnation admitted by Kernel configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredRunnerPeer {
    runner_id: RunnerId,
    runner_epoch: u64,
    service_uid: u32,
}

impl RegisteredRunnerPeer {
    /// Register one exact Runner ID, epoch, and operating-system service UID.
    #[must_use]
    pub fn new(runner_id: RunnerId, runner_epoch: u64, service_uid: u32) -> Self {
        Self {
            runner_id,
            runner_epoch,
            service_uid,
        }
    }
}

/// Immutable peer policy supplied by an authoritative registration source.
#[derive(Clone, Debug)]
pub struct LeasePeerRegistry {
    farmd_uid: u32,
    socket_gid: u32,
    runners: BTreeMap<(String, u64), u32>,
}

impl LeasePeerRegistry {
    /// Build one exact registry. Duplicate Runner incarnations are refused.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an empty registry or duplicate incarnation.
    pub fn new(
        farmd_uid: u32,
        socket_gid: u32,
        runners: impl IntoIterator<Item = RegisteredRunnerPeer>,
    ) -> Result<Self, Error> {
        let mut admitted = BTreeMap::new();
        for runner in runners {
            let key = (runner.runner_id.to_string(), runner.runner_epoch);
            if admitted.insert(key, runner.service_uid).is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "duplicate registered Runner incarnation",
                ));
            }
        }
        if admitted.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "lease-transport peer registry must not be empty",
            ));
        }
        Ok(Self {
            farmd_uid,
            socket_gid,
            runners: admitted,
        })
    }

    /// Check the socket path and parent without creating filesystem state.
    ///
    /// The server repeats this check immediately before binding. Debug-only
    /// component launchers use it to refuse invalid fixtures before startup.
    ///
    /// # Errors
    ///
    /// Returns an I/O or permission error when the path is not admissible.
    pub fn preflight_socket_path(&self, path: &Path) -> Result<(), Error> {
        validate_socket_path(path, self)
    }

    fn admit_runner(&self, runner_id: &RunnerId, runner_epoch: u64, uid: u32) -> Result<(), Error> {
        match self.runners.get(&(runner_id.to_string(), runner_epoch)) {
            Some(expected_uid) if *expected_uid == uid => Ok(()),
            _ => Err(Error::new(
                ErrorKind::PermissionDenied,
                "lease-transport Runner ID/epoch is not registered for the peer UID",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ListenerIdentity {
    pub(super) dev: u64,
    pub(super) ino: u64,
}

impl ListenerIdentity {
    fn from_listener(listener: &UnixListener) -> Result<Self, Error> {
        let stat = rustix::fs::fstat(listener)
            .map_err(|error| Error::from_raw_os_error(error.raw_os_error()))?;
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PathIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl PathIdentity {
    fn from_path(path: &Path) -> Result<Self, Error> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "lease-transport path must be a non-symlink Unix socket",
            ));
        }
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.permissions().mode() & 0o777,
        })
    }

    fn validate_policy(&self, registry: &LeasePeerRegistry) -> Result<(), Error> {
        if self.uid != registry.farmd_uid {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "lease-transport socket owner does not match registered farmd UID",
            ));
        }
        if self.gid != registry.socket_gid {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "lease-transport socket group does not match registered socket GID",
            ));
        }
        if self.mode != SOCKET_MODE {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "lease-transport socket must be mode 0660",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BoundSocketIdentity {
    listener: ListenerIdentity,
    path: PathIdentity,
}

impl BoundSocketIdentity {
    pub(super) fn socket_dev(self) -> u64 {
        self.path.dev
    }

    pub(super) fn socket_ino(self) -> u64 {
        self.path.ino
    }

    pub(super) fn listener_dev(self) -> u64 {
        self.listener.dev
    }

    pub(super) fn listener_ino(self) -> u64 {
        self.listener.ino
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PeerCred {
    pub(super) pid: i32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) fn bind_admitted_socket(
    path: &Path,
    registry: &LeasePeerRegistry,
) -> Result<(UnixListener, BoundSocketIdentity), Error> {
    validate_socket_path(path, registry)?;

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    let listener_identity = ListenerIdentity::from_listener(&listener)?;
    let path_identity = PathIdentity::from_path(path)?;
    path_identity.validate_policy(registry)?;
    let local_path = listener
        .local_addr()?
        .as_pathname()
        .ok_or_else(|| Error::new(ErrorKind::PermissionDenied, "listener has no pathname"))?
        .to_path_buf();
    if local_path != path {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "lease-transport listening descriptor has the wrong pathname",
        ));
    }
    Ok((
        listener,
        BoundSocketIdentity {
            listener: listener_identity,
            path: path_identity,
        },
    ))
}

fn validate_socket_path(path: &Path, registry: &LeasePeerRegistry) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport socket must be an absolute path",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "lease-transport socket needs a parent directory",
        )
    })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    if canonical_parent != parent {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be canonical and contain no symlink traversal",
        ));
    }
    let meta = std::fs::symlink_metadata(parent)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be a non-symlink directory",
        ));
    }
    if meta.permissions().mode() & 0o777 != PARENT_MODE {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be mode 0710",
        ));
    }
    if meta.uid() != registry.farmd_uid || meta.gid() != registry.socket_gid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "lease-transport parent identity does not match the peer registry",
        ));
    }
    if let Err(error) = std::fs::symlink_metadata(path) {
        if error.kind() != ErrorKind::NotFound {
            return Err(error);
        }
    } else {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "refusing to replace an existing lease-transport path",
        ));
    }
    Ok(())
}

pub(super) fn admit_peer(
    socket: &Path,
    listener: &UnixListener,
    bound: &BoundSocketIdentity,
    stream: &UnixStream,
) -> Result<PeerCred, Error> {
    let current_listener = ListenerIdentity::from_listener(listener)?;
    if current_listener != bound.listener {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "lease-transport listening descriptor identity drifted",
        ));
    }
    let current_path = PathIdentity::from_path(socket)?;
    if current_path != bound.path {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "lease-transport socket identity drifted",
        ));
    }
    let cred = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|error| Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(PeerCred {
        pid: cred.pid.as_raw_pid(),
        uid: cred.uid.as_raw(),
        gid: cred.gid.as_raw(),
    })
}

pub(super) fn admit_runner(
    registry: &LeasePeerRegistry,
    runner_id: &RunnerId,
    runner_epoch: u64,
    peer: &PeerCred,
) -> Result<(), Error> {
    registry.admit_runner(runner_id, runner_epoch, peer.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn ids() -> (u32, u32) {
        let info = std::fs::metadata("/proc/self").expect("self metadata");
        (info.uid(), info.gid())
    }

    fn registry(runner: &RunnerId, epoch: u64) -> LeasePeerRegistry {
        let (uid, gid) = ids();
        LeasePeerRegistry::new(
            uid,
            gid,
            [RegisteredRunnerPeer::new(runner.clone(), epoch, uid)],
        )
        .expect("registry")
    }

    #[test]
    fn registry_binds_runner_id_epoch_and_uid_exactly() {
        let runner = RunnerId::from_seed("registered");
        let policy = registry(&runner, 7);
        let (uid, _) = ids();
        policy.admit_runner(&runner, 7, uid).expect("exact peer");
        assert!(policy.admit_runner(&runner, 8, uid).is_err());
        assert!(policy
            .admit_runner(&runner, 7, uid.wrapping_add(1))
            .is_err());
        assert!(policy
            .admit_runner(&RunnerId::from_seed("spoof"), 7, uid)
            .is_err());
    }

    #[tokio::test]
    async fn listener_descriptor_detects_path_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(PARENT_MODE))
            .expect("0710");
        let runner = RunnerId::from_seed("replacement");
        let policy = registry(&runner, 1);
        let socket = root.path().join("lease.sock");
        let (listener, bound) = bind_admitted_socket(&socket, &policy).expect("bind");
        let client = UnixStream::connect(&socket)
            .await
            .expect("connect original");
        let (accepted, _) = listener.accept().await.expect("accept original");
        std::fs::remove_file(&socket).expect("unlink in isolated tempdir");
        let replacement = UnixListener::bind(&socket).expect("replacement");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE))
            .expect("0660");
        assert_eq!(
            admit_peer(&socket, &listener, &bound, &accepted)
                .expect_err("replacement must refuse")
                .kind(),
            ErrorKind::PermissionDenied
        );
        drop(client);
        drop(replacement);
    }

    #[test]
    fn bind_refuses_wrong_parent_mode_and_existing_symlink_without_removal() {
        let root = tempfile::tempdir().expect("tempdir");
        let runner = RunnerId::from_seed("path-hostiles");
        let policy = registry(&runner, 1);
        let relative = Path::new("relative-peercred-test.sock");
        assert_eq!(
            bind_admitted_socket(relative, &policy)
                .expect_err("relative path must refuse before bind")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert!(
            !relative.exists(),
            "relative refusal must not create a socket"
        );
        let missing = root.path().join("missing").join("lease.sock");
        assert!(bind_admitted_socket(&missing, &policy).is_err());
        assert!(
            !missing.exists(),
            "missing-parent refusal must not create a socket"
        );
        let socket = root.path().join("lease.sock");
        assert_eq!(
            bind_admitted_socket(&socket, &policy)
                .expect_err("0700 parent must refuse")
                .kind(),
            ErrorKind::InvalidInput
        );
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(PARENT_MODE))
            .expect("0710");
        let (uid, gid) = ids();
        let wrong_owner = LeasePeerRegistry::new(
            uid.wrapping_add(1),
            gid,
            [RegisteredRunnerPeer::new(runner.clone(), 1, uid)],
        )
        .expect("wrong-owner registry");
        assert_eq!(
            bind_admitted_socket(&socket, &wrong_owner)
                .expect_err("wrong registered owner must refuse")
                .kind(),
            ErrorKind::PermissionDenied
        );
        symlink(root.path().join("missing"), &socket).expect("symlink");
        assert_eq!(
            bind_admitted_socket(&socket, &policy)
                .expect_err("existing symlink must refuse")
                .kind(),
            ErrorKind::AlreadyExists
        );
        assert!(std::fs::symlink_metadata(&socket)
            .expect("symlink preserved")
            .file_type()
            .is_symlink());
    }
}
