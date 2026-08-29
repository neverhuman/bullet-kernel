//! Production Runner client for Kernel-minted Unix lease transport.
//!
//! The client never holds `LeaseTransportSigningKey`. It admits only an
//! absolute service-group socket and authenticates the connected farmd peer;
//! public HTTP `/v1/leases/*` stays unmounted.

use crate::error::RunnerError;
use crate::lease::{
    AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient, ReadyView, ReleaseCall,
};
use async_trait::async_trait;
use bullet_application::lease_transport::{SignedAcquireBody, SignedHeartbeatBody};
use bullet_application::HeartbeatRequest;
use bullet_domain::{AttemptId, AttemptState, RunnerId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::net::UnixStream;

const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";
const SOCKET_MODE: u32 = 0o660;

mod acquire;
mod candidate;
mod command_dispatch;
mod recovery;
mod settlement;
mod support;
#[cfg(all(feature = "test-seams", debug_assertions))]
mod synthetic_selection;

pub use candidate::{
    CandidatePreparationAuthority, CandidatePreparationGrant, CandidatePreparationRpcClient,
};
use recovery::{load_recovery, persist_recovery, AcquireIntent, AcquireMeta, RecoveryJournal};
use support::*;

/// Expected identity of the farmd service and its shared socket group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedLeaseServer {
    uid: u32,
    socket_gid: u32,
}

impl ExpectedLeaseServer {
    /// Pin one farmd service UID and socket GID from trusted configuration.
    #[must_use]
    pub const fn new(uid: u32, socket_gid: u32) -> Self {
        Self { uid, socket_gid }
    }

    /// Pinned farmd service UID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Pinned socket GID.
    #[must_use]
    pub const fn socket_gid(self) -> u32 {
        self.socket_gid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Unix JSON-RPC client. No signing key is stored or accepted.
pub struct SignedLeaseRpcClient {
    socket: PathBuf,
    runner_id: RunnerId,
    runner_epoch: u64,
    expected_server: Option<ExpectedLeaseServer>,
    recovery_file: Option<PathBuf>,
    last: Mutex<RecoveryJournal>,
}

impl SignedLeaseRpcClient {
    /// Bind one socket and the hello runner identity.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, runner_id: RunnerId, runner_epoch: u64) -> Self {
        let journal = RecoveryJournal::new(runner_id.clone(), runner_epoch);
        Self {
            socket: socket.into(),
            runner_id,
            runner_epoch,
            expected_server: None,
            recovery_file: None,
            last: Mutex::new(journal),
        }
    }

    /// Bind the client to a farmd identity from trusted configuration.
    #[must_use]
    pub fn new_admitted(
        socket: impl Into<PathBuf>,
        runner_id: RunnerId,
        runner_epoch: u64,
        expected_server: ExpectedLeaseServer,
    ) -> Self {
        let journal = RecoveryJournal::new(runner_id.clone(), runner_epoch);
        Self {
            socket: socket.into(),
            runner_id,
            runner_epoch,
            expected_server: Some(expected_server),
            recovery_file: None,
            last: Mutex::new(journal),
        }
    }

    /// Persist and reload acquire metadata from one regular file.
    ///
    /// Process-local `last` is not admission. This only survives runner restart
    /// so heartbeat/advance/release can read back the exact acquire subject.
    /// Product CLI admission stays unavailable until durable registration exists.
    pub fn with_recovery_file(mut self, path: impl Into<PathBuf>) -> Result<Self, RunnerError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(rpc_err(
                "LEASE_RECOVERY_NOT_ABSOLUTE",
                "acquire recovery file must be an absolute path",
            ));
        }
        let loaded = load_recovery(&path, &self.runner_id, self.runner_epoch)?;
        *self
            .last
            .lock()
            .map_err(|_| io_err("lease-transport meta lock", "poisoned"))? = loaded;
        self.recovery_file = Some(path);
        Ok(self)
    }

    fn socket(&self) -> &Path {
        &self.socket
    }

    fn meta_for(&self, attempt_id: &AttemptId) -> Result<AcquireMeta, RunnerError> {
        self.last
            .lock()
            .map_err(|_| io_err("lease-transport meta lock", "poisoned"))?
            .intent_for(attempt_id)
            .ok_or_else(|| RunnerError::Lease {
                code: "LEASE_TRANSPORT_UNKNOWN".into(),
                message: format!("no signed acquire recorded for {attempt_id}"),
            })
    }

    fn admit_socket(&self) -> Result<SocketIdentity, RunnerError> {
        let expected_server = self.expected_server.ok_or_else(|| {
            rpc_err(
                "LEASE_SERVER_IDENTITY_UNCONFIGURED",
                "expected farmd UID/socket GID is not configured",
            )
        })?;
        let path = self.socket();
        if !path.is_absolute() {
            return Err(rpc_err(
                "LEASE_SOCKET_NOT_ABSOLUTE",
                "lease-transport socket must be an absolute path",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            rpc_err(
                "LEASE_SOCKET_PARENT",
                "lease-transport socket needs a parent directory",
            )
        })?;
        let canonical_parent = std::fs::canonicalize(parent).map_err(|err| {
            io_err(
                "lease-transport socket parent",
                &format!("{}: {err}", parent.display()),
            )
        })?;
        if canonical_parent != parent {
            return Err(rpc_err(
                "LEASE_SOCKET_PARENT",
                "lease-transport parent must be canonical and contain no symlink traversal",
            ));
        }
        let meta = std::fs::symlink_metadata(path).map_err(|err| {
            io_err(
                "lease-transport socket",
                &format!("{}: {err}", path.display()),
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(rpc_err(
                "LEASE_SOCKET_SYMLINK",
                "lease-transport path must not be a symlink",
            ));
        }
        if !meta.file_type().is_socket() {
            return Err(rpc_err(
                "LEASE_SOCKET_NOT_SOCKET",
                "lease-transport path is not a Unix socket",
            ));
        }
        if meta.permissions().mode() & 0o777 != SOCKET_MODE {
            return Err(rpc_err(
                "LEASE_SOCKET_MODE",
                "lease-transport socket must be mode 0660",
            ));
        }
        if meta.uid() != expected_server.uid {
            return Err(rpc_err(
                "LEASE_SOCKET_OWNER",
                "lease-transport socket owner does not match expected farmd UID",
            ));
        }
        if meta.gid() != expected_server.socket_gid {
            return Err(rpc_err(
                "LEASE_SOCKET_GROUP",
                "lease-transport socket group does not match expected socket GID",
            ));
        }
        Ok(SocketIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.permissions().mode() & 0o777,
        })
    }

    fn authenticate_connected_server(
        &self,
        stream: &UnixStream,
        before: SocketIdentity,
    ) -> Result<(), RunnerError> {
        let expected_server = self.expected_server.ok_or_else(|| {
            rpc_err(
                "LEASE_SERVER_IDENTITY_UNCONFIGURED",
                "expected farmd UID/socket GID is not configured",
            )
        })?;
        let peer = stream
            .peer_cred()
            .map_err(|err| io_err("lease-transport server peer credential", &err.to_string()))?;
        validate_server_uid(expected_server.uid, peer.uid())?;
        let after = self.admit_socket()?;
        if after != before {
            return Err(rpc_err(
                "LEASE_SOCKET_IDENTITY_DRIFT",
                "lease-transport socket identity changed during connect",
            ));
        }
        Ok(())
    }

    async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &T,
    ) -> Result<R, RunnerError> {
        let admitted = self.admit_socket()?;
        let mut stream = UnixStream::connect(self.socket())
            .await
            .map_err(|err| io_err("lease-transport connect", &err.to_string()))?;
        self.authenticate_connected_server(&stream, admitted)?;
        write_line(
            &mut stream,
            &serde_json::json!({
                "proto": PROTO,
                "runner_id": self.runner_id.as_str(),
                "runner_epoch": self.runner_epoch,
            }),
        )
        .await?;
        let hello: HelloAck = read_json(&mut stream).await?;
        if !hello.ok
            || hello.proto != PROTO
            || hello.socket_dev != admitted.dev
            || hello.socket_ino != admitted.ino
            || hello.listener_dev == 0
            || hello.listener_ino == 0
        {
            return Err(rpc_err(
                "LEASE_TRANSPORT_INVALID",
                "hello does not bind the admitted farmd socket",
            ));
        }
        let _observed_client = (hello.peer_uid, hello.peer_gid, hello.peer_pid);
        if self.admit_socket()? != admitted {
            return Err(rpc_err(
                "LEASE_SOCKET_IDENTITY_DRIFT",
                "lease-transport socket identity changed before request",
            ));
        }
        write_line(
            &mut stream,
            &serde_json::json!({
                "id": 1,
                "method": method,
                "params": params,
            }),
        )
        .await?;
        let reply: serde_json::Value = read_json(&mut stream).await?;
        if let Some(error) = reply.get("error") {
            return Err(rpc_err(
                error
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("LEASE_TRANSPORT_INVALID"),
                error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("lease-transport refused"),
            ));
        }
        let result = reply
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        serde_json::from_value(result)
            .map_err(|err| io_err("lease-transport decode", &err.to_string()))
    }

    #[cfg(test)]
    fn reserve_intent(&self, body: SignedAcquireBody) -> Result<(AcquireMeta, bool), RunnerError> {
        self.reserve_tagged_intent(AcquireIntent::ordinary(body))
    }

    fn reserve_tagged_intent(
        &self,
        intent: AcquireIntent,
    ) -> Result<(AcquireMeta, bool), RunnerError> {
        let body = intent.body().clone();
        self.mutate_recovery(|journal| {
            let is_new = journal.reserve_intent(intent)?;
            let attempt = AttemptId::from_seed(&body.idempotency_key);
            let meta = journal.intent_for(&attempt).ok_or_else(|| {
                rpc_err(
                    "LEASE_RECOVERY_CORRUPT",
                    "reserved acquire intent disappeared before request",
                )
            })?;
            Ok((meta, is_new))
        })
    }

    fn forget_intent(&self, body: &SignedAcquireBody) -> Result<(), RunnerError> {
        self.mutate_recovery(|journal| journal.forget(body))
    }

    fn record_acquire_grant(
        &self,
        body: &SignedAcquireBody,
        grant: AcquireGrant,
    ) -> Result<(), RunnerError> {
        self.mutate_recovery(|journal| journal.record_grant(body, grant))
    }

    fn mutate_recovery<T>(
        &self,
        mutation: impl FnOnce(&mut RecoveryJournal) -> Result<T, RunnerError>,
    ) -> Result<T, RunnerError> {
        let path = self.recovery_file.as_ref().ok_or_else(|| {
            rpc_err(
                "LEASE_RECOVERY_UNCONFIGURED",
                "durable lease recovery must be configured before authority use",
            )
        })?;
        let mut current = self
            .last
            .lock()
            .map_err(|_| io_err("lease-transport meta lock", "poisoned"))?;
        let mut next = current.clone();
        let result = mutation(&mut next)?;
        persist_recovery(path, &next)?;
        *current = next;
        Ok(result)
    }

    async fn active_readback(&self, meta: &AcquireMeta) -> Result<AcquireGrant, RunnerError> {
        self.call("readback_active", &meta.body).await
    }
}

#[async_trait]
impl LeaseClient for SignedLeaseRpcClient {
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        Some(self)
    }

    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let body = SignedAcquireBody {
            work_package_id: request.work_package_id.clone(),
            runner_id: request.runner_id.clone(),
            runner_epoch: request.runner_epoch,
            idempotency_key: request.idempotency_key.clone(),
            ttl_seconds: request.ttl_seconds,
        };
        self.reconcile_acquire(AcquireIntent::ordinary(body)).await
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        let meta = self.meta_for(&call.attempt_id)?;
        let ttl_seconds = meta.body.ttl_seconds;
        let body = SignedHeartbeatBody {
            work_package_id: meta.body.work_package_id,
            idempotency_key: meta.body.idempotency_key,
            call: HeartbeatRequest {
                variant_id: call.variant_id.clone(),
                attempt_id: call.attempt_id.clone(),
                fence: call.fence,
                runner_id: call.runner_id.clone(),
                runner_epoch: call.runner_epoch,
                workspace_nonce: call.workspace_nonce,
                ttl_seconds,
            },
        };
        let _: serde_json::Value = self.call("heartbeat", &body).await?;
        Ok(())
    }

    async fn advance(
        &self,
        attempt_id: &AttemptId,
        state: AttemptState,
    ) -> Result<(), RunnerError> {
        self.settle_advance(attempt_id, state).await
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        self.settle_release(call).await
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        self.call("next_ready", &serde_json::json!({})).await
    }
}

#[cfg(test)]
mod tests;
