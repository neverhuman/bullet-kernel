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
use bullet_application::lease_transport::{
    SignedAcquireBody, SignedAdvanceBody, SignedHeartbeatBody, SignedReleaseBody,
};
use bullet_application::{HeartbeatRequest, ReleaseRequest};
use bullet_domain::{AttemptId, AttemptState, RunnerId, WorkPackageId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";
const LINE_MAX: usize = 65_536;
const SOCKET_MODE: u32 = 0o660;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

struct AcquireMeta {
    work_package_id: WorkPackageId,
    idempotency_key: String,
    runner_id: RunnerId,
    runner_epoch: u64,
}

/// Unix JSON-RPC client. No signing key is stored or accepted.
pub struct SignedLeaseRpcClient {
    socket: PathBuf,
    runner_id: RunnerId,
    runner_epoch: u64,
    expected_server: Option<ExpectedLeaseServer>,
    last: Mutex<BTreeMap<String, AcquireMeta>>,
}

impl SignedLeaseRpcClient {
    /// Bind one socket and the hello runner identity.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, runner_id: RunnerId, runner_epoch: u64) -> Self {
        Self {
            socket: socket.into(),
            runner_id,
            runner_epoch,
            expected_server: None,
            last: Mutex::new(BTreeMap::new()),
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
        Self {
            socket: socket.into(),
            runner_id,
            runner_epoch,
            expected_server: Some(expected_server),
            last: Mutex::new(BTreeMap::new()),
        }
    }

    fn socket(&self) -> &Path {
        &self.socket
    }

    fn meta_for(&self, attempt_id: &AttemptId) -> Result<AcquireMeta, RunnerError> {
        self.last
            .lock()
            .map_err(|_| io_err("lease-transport meta lock", "poisoned"))?
            .get(attempt_id.as_str())
            .map(|meta| AcquireMeta {
                work_package_id: meta.work_package_id.clone(),
                idempotency_key: meta.idempotency_key.clone(),
                runner_id: meta.runner_id.clone(),
                runner_epoch: meta.runner_epoch,
            })
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
}

fn validate_server_uid(expected: u32, observed: u32) -> Result<(), RunnerError> {
    if observed == expected {
        Ok(())
    } else {
        Err(rpc_err(
            "LEASE_SERVER_UID_MISMATCH",
            "connected server UID does not match expected farmd UID",
        ))
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloAck {
    ok: bool,
    proto: String,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    socket_dev: u64,
    socket_ino: u64,
    listener_dev: u64,
    listener_ino: u64,
}

#[async_trait]
impl LeaseClient for SignedLeaseRpcClient {
    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let body = SignedAcquireBody {
            work_package_id: request.work_package_id.clone(),
            runner_id: request.runner_id.clone(),
            runner_epoch: request.runner_epoch,
            idempotency_key: request.idempotency_key.clone(),
            ttl_seconds: request.ttl_seconds,
        };
        let grant: AcquireGrant = self.call("acquire", &body).await?;
        self.last
            .lock()
            .map_err(|_| io_err("lease-transport meta lock", "poisoned"))?
            .insert(
                grant.attempt.id.to_string(),
                AcquireMeta {
                    work_package_id: request.work_package_id.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    runner_id: request.runner_id.clone(),
                    runner_epoch: request.runner_epoch,
                },
            );
        Ok(grant)
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        let meta = self.meta_for(&call.attempt_id)?;
        let body = SignedHeartbeatBody {
            work_package_id: meta.work_package_id,
            idempotency_key: meta.idempotency_key,
            call: HeartbeatRequest {
                variant_id: call.variant_id.clone(),
                attempt_id: call.attempt_id.clone(),
                fence: call.fence,
                runner_id: call.runner_id.clone(),
                runner_epoch: call.runner_epoch,
                workspace_nonce: call.workspace_nonce,
                ttl_seconds: call.ttl_seconds,
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
        let meta = self.meta_for(attempt_id)?;
        let body = SignedAdvanceBody {
            work_package_id: meta.work_package_id,
            runner_id: meta.runner_id,
            runner_epoch: meta.runner_epoch,
            idempotency_key: meta.idempotency_key,
            attempt_id: attempt_id.clone(),
            state,
        };
        let _: serde_json::Value = self.call("advance", &body).await?;
        Ok(())
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        let meta = self.meta_for(&call.attempt_id)?;
        let attempt: AcquireGrant = self
            .call(
                "readback",
                &SignedAcquireBody {
                    work_package_id: meta.work_package_id.clone(),
                    runner_id: meta.runner_id.clone(),
                    runner_epoch: meta.runner_epoch,
                    idempotency_key: meta.idempotency_key.clone(),
                    ttl_seconds: 15,
                },
            )
            .await
            .map_err(|_| RunnerError::Lease {
                code: "LEASE_TRANSPORT_UNKNOWN".into(),
                message: format!("no grant for {}", call.attempt_id),
            })?;
        let body = SignedReleaseBody {
            work_package_id: meta.work_package_id,
            runner_id: meta.runner_id,
            runner_epoch: meta.runner_epoch,
            idempotency_key: meta.idempotency_key,
            call: ReleaseRequest {
                variant_id: attempt.lease.variant_id,
                attempt_id: call.attempt_id.clone(),
                final_state: call.outcome,
                requeue: call.requeue,
            },
        };
        let _: serde_json::Value = self.call("release", &body).await?;
        Ok(())
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        self.call("next_ready", &serde_json::json!({})).await
    }
}

async fn write_line(stream: &mut UnixStream, value: &impl Serialize) -> Result<(), RunnerError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|err| io_err("lease-transport encode", &err.to_string()))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .await
        .map_err(|err| io_err("lease-transport write", &err.to_string()))
}

async fn read_json<R: DeserializeOwned>(stream: &mut UnixStream) -> Result<R, RunnerError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= LINE_MAX {
            return Err(io_err("lease-transport read", "line too long"));
        }
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|err| io_err("lease-transport read", &err.to_string()))?;
        if n == 0 {
            return Err(io_err("lease-transport read", "eof"));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).map_err(|err| io_err("lease-transport decode", &err.to_string()))
}

fn io_err(context: &str, reason: &str) -> RunnerError {
    RunnerError::Io {
        context: context.into(),
        reason: reason.into(),
    }
}

fn rpc_err(code: &str, message: &str) -> RunnerError {
    RunnerError::Lease {
        code: code.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
