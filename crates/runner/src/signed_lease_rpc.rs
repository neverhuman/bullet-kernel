//! Production Runner client for Kernel-minted Unix lease transport.
//!
//! The client never holds `LeaseTransportSigningKey`. Farmd authenticates
//! the process by peer credentials and mints the permit itself.

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
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";
const LINE_MAX: usize = 65_536;

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

    async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &T,
    ) -> Result<R, RunnerError> {
        let mut stream = UnixStream::connect(self.socket())
            .await
            .map_err(|err| io_err("lease-transport connect", &err.to_string()))?;
        write_line(
            &mut stream,
            &serde_json::json!({
                "proto": PROTO,
                "runner_id": self.runner_id.as_str(),
                "runner_epoch": self.runner_epoch,
            }),
        )
        .await?;
        let hello: serde_json::Value = read_json(&mut stream).await?;
        if hello.get("ok") != Some(&serde_json::Value::Bool(true)) {
            return Err(rpc_err("LEASE_TRANSPORT_INVALID", "hello refused"));
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
