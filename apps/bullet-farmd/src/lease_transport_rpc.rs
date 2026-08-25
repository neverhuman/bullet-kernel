//! Farmd-internal Unix JSON-RPC for Kernel-minted lease transport.
//!
//! Not a public `/v1` route. The operator signing key stays in this process.
//! The Runner authenticates by Unix peer credentials and a hello binding.

use crate::api::SharedState;
use bullet_application::lease_transport::{
    KernelLeaseTransport, SignedAcquireBody, SignedAdvanceBody, SignedHeartbeatBody,
    SignedLeaseError, SignedReleaseBody,
};
use bullet_application::{LeaseGrant, LeaseService, Ledger, StoredGraph};
use bullet_domain::{RunnerId, VariantId, WorkPackageId};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";
const HELLO_MAX: usize = 4_096;
const REQUEST_MAX: usize = 65_536;

/// Bind an admitted socket and serve Kernel-minted lease operations.
///
/// # Errors
///
/// Socket admission or accept failure.
pub async fn serve(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
) -> Result<(), Error> {
    let listener = bind_admitted_socket(&socket)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let transport = Arc::clone(&transport);
        tokio::spawn(async move {
            if let Err(error) = handle(stream, state, transport).await {
                tracing::warn!("lease-transport session: {error}");
            }
        });
    }
}

fn bind_admitted_socket(path: &Path) -> Result<UnixListener, Error> {
    let parent = path.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "lease-transport socket needs a parent directory",
        )
    })?;
    let meta = std::fs::metadata(parent)?;
    if !meta.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be a directory",
        ));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be mode 0700",
        ));
    }
    let self_uid = std::fs::metadata("/proc/self")
        .map(|info| info.uid())
        .unwrap_or(u32::MAX);
    if meta.uid() != self_uid {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "lease-transport parent must be owned by the farmd effective user",
        ));
    }
    if path.exists() {
        let existing = std::fs::metadata(path)?;
        if !existing.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "refusing to unlink a non-socket lease-transport path",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn handle(
    mut stream: UnixStream,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
) -> Result<(), Error> {
    let hello: Hello = serde_json::from_slice(&read_line(&mut stream, HELLO_MAX).await?)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    if hello.proto != PROTO {
        return write_err(
            &mut stream,
            None,
            "LEASE_TRANSPORT_INVALID",
            "unsupported proto",
        )
        .await;
    }
    let runner_id = RunnerId::parse(&hello.runner_id)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
    write_json(
        &mut stream,
        &HelloAck {
            ok: true,
            proto: PROTO,
        },
    )
    .await?;
    loop {
        let bytes = match read_line(&mut stream, REQUEST_MAX).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let request: RpcRequest = serde_json::from_slice(&bytes)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        dispatch(
            &mut stream,
            &state,
            &transport,
            &runner_id,
            hello.runner_epoch,
            request,
        )
        .await?;
    }
}

async fn dispatch(
    stream: &mut UnixStream,
    state: &SharedState,
    transport: &KernelLeaseTransport,
    hello_runner: &RunnerId,
    hello_epoch: u64,
    request: RpcRequest,
) -> Result<(), Error> {
    let now = unix_ms();
    let mut ledger = state.ledger.lock().await;
    let result = match request.method.as_str() {
        "acquire" => {
            let body: SignedAcquireBody = parse_params(&request)?;
            if body.runner_id != *hello_runner || body.runner_epoch != hello_epoch {
                return write_err(
                    stream,
                    request.id,
                    "LEASE_TRANSPORT_SUBJECT_MISMATCH",
                    "hello",
                )
                .await;
            }
            map_grant(
                transport.acquire(&mut *ledger, &body, now),
                &*ledger,
                &body.work_package_id,
            )
        }
        "readback" => {
            let body: SignedAcquireBody = parse_params(&request)?;
            if body.runner_id != *hello_runner || body.runner_epoch != hello_epoch {
                return write_err(
                    stream,
                    request.id,
                    "LEASE_TRANSPORT_SUBJECT_MISMATCH",
                    "hello",
                )
                .await;
            }
            map_grant(
                transport.readback(&mut *ledger, &body, now),
                &*ledger,
                &body.work_package_id,
            )
        }
        "heartbeat" => {
            let body: SignedHeartbeatBody = parse_params(&request)?;
            if body.call.runner_id != *hello_runner || body.call.runner_epoch != hello_epoch {
                return write_err(
                    stream,
                    request.id,
                    "LEASE_TRANSPORT_SUBJECT_MISMATCH",
                    "hello",
                )
                .await;
            }
            map_unit(transport.heartbeat(&mut *ledger, &body, now))
        }
        "release" => {
            let body: SignedReleaseBody = parse_params(&request)?;
            if body.runner_id != *hello_runner || body.runner_epoch != hello_epoch {
                return write_err(
                    stream,
                    request.id,
                    "LEASE_TRANSPORT_SUBJECT_MISMATCH",
                    "hello",
                )
                .await;
            }
            map_unit(transport.release(&mut *ledger, &body, now))
        }
        "advance" => {
            let body: SignedAdvanceBody = parse_params(&request)?;
            if body.runner_id != *hello_runner || body.runner_epoch != hello_epoch {
                return write_err(
                    stream,
                    request.id,
                    "LEASE_TRANSPORT_SUBJECT_MISMATCH",
                    "hello",
                )
                .await;
            }
            map_json(transport.advance(&mut *ledger, &body, now))
        }
        "next_ready" => next_ready(&*ledger),
        other => {
            return write_err(
                stream,
                request.id,
                "LEASE_TRANSPORT_INVALID",
                &format!("unknown method {other}"),
            )
            .await;
        }
    };
    match result {
        Ok(value) => {
            write_json(
                stream,
                &RpcOk {
                    id: request.id,
                    result: value,
                },
            )
            .await
        }
        Err((code, message)) => write_err(stream, request.id, code, &message).await,
    }
}

fn next_ready(ledger: &dyn Ledger) -> Result<serde_json::Value, (&'static str, String)> {
    let Some(row) = ledger
        .ready_rows()
        .map_err(|err| (err.reason_code(), err.to_string()))?
        .into_iter()
        .next()
    else {
        return Ok(serde_json::Value::Null);
    };
    let mut found = None;
    for mission in ledger
        .list_missions()
        .map_err(|err| (err.reason_code(), err.to_string()))?
    {
        let Some(graph) = ledger
            .get_graph(&mission.id)
            .map_err(|err| (err.reason_code(), err.to_string()))?
        else {
            continue;
        };
        if let Some(variant) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == row.work_package_id)
        {
            let title = graph
                .packages
                .iter()
                .find(|package| package.id == row.work_package_id)
                .map(|package| package.title.clone())
                .unwrap_or_default();
            found = Some(serde_json::json!({
                "work_package_id": row.work_package_id.to_string(),
                "mission_id": graph.mission.id.to_string(),
                "variant_id": variant.id.to_string(),
                "title": title,
                "enqueued_at": row.enqueued_at,
            }));
            break;
        }
    }
    Ok(found.unwrap_or(serde_json::Value::Null))
}

fn parse_params<T: for<'de> Deserialize<'de>>(request: &RpcRequest) -> Result<T, Error> {
    serde_json::from_value(request.params.clone())
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))
}

fn map_grant(
    result: Result<LeaseGrant, SignedLeaseError>,
    ledger: &dyn Ledger,
    package: &WorkPackageId,
) -> Result<serde_json::Value, (&'static str, String)> {
    let grant = result.map_err(|error| (error.reason_code(), error.to_string()))?;
    let (graph, _) = graph_for_package(ledger, package)?.ok_or((
        "NOT_FOUND",
        format!("work package {package} not in any graph"),
    ))?;
    let token = LeaseService::token_for(&graph, &grant.attempt)
        .map_err(|err| (err.reason_code(), err.to_string()))?;
    serde_json::to_value(serde_json::json!({
        "attempt": grant.attempt,
        "authority_token": token,
        "lease": grant.lease,
    }))
    .map_err(|err| ("ENCODING", err.to_string()))
}

fn graph_for_package(
    ledger: &dyn Ledger,
    package: &WorkPackageId,
) -> Result<Option<(StoredGraph, VariantId)>, (&'static str, String)> {
    for mission in ledger
        .list_missions()
        .map_err(|err| (err.reason_code(), err.to_string()))?
    {
        let Some(graph) = ledger
            .get_graph(&mission.id)
            .map_err(|err| (err.reason_code(), err.to_string()))?
        else {
            continue;
        };
        if let Some(variant_id) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == *package)
            .map(|variant| variant.id.clone())
        {
            return Ok(Some((graph, variant_id)));
        }
    }
    Ok(None)
}

fn map_json<T: Serialize>(
    result: Result<T, SignedLeaseError>,
) -> Result<serde_json::Value, (&'static str, String)> {
    match result {
        Ok(value) => serde_json::to_value(value).map_err(|err| ("ENCODING", err.to_string())),
        Err(error) => Err((error.reason_code(), error.to_string())),
    }
}

fn map_unit(
    result: Result<(), SignedLeaseError>,
) -> Result<serde_json::Value, (&'static str, String)> {
    match result {
        Ok(()) => Ok(serde_json::json!({"ok": true})),
        Err(error) => Err((error.reason_code(), error.to_string())),
    }
}

async fn read_line(stream: &mut UnixStream, max: usize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= max {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "lease-transport line too long",
            ));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "lease-transport eof"));
        }
        if byte[0] == b'\n' {
            return Ok(buf);
        }
        buf.push(byte[0]);
    }
}

async fn write_json<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), Error> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

async fn write_err(
    stream: &mut UnixStream,
    id: Option<u64>,
    code: &str,
    message: &str,
) -> Result<(), Error> {
    write_json(
        stream,
        &RpcErr {
            id,
            error: RpcErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        },
    )
    .await
}

fn unix_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

#[derive(Deserialize)]
struct Hello {
    proto: String,
    runner_id: String,
    runner_epoch: u64,
}

#[derive(Serialize)]
struct HelloAck {
    ok: bool,
    proto: &'static str,
}

#[derive(Deserialize)]
struct RpcRequest {
    id: Option<u64>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct RpcOk {
    id: Option<u64>,
    result: serde_json::Value,
}

#[derive(Serialize)]
struct RpcErr {
    id: Option<u64>,
    error: RpcErrorBody,
}

#[derive(Serialize)]
struct RpcErrorBody {
    code: String,
    message: String,
}
