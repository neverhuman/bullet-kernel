//! Farmd-internal Unix JSON-RPC for Kernel-minted lease transport.
//!
//! Not a public `/api/v1` route. The operator signing key stays in this process.
//! Each accepted session is bound to `SO_PEERCRED` and the listening socket's
//! device/inode identity. Public `/v1/leases/*` stay absent.

mod candidate;
mod command_dispatch;
mod deadline;
mod operations;
mod peer;

pub use deadline::{
    TransportBounds, TransportRefusal, LEASE_TRANSPORT_BOUNDS_INVALID,
    LEASE_TRANSPORT_FRAME_TOO_LARGE, LEASE_TRANSPORT_OVERLOADED, LEASE_TRANSPORT_READ_DEADLINE,
    LEASE_TRANSPORT_SESSION_DEADLINE,
};
pub use peer::{LeasePeerRegistry, RegisteredRunnerPeer};

use crate::api::SharedState;
use bullet_application::candidate_preparation::CandidatePreparationSigningKey;
use bullet_application::lease_transport::KernelLeaseTransport;
use bullet_domain::RunnerId;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::unix::WriteHalf;

use deadline::{
    bounded_session, close_with_reason, read_frame, refuse_overloaded, session_halves, FrameReader,
    SessionSlots,
};
use peer::{admit_peer, admit_runner, bind_admitted_socket, BoundSocketIdentity, PeerCred};

const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";
const HELLO_MAX: usize = 4_096;

/// Bind an admitted socket and serve Kernel-minted lease operations under
/// [`TransportBounds::defaults`].
///
/// # Errors
///
/// Socket admission or accept failure.
pub async fn serve(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
) -> Result<(), Error> {
    serve_inner(
        socket,
        state,
        transport,
        registry,
        None,
        TransportBounds::defaults(),
    )
    .await
}

/// Serve lease operations plus durable Candidate preparation under the same
/// authenticated workload session.
///
/// # Errors
///
/// Socket admission or accept failure.
pub async fn serve_with_candidate(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
    candidate_key: Arc<CandidatePreparationSigningKey>,
) -> Result<(), Error> {
    serve_inner(
        socket,
        state,
        transport,
        registry,
        Some(candidate_key),
        TransportBounds::defaults(),
    )
    .await
}

/// [`serve`] under explicit [`TransportBounds`].
///
/// Every accepted session runs under `bounds`: one whole frame per
/// `read_deadline`, the whole session under `session_deadline`, no frame past
/// `max_line_bytes`, and at most `max_in_flight_sessions` sessions at once. A
/// peer that trips a bound gets one typed refusal frame and is closed; a peer
/// arriving when every slot is busy is refused at accept, never queued.
///
/// # Errors
///
/// `LEASE_TRANSPORT_BOUNDS_INVALID` for a zero bound (before binding), socket
/// admission or accept failure.
pub async fn serve_with_bounds(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
    bounds: TransportBounds,
) -> Result<(), Error> {
    serve_inner(socket, state, transport, registry, None, bounds).await
}

/// [`serve_with_candidate`] under explicit resource bounds.
///
/// # Errors
///
/// Invalid bounds, socket admission, or accept failure.
pub async fn serve_with_candidate_and_bounds(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
    candidate_key: Arc<CandidatePreparationSigningKey>,
    bounds: TransportBounds,
) -> Result<(), Error> {
    serve_inner(
        socket,
        state,
        transport,
        registry,
        Some(candidate_key),
        bounds,
    )
    .await
}

async fn serve_inner(
    socket: PathBuf,
    state: SharedState,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
    candidate_key: Option<Arc<CandidatePreparationSigningKey>>,
    bounds: TransportBounds,
) -> Result<(), Error> {
    let bounds = bounds.admitted()?;
    let (listener, bound) = bind_admitted_socket(&socket, &registry)?;
    let slots = SessionSlots::new(bounds);
    loop {
        let (mut stream, _) = listener.accept().await?;
        let peer = match admit_peer(&socket, &listener, &bound, &stream) {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!("lease-transport peer refused: {error}");
                continue;
            }
        };
        let permit = match slots.try_admit() {
            Ok(permit) => permit,
            Err(refusal) => {
                refuse_overloaded(stream, &refusal);
                continue;
            }
        };
        let state = Arc::clone(&state);
        let transport = Arc::clone(&transport);
        let registry = Arc::clone(&registry);
        let candidate_key = candidate_key.as_ref().map(Arc::clone);
        tokio::spawn(async move {
            let _slot = permit;
            let (mut reader, mut writer) = session_halves(&mut stream, bounds);
            let session = handle(
                &mut reader,
                &mut writer,
                &state,
                &transport,
                candidate_key.as_deref(),
                &registry,
                bound,
                peer,
                bounds,
            );
            if let Err(error) = bounded_session(bounds, session).await {
                match close_with_reason(&mut writer, bounds, &error).await {
                    Some(code) => tracing::warn!("lease-transport session closed: {code}: {error}"),
                    None => tracing::warn!("lease-transport session: {error}"),
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    reader: &mut FrameReader<'_>,
    stream: &mut WriteHalf<'_>,
    state: &SharedState,
    transport: &KernelLeaseTransport,
    candidate_key: Option<&CandidatePreparationSigningKey>,
    registry: &LeasePeerRegistry,
    bound: BoundSocketIdentity,
    peer: PeerCred,
    bounds: TransportBounds,
) -> Result<(), Error> {
    let hello_max = HELLO_MAX.min(bounds.max_line_bytes);
    let hello: Hello = serde_json::from_slice(&read_frame(reader, bounds, hello_max).await?)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    if hello.proto != PROTO {
        return write_err(stream, None, "LEASE_TRANSPORT_INVALID", "unsupported proto").await;
    }
    let runner_id = RunnerId::parse(&hello.runner_id)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
    if admit_runner(registry, &runner_id, hello.runner_epoch, &peer).is_err() {
        return write_err(
            stream,
            None,
            "LEASE_TRANSPORT_PEER_UNREGISTERED",
            "Runner ID/epoch is not registered for the connected peer UID",
        )
        .await;
    }
    write_json(
        stream,
        &HelloAck {
            ok: true,
            proto: PROTO,
            peer_uid: peer.uid,
            peer_gid: peer.gid,
            peer_pid: peer.pid,
            socket_dev: bound.socket_dev(),
            socket_ino: bound.socket_ino(),
            listener_dev: bound.listener_dev(),
            listener_ino: bound.listener_ino(),
        },
    )
    .await?;
    loop {
        let bytes = match read_frame(reader, bounds, bounds.max_line_bytes).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let request: RpcRequest = serde_json::from_slice(&bytes)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        dispatch(
            stream,
            state,
            transport,
            candidate_key,
            &runner_id,
            hello.runner_epoch,
            request,
        )
        .await?;
    }
}

async fn dispatch(
    stream: &mut WriteHalf<'_>,
    state: &SharedState,
    transport: &KernelLeaseTransport,
    candidate_key: Option<&CandidatePreparationSigningKey>,
    hello_runner: &RunnerId,
    hello_epoch: u64,
    request: RpcRequest,
) -> Result<(), Error> {
    let result = {
        // The lock is released before the response is written so a peer that
        // does not drain its socket cannot hold the ledger for other callers.
        let mut ledger = state.ledger.lock().await;
        if command_dispatch::is_method(&request.method) {
            command_dispatch::call(&mut ledger, hello_runner, hello_epoch, &request)
        } else if let Some(key) = candidate_key.filter(|_| candidate::is_method(&request.method)) {
            candidate::call(&mut ledger, key, hello_runner, hello_epoch, &request)
        } else {
            operations::call(&mut *ledger, transport, hello_runner, hello_epoch, &request)?
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

type CallResult = Result<serde_json::Value, (&'static str, String)>;

async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> Result<(), Error> {
    let bytes = encode_line(value)?;
    stream.write_all(&bytes).await
}

fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn encode_err(id: Option<u64>, code: &str, message: &str) -> Result<Vec<u8>, Error> {
    encode_line(&RpcErr {
        id,
        error: RpcErrorBody {
            code: code.to_string(),
            message: message.to_string(),
        },
    })
}

async fn write_err<W: AsyncWrite + Unpin>(
    stream: &mut W,
    id: Option<u64>,
    code: &str,
    message: &str,
) -> Result<(), Error> {
    let bytes = encode_err(id, code, message)?;
    stream.write_all(&bytes).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    proto: String,
    runner_id: String,
    runner_epoch: u64,
}

#[derive(Serialize)]
struct HelloAck {
    ok: bool,
    proto: &'static str,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    socket_dev: u64,
    socket_ino: u64,
    listener_dev: u64,
    listener_ino: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
