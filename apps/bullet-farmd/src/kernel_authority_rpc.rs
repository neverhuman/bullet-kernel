//! Unix JSON-RPC for production gitd Kernel-permit mint/check/settle.
//!
//! Not a public `/api/v1` route. Public `/v1/leases/*` stay absent.

use crate::api::SharedState;
use crate::kernel_authority::{
    token_attempt_id, AuthenticatedCandidatePreparation, CheckParams, KernelAuthority, MintParams,
    SettleParams,
};
use bullet_application::candidate_preparation::{
    CandidateNonceConsumption, CandidatePreparationFinalCheckStore,
};
use bullet_application::{ActiveLeaseSubject, Ledger};
use bullet_domain::AttemptId;
use serde::Deserialize;
use serde_json::Value;
use std::io::{Error, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const PROTO: &str = "bullet-farm.kernel-authority.rpc.v1";
const LINE_MAX: usize = 65_536;
const SOCKET_MODE: u32 = 0o660;

/// Serve mint/check/settle on one absolute Unix socket.
///
/// # Errors
///
/// Bind or accept failure.
pub async fn serve(
    socket: PathBuf,
    state: SharedState,
    authority: Arc<KernelAuthority>,
    farmd_uid: u32,
) -> Result<(), Error> {
    if !socket.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "kernel authority socket must be an absolute path",
        ));
    }
    if socket.exists() {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "refusing to replace an existing kernel authority path",
        ));
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let peer = rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|error| Error::from_raw_os_error(error.raw_os_error()))?;
        if peer.uid.as_raw() != farmd_uid {
            tracing::warn!("kernel-authority peer UID refused");
            continue;
        }
        let state = Arc::clone(&state);
        let authority = Arc::clone(&authority);
        tokio::spawn(async move {
            if let Err(error) = handle(&mut stream, &state, &authority).await {
                tracing::warn!("kernel-authority session: {error}");
            }
        });
    }
}

async fn handle(
    stream: &mut tokio::net::UnixStream,
    state: &SharedState,
    authority: &KernelAuthority,
) -> Result<(), Error> {
    let request: RpcRequest = read_json(stream).await?;
    if request.proto != PROTO {
        return write_err(
            stream,
            request.id,
            "LEASE_TRANSPORT_INVALID",
            "unsupported proto",
        )
        .await;
    }
    let now = request.now_unix_ms;
    let result = match request.method.as_str() {
        "mint" => {
            let body: MintParams = parse_params(&request.params)?;
            let subject = match online_subject(state, &body.authority).await {
                Ok(subject) => subject,
                Err((code, message)) => {
                    return write_err(stream, request.id, &code, &message).await
                }
            };
            map_json(authority.mint(&subject, &body, now))
        }
        "check" => {
            let body: CheckParams = parse_params(&request.params)?;
            let subject = match online_subject(state, &body.authority).await {
                Ok(subject) => subject,
                Err((code, message)) => {
                    return write_err(stream, request.id, &code, &message).await
                }
            };
            match authority.check(&subject, &body, now) {
                Ok(checked) => {
                    let candidate = match authority.authenticate_candidate_preparation(&body) {
                        Ok(candidate) => candidate,
                        Err(error) => {
                            return write_err(stream, request.id, &error.0, &error.1).await
                        }
                    };
                    if let Some(candidate) = candidate {
                        if let Err((code, message)) =
                            final_check_candidate(state, &subject, &candidate).await
                        {
                            return write_err(stream, request.id, &code, &message).await;
                        }
                    }
                    map_json(Ok(checked))
                }
                Err(error) => Err(error),
            }
        }
        "settle" => {
            let body: SettleParams = parse_params(&request.params)?;
            map_json(authority.settle(&body))
        }
        other => {
            return write_err(
                stream,
                request.id,
                "AUTHORITY_REFUSED",
                &format!("unknown kernel authority method {other}"),
            )
            .await
        }
    };
    match result {
        Ok(value) => {
            write_json(
                stream,
                &serde_json::json!({"proto": PROTO, "id": request.id, "result": value}),
            )
            .await
        }
        Err((code, message)) => write_err(stream, request.id, &code, &message).await,
    }
}

async fn final_check_candidate(
    state: &SharedState,
    subject: &ActiveLeaseSubject,
    candidate: &AuthenticatedCandidatePreparation,
) -> Result<(), (String, String)> {
    let mut ledger = state.ledger.lock().await;
    let outcome = ledger
        .final_check_candidate_preparation_grant(
            &candidate.claims,
            &candidate.signed,
            &subject.attempt_id,
        )
        .map_err(|error| (error.reason_code().to_owned(), error.to_string()))?;
    match outcome {
        CandidateNonceConsumption::Consumed => Ok(()),
        CandidateNonceConsumption::Replayed => Err((
            "CANDIDATE_PREPARATION_REPLAYED".to_owned(),
            "Candidate-preparation grant was already consumed".to_owned(),
        )),
        CandidateNonceConsumption::Expired => Err((
            "CANDIDATE_PREPARATION_EXPIRED".to_owned(),
            "Candidate-preparation grant expired before final check".to_owned(),
        )),
        CandidateNonceConsumption::Unknown => Err((
            "CANDIDATE_PREPARATION_REFUSED".to_owned(),
            "Candidate-preparation grant differs from current authority".to_owned(),
        )),
    }
}

async fn online_subject(
    state: &SharedState,
    authority: &Value,
) -> Result<ActiveLeaseSubject, (String, String)> {
    let attempt_id = token_attempt_id(authority)?;
    let parsed = AttemptId::parse(&attempt_id)
        .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
    let mut ledger = state.ledger.lock().await;
    let attempt = ledger
        .get_attempt(&parsed)
        .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?
        .ok_or_else(|| {
            (
                "AUTHORITY_REFUSED".into(),
                "attempt not found for Kernel lease/fence read-back".into(),
            )
        })?;
    let subject = ActiveLeaseSubject::from_attempt(&attempt);
    ledger.check_active_lease(&subject).map_err(|error| {
        (
            "AUTHORITY_REFUSED".into(),
            format!("online lease/fence read-back refused: {error}"),
        )
    })?;
    Ok(subject)
}

fn parse_params<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, Error> {
    serde_json::from_value(value.clone()).map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

fn map_json<T: serde::Serialize>(
    result: Result<T, (String, String)>,
) -> Result<Value, (String, String)> {
    match result {
        Ok(value) => serde_json::to_value(value)
            .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string())),
        Err(error) => Err(error),
    }
}

async fn write_json(
    stream: &mut tokio::net::UnixStream,
    value: &impl serde::Serialize,
) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

async fn write_err(
    stream: &mut tokio::net::UnixStream,
    id: u64,
    code: &str,
    message: &str,
) -> Result<(), Error> {
    write_json(
        stream,
        &serde_json::json!({
            "proto": PROTO,
            "id": id,
            "error": {"code": code, "message": message},
        }),
    )
    .await
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    stream: &mut tokio::net::UnixStream,
) -> Result<T, Error> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= LINE_MAX {
            return Err(Error::new(ErrorKind::InvalidData, "line too long"));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "eof"));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    proto: String,
    id: u64,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    now_unix_ms: u64,
}
