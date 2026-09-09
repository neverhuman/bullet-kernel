//! Mint a Kernel one-use permit for a production gitd call.
//!
//! The runner does not depend on `bullet-gitd`. The fingerprint domain
//! matches gitd's pre-contract request framing.

use crate::error::RunnerError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ENV_SOCKET: &str = "BULLET_KERNEL_AUTHORITY_SOCKET";
const PROTO: &str = "bullet-farm.kernel-authority.rpc.v1";
const LINE_MAX: usize = 65_536;
const FINGERPRINT_DOMAIN: &[u8] = b"bullet-gitd.pre-contract-request-fingerprint.v1";

/// Attach a freshly minted Kernel permit when the authority socket is set.
pub(crate) fn admit_token(
    method: &str,
    token: &Value,
    params: &Value,
) -> Result<Value, RunnerError> {
    let Some(operation) = mutation_operation(method) else {
        return Ok(token.clone());
    };
    let Some(socket) = env::var_os(ENV_SOCKET).map(PathBuf::from) else {
        return Ok(token.clone());
    };
    let permit = mint_kernel_permit(&socket, operation, token, params)?;
    Ok(attach_kernel_permit(token.clone(), permit))
}

fn mutation_operation(method: &str) -> Option<&'static str> {
    match method {
        "clone" => Some("clone-workspace"),
        "apply_proposal" | "apply_change" => Some("apply-patch"),
        "checkpoint" => Some("checkpoint"),
        "prepare_candidate" => Some("prepare-candidate"),
        "preserve" => Some("preserve-workspace"),
        "cleanup" => Some("cleanup-workspace"),
        _ => None,
    }
}

fn attach_kernel_permit(mut authority: Value, permit: Value) -> Value {
    if let Value::Object(map) = &mut authority {
        map.insert("kernel_permit".into(), permit);
    }
    authority
}

fn authority_without_permit(authority: &Value) -> Value {
    match authority {
        Value::Object(map) => {
            let mut stripped = map.clone();
            stripped.remove("kernel_permit");
            Value::Object(stripped)
        }
        other => other.clone(),
    }
}

fn mint_kernel_permit(
    socket: &Path,
    operation: &str,
    authority: &Value,
    params: &Value,
) -> Result<Value, RunnerError> {
    let reply: MintReply = call(
        socket,
        "mint",
        &MintBody {
            operation: operation.to_string(),
            authority: authority_without_permit(authority),
            params: params.clone(),
        },
    )?;
    let _ = request_fingerprint(operation, &authority_without_permit(authority), params)?;
    Ok(reply.kernel_permit)
}

fn request_fingerprint(
    operation: &str,
    authority: &Value,
    params: &Value,
) -> Result<String, RunnerError> {
    let authority =
        serde_json::to_vec(authority).map_err(|error| RunnerError::Protocol(error.to_string()))?;
    let params =
        serde_json::to_vec(params).map_err(|error| RunnerError::Protocol(error.to_string()))?;
    let mut buf = Vec::new();
    for field in [
        FINGERPRINT_DOMAIN,
        operation.as_bytes(),
        &authority,
        &params,
    ] {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    Ok(bullet_domain::Digest::of(&buf).to_hex())
}

fn call<T: Serialize, R: for<'de> Deserialize<'de>>(
    socket: &Path,
    method: &str,
    params: &T,
) -> Result<R, RunnerError> {
    if !socket.is_absolute() {
        return Err(RunnerError::Protocol(
            "Kernel authority socket must be an absolute path".into(),
        ));
    }
    let mut stream = UnixStream::connect(socket).map_err(|error| RunnerError::Io {
        context: "kernel authority connect".into(),
        reason: error.to_string(),
    })?;
    write_line(
        &mut stream,
        &serde_json::json!({
            "proto": PROTO,
            "id": 1,
            "method": method,
            "params": params,
            "now_unix_ms": now_unix_ms()?,
        }),
    )?;
    let reply: Value = read_json(&mut stream)?;
    if let Some(error) = reply.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("AUTHORITY_REFUSED");
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Kernel authority refused");
        return Err(RunnerError::Gitd {
            method: method.to_string(),
            code: code.to_string(),
            message: message.to_string(),
        });
    }
    let result = reply.get("result").cloned().unwrap_or(Value::Null);
    serde_json::from_value(result).map_err(|error| RunnerError::Protocol(error.to_string()))
}

fn write_line(stream: &mut UnixStream, value: &impl Serialize) -> Result<(), RunnerError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| RunnerError::Protocol(error.to_string()))?;
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(|error| RunnerError::Io {
        context: "kernel authority write".into(),
        reason: error.to_string(),
    })
}

fn read_json<R: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<R, RunnerError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= LINE_MAX {
            return Err(RunnerError::Protocol(
                "Kernel authority line too long".into(),
            ));
        }
        let n = stream.read(&mut byte).map_err(|error| RunnerError::Io {
            context: "kernel authority read".into(),
            reason: error.to_string(),
        })?;
        if n == 0 {
            return Err(RunnerError::Protocol("Kernel authority eof".into()));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).map_err(|error| RunnerError::Protocol(error.to_string()))
}

fn now_unix_ms() -> Result<u64, RunnerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RunnerError::Protocol(error.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| RunnerError::Protocol("clock overflow".into()))
}

#[derive(Serialize)]
struct MintBody {
    operation: String,
    authority: Value,
    params: Value,
}

#[derive(Deserialize)]
struct MintReply {
    kernel_permit: Value,
}
