use crate::error::RunnerError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const LINE_MAX: usize = 65_536;

pub(super) fn validate_server_uid(expected: u32, observed: u32) -> Result<(), RunnerError> {
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
pub(super) struct HelloAck {
    pub(super) ok: bool,
    pub(super) proto: String,
    pub(super) peer_uid: u32,
    pub(super) peer_gid: u32,
    pub(super) peer_pid: i32,
    pub(super) socket_dev: u64,
    pub(super) socket_ino: u64,
    pub(super) listener_dev: u64,
    pub(super) listener_ino: u64,
}

pub(super) async fn write_line(
    stream: &mut UnixStream,
    value: &impl Serialize,
) -> Result<(), RunnerError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|err| io_err("lease-transport encode", &err.to_string()))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .await
        .map_err(|err| io_err("lease-transport write", &err.to_string()))
}

pub(super) async fn read_json<R: DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<R, RunnerError> {
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

pub(super) fn io_err(context: &str, reason: &str) -> RunnerError {
    RunnerError::Io {
        context: context.into(),
        reason: reason.into(),
    }
}

pub(super) fn rpc_err(code: &str, message: &str) -> RunnerError {
    RunnerError::Lease {
        code: code.into(),
        message: message.into(),
    }
}
