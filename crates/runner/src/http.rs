//! Minimal loopback HTTP/1.1 JSON client over `tokio::net::TcpStream`.
//! One connection per request (`Connection: close`); enough for the farmd
//! lease API without adding an HTTP client dependency.

use crate::error::RunnerError;
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// JSON-over-HTTP client bound to one `http://host:port` base.
#[derive(Clone, Debug)]
pub struct HttpJson {
    authority: String,
}

impl HttpJson {
    /// Parse a base URL. Only plain `http://host:port` is supported.
    ///
    /// # Errors
    ///
    /// Returns `PROTOCOL_ERROR` for any other URL shape.
    pub fn new(base: &str) -> Result<Self, RunnerError> {
        let rest = base.strip_prefix("http://").ok_or_else(|| {
            RunnerError::Protocol(format!("only http:// loopback bases are supported: {base}"))
        })?;
        let authority = rest.trim_end_matches('/').to_string();
        if authority.is_empty() || authority.contains('/') {
            return Err(RunnerError::Protocol(format!(
                "base must be http://host:port with no path: {base}"
            )));
        }
        Ok(Self { authority })
    }

    /// POST a JSON body. Returns status and decoded body (Null when empty).
    ///
    /// # Errors
    ///
    /// Returns IO or protocol failures. HTTP error statuses are not errors.
    pub async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), RunnerError> {
        self.request("POST", path, Some(body)).await
    }

    /// GET a JSON resource. Returns status and decoded body (Null when empty).
    ///
    /// # Errors
    ///
    /// Returns IO or protocol failures. HTTP error statuses are not errors.
    pub async fn get(&self, path: &str) -> Result<(u16, Value), RunnerError> {
        self.request("GET", path, None).await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), RunnerError> {
        let io = |context: &str, reason: String| RunnerError::Io {
            context: format!("{context} {method} {path}"),
            reason,
        };
        let mut stream = TcpStream::connect(&self.authority)
            .await
            .map_err(|err| io("connect", err.to_string()))?;
        let payload = body.map(Value::to_string).unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.authority,
            payload.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|err| io("write", err.to_string()))?;
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|err| io("write", err.to_string()))?;
        let mut raw = Vec::new();
        tokio::time::timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut raw))
            .await
            .map_err(|_| io("read", "timeout".into()))?
            .map_err(|err| io("read", err.to_string()))?;
        parse_response(&raw)
    }
}

fn parse_response(raw: &[u8]) -> Result<(u16, Value), RunnerError> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| RunnerError::Protocol("http response without header break".into()))?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| RunnerError::Protocol(format!("bad status line: {head:.60}")))?;
    let chunked = head
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked");
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_string()
    };
    if body.trim().is_empty() {
        return Ok((status, Value::Null));
    }
    let value: Value = serde_json::from_str(body.trim())
        .map_err(|err| RunnerError::Protocol(format!("non-json body (status {status}): {err}")))?;
    Ok((status, value))
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size_line, tail)) = rest.split_once("\r\n") else {
            return out;
        };
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            return out;
        };
        if size == 0 || tail.len() < size {
            return out;
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].trim_start_matches("\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_shapes_are_validated() {
        assert!(HttpJson::new("http://127.0.0.1:7420").is_ok());
        assert!(HttpJson::new("http://127.0.0.1:7420/").is_ok());
        for bad in ["https://x", "127.0.0.1:1", "http://", "http://h:1/v1"] {
            assert!(HttpJson::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_and_chunked_bodies_parse() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(plain).unwrap(), (200, serde_json::json!({})));
        let chunked =
            b"HTTP/1.1 409 Conflict\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(chunked).unwrap(),
            (409, serde_json::json!({}))
        );
        let empty = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse_response(empty).unwrap(), (204, Value::Null));
    }
}
