//! Strict, bounded HTTP reads against the loopback farmd projection API.

use bullet_domain::MissionId;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_WIRE_BYTES: usize = 512 * 1024;
const SNAPSHOT_SOURCE: &str = "bullet-kernel/sqlite-ledger";

/// One validated loopback farmd endpoint.
#[derive(Clone, Debug)]
pub struct LoopbackFarmd {
    authority: String,
}

/// A read failure that cannot be converted into projection truth.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The MCP caller supplied an invalid shared-domain identifier.
    #[error("INVALID_INPUT: {0}")]
    InvalidInput(String),
    /// The configured endpoint is not exact loopback HTTP.
    #[error("INVALID_FARMD_ENDPOINT: {0}")]
    InvalidEndpoint(String),
    /// The bounded request could not complete.
    #[error("FARMD_UNAVAILABLE: {0}")]
    Unavailable(String),
    /// farmd answered with a non-success status.
    #[error("FARMD_REFUSED: HTTP {status}")]
    Refused {
        /// HTTP response status.
        status: u16,
    },
    /// farmd returned a malformed, oversized, or non-snapshot response.
    #[error("INVALID_FARMD_RESPONSE: {0}")]
    InvalidResponse(String),
}

impl LoopbackFarmd {
    /// Parse an exact `http://<numeric-loopback>:<port>` base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidEndpoint`] for hostnames, non-loopback
    /// addresses, paths, credentials, query strings, or fragments.
    pub fn new(base: &str) -> Result<Self, ClientError> {
        let authority = base.strip_prefix("http://").ok_or_else(|| {
            ClientError::InvalidEndpoint("only plain loopback http is supported".into())
        })?;
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@'])
            || authority.ends_with(':')
        {
            return Err(ClientError::InvalidEndpoint(
                "expected http://<numeric-loopback>:<port> with no path".into(),
            ));
        }
        let address: SocketAddr = authority.parse().map_err(|_| {
            ClientError::InvalidEndpoint(
                "expected an explicit numeric IP address and nonzero port".into(),
            )
        })?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(ClientError::InvalidEndpoint(
                "farmd endpoint must be a numeric loopback address with a nonzero port".into(),
            ));
        }
        Ok(Self {
            authority: authority.to_owned(),
        })
    }

    /// Read one of the fixed, argument-free Kernel projection routes.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if farmd is unavailable or if its response is
    /// not an exact sequence-bound snapshot.
    pub async fn read_projection(&self, route: ProjectionRoute) -> Result<Value, ClientError> {
        self.get(route.path()).await
    }

    /// Read one exact mission projection after validating the shared ID type.
    ///
    /// # Errors
    ///
    /// Returns a domain validation or bounded farmd response error.
    pub async fn read_mission(&self, mission_id: &str) -> Result<Value, ClientError> {
        let id = MissionId::parse(mission_id)
            .map_err(|error| ClientError::InvalidInput(format!("invalid mission id: {error}")))?;
        self.get(&format!("/api/v1/missions/{id}")).await
    }

    async fn get(&self, path: &str) -> Result<Value, ClientError> {
        debug_assert!(path.starts_with("/api/v1/"));
        let raw = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect(&self.authority),
            )
            .await
            .map_err(|_| ClientError::Unavailable("connect deadline elapsed".into()))?
            .map_err(|error| ClientError::Unavailable(format!("connect: {error}")))?;
            stream
                .set_nodelay(true)
                .map_err(|error| ClientError::Unavailable(format!("socket: {error}")))?;
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                self.authority
            );
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| ClientError::Unavailable(format!("write: {error}")))?;
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 8 * 1024];
            loop {
                let count = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|error| ClientError::Unavailable(format!("read: {error}")))?;
                if count == 0 {
                    break;
                }
                if raw.len().saturating_add(count) > MAX_WIRE_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "response exceeds the fixed wire limit".into(),
                    ));
                }
                raw.extend_from_slice(&chunk[..count]);
            }
            Ok(raw)
        })
        .await
        .map_err(|_| ClientError::Unavailable("request deadline elapsed".into()))??;

        let response = parse_http_response(&raw)?;
        if response.status != 200 {
            return Err(ClientError::Refused {
                status: response.status,
            });
        }
        validate_snapshot(&response)
    }
}

/// Fixed projection routes; callers cannot supply an arbitrary URL or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionRoute {
    /// Mission list.
    Missions,
    /// Fleet and ready queue.
    Fleet,
    /// Attempts and sessions.
    Sessions,
    /// Context lineage.
    ContextLineage,
    /// Candidate/effect state.
    MergeRail,
    /// Evidence state.
    QualityLab,
    /// Bounded durable audit tail.
    Audit,
}

impl ProjectionRoute {
    fn path(self) -> &'static str {
        match self {
            Self::Missions => "/api/v1/missions",
            Self::Fleet => "/api/v1/fleet",
            Self::Sessions => "/api/v1/sessions",
            Self::ContextLineage => "/api/v1/context-lineage",
            Self::MergeRail => "/api/v1/merge-rail",
            Self::QualityLab => "/api/v1/quality-lab",
            Self::Audit => "/api/v1/audit",
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, ClientError> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ClientError::InvalidResponse("missing HTTP header terminator".into()))?;
    if split > MAX_HEADER_BYTES {
        return Err(ClientError::InvalidResponse(
            "response headers exceed the fixed limit".into(),
        ));
    }
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| ClientError::InvalidResponse("response headers are not UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ClientError::InvalidResponse("missing status line".into()))?;
    let mut status_fields = status_line.split_whitespace();
    if status_fields.next() != Some("HTTP/1.1") {
        return Err(ClientError::InvalidResponse(
            "only HTTP/1.1 responses are accepted".into(),
        ));
    }
    let status = status_fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .ok_or_else(|| ClientError::InvalidResponse("invalid response status".into()))?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(ClientError::InvalidResponse(
                "folded response headers are forbidden".into(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ClientError::InvalidResponse("malformed response header".into()))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ClientError::InvalidResponse(
                "malformed response header name".into(),
            ));
        }
        let name = name.to_ascii_lowercase();
        if headers.insert(name, value.trim().to_owned()).is_some() {
            return Err(ClientError::InvalidResponse(
                "duplicate response header".into(),
            ));
        }
    }

    let encoded_body = &raw[split + 4..];
    let transfer_encoding = headers.get("transfer-encoding").map(String::as_str);
    let content_length = headers.get("content-length").map(String::as_str);
    let body = match (transfer_encoding, content_length) {
        (Some(_), Some(_)) => {
            return Err(ClientError::InvalidResponse(
                "ambiguous response body framing".into(),
            ));
        }
        (Some("chunked"), None) => decode_chunked(encoded_body)?,
        (Some(_), None) => {
            return Err(ClientError::InvalidResponse(
                "unsupported transfer encoding".into(),
            ));
        }
        (None, Some(value)) => {
            let expected = value
                .parse::<usize>()
                .map_err(|_| ClientError::InvalidResponse("invalid content length".into()))?;
            if expected != encoded_body.len() {
                return Err(ClientError::InvalidResponse(
                    "content length does not match response body".into(),
                ));
            }
            encoded_body.to_vec()
        }
        (None, None) => encoded_body.to_vec(),
    };
    if body.len() > MAX_BODY_BYTES {
        return Err(ClientError::InvalidResponse(
            "response body exceeds the fixed projection limit".into(),
        ));
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut encoded: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| ClientError::InvalidResponse("truncated chunk header".into()))?;
        let size = std::str::from_utf8(&encoded[..line_end])
            .ok()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or_else(|| ClientError::InvalidResponse("invalid chunk size".into()))?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            if encoded != b"\r\n" {
                return Err(ClientError::InvalidResponse(
                    "chunk trailers are not accepted".into(),
                ));
            }
            return Ok(decoded);
        }
        if size > MAX_BODY_BYTES.saturating_sub(decoded.len())
            || encoded.len() < size.saturating_add(2)
            || &encoded[size..size + 2] != b"\r\n"
        {
            return Err(ClientError::InvalidResponse(
                "invalid or oversized chunk body".into(),
            ));
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
}

fn validate_snapshot(response: &HttpResponse) -> Result<Value, ClientError> {
    let media_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return Err(ClientError::InvalidResponse(
            "projection content type is not application/json".into(),
        ));
    }
    let snapshot: Value = serde_json::from_slice(&response.body)
        .map_err(|error| ClientError::InvalidResponse(format!("non-JSON body: {error}")))?;
    let object = snapshot.as_object().ok_or_else(|| {
        ClientError::InvalidResponse("projection snapshot is not an object".into())
    })?;
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["as_of_sequence", "data", "observed_at", "source"] {
        return Err(ClientError::InvalidResponse(
            "projection snapshot fields do not match the public contract".into(),
        ));
    }
    let sequence = object
        .get("as_of_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| ClientError::InvalidResponse("snapshot sequence is invalid".into()))?;
    if object.get("observed_at").and_then(Value::as_str).is_none()
        || object.get("source").and_then(Value::as_str) != Some(SNAPSHOT_SOURCE)
    {
        return Err(ClientError::InvalidResponse(
            "snapshot provenance is invalid".into(),
        ));
    }
    let header_sequence = response
        .headers
        .get("x-bullet-as-of-sequence")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            ClientError::InvalidResponse("snapshot watermark header is absent".into())
        })?;
    if header_sequence != sequence {
        return Err(ClientError::InvalidResponse(
            "snapshot watermark header conflicts with the body".into(),
        ));
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_numeric_loopback_only() {
        for allowed in ["http://127.0.0.1:7420", "http://[::1]:7420"] {
            assert!(LoopbackFarmd::new(allowed).is_ok(), "{allowed}");
        }
        for denied in [
            "https://127.0.0.1:7420",
            "http://localhost:7420",
            "http://0.0.0.0:7420",
            "http://127.0.0.1:0",
            "http://127.0.0.1:7420/api/v1",
            "http://user@127.0.0.1:7420",
        ] {
            assert!(LoopbackFarmd::new(denied).is_err(), "{denied}");
        }
    }

    #[tokio::test]
    async fn mission_id_is_validated_before_network_access() {
        let client = LoopbackFarmd::new("http://127.0.0.1:9").unwrap();
        assert!(matches!(
            client.read_mission("../mission").await,
            Err(ClientError::InvalidInput(_))
        ));
    }

    #[test]
    fn response_requires_exact_watermarked_snapshot() {
        let body = br#"{"data":[],"as_of_sequence":7,"observed_at":"2026-08-25T00:00:00Z","source":"bullet-kernel/sqlite-ledger"}"#;
        let raw = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Bullet-As-Of-Sequence: 7\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat();
        let response = parse_http_response(&raw).expect("HTTP response");
        assert_eq!(validate_snapshot(&response).unwrap()["as_of_sequence"], 7);

        let conflicting = raw
            .windows(b"Sequence: 7".len())
            .position(|window| window == b"Sequence: 7")
            .map(|index| {
                let mut changed = raw.clone();
                *changed.last_mut().expect("body") = b'}';
                changed[index + b"Sequence: ".len()] = b'8';
                changed
            })
            .expect("header marker");
        let response = parse_http_response(&conflicting).expect("HTTP response");
        assert!(validate_snapshot(&response).is_err());

        let wrong_type = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Bullet-As-Of-Sequence: 7\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat();
        let response = parse_http_response(&wrong_type).expect("HTTP response");
        assert!(validate_snapshot(&response).is_err());
    }

    #[test]
    fn chunked_parser_is_bounded_and_exact() {
        assert_eq!(decode_chunked(b"2\r\n{}\r\n0\r\n\r\n").unwrap(), b"{}");
        for malformed in [
            b"2\r\n{}\r\n".as_slice(),
            b"x\r\n{}\r\n0\r\n\r\n".as_slice(),
            b"2;ext=x\r\n{}\r\n0\r\n\r\n".as_slice(),
            b"0\r\ntrailer: value\r\n\r\n".as_slice(),
        ] {
            assert!(decode_chunked(malformed).is_err());
        }
    }
}
