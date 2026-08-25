//! Proxy wire mechanics: bounded request-head reading, the concurrency
//! guard, the upstream dial (the first and only place a name is resolved,
//! strictly after the allow decision), the refusal responder, and the relay.

use crate::proxy::Shared;
use crate::request::{
    ConnectTarget, RequestError, MAX_HEADER_LINES, MAX_HEAD_BYTES, MAX_REQUEST_LINE,
};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

pub(crate) struct TunnelGuard<'a> {
    shared: &'a Shared,
}

impl<'a> TunnelGuard<'a> {
    pub(crate) fn acquire(shared: &'a Shared) -> Option<Self> {
        let previous = shared.tunnels.fetch_add(1, Ordering::SeqCst);
        if previous >= shared.limits.max_tunnels {
            shared.tunnels.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self { shared })
    }
}

impl Drop for TunnelGuard<'_> {
    fn drop(&mut self) {
        self.shared.tunnels.fetch_sub(1, Ordering::SeqCst);
    }
}

/// First point at which a name is resolved: strictly after the allow decision.
pub(crate) fn connect_upstream(
    target: &ConnectTarget,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let addrs = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|err| format!("upstream-resolve:{}", err.kind()))?;
    let mut last = String::from("upstream-resolve:empty");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = format!("upstream-connect:{}", err.kind()),
        }
    }
    Err(last)
}

pub(crate) fn respond(client: &mut TcpStream, status: u16, extra_headers: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Refused",
    };
    let head =
        format!("HTTP/1.1 {status} {reason}\r\n{extra_headers}Connection: close\r\nContent-Length: 0\r\n\r\n");
    client.write_all(head.as_bytes())?;
    client.shutdown(Shutdown::Both)
}

pub(crate) fn relay(client: TcpStream, upstream: TcpStream, idle: Duration) {
    for stream in [&client, &upstream] {
        let _ = stream.set_read_timeout(Some(idle));
        let _ = stream.set_write_timeout(Some(idle));
    }
    let (Ok(client_rx), Ok(upstream_tx)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let uplink = thread::Builder::new()
        .name("bf-egress-up".into())
        .spawn(move || pump(client_rx, upstream_tx));
    pump(upstream, client);
    if let Ok(handle) = uplink {
        let _ = handle.join();
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Both);
    let _ = from.shutdown(Shutdown::Both);
}

/// Parsed request line of one head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    /// Method token exactly as sent (bounded).
    pub method: String,
    /// Request target exactly as sent (bounded).
    pub target: String,
    /// HTTP version token.
    pub version: String,
    /// Number of header lines that followed the request line.
    pub header_lines: usize,
}

/// Read one bounded request head. Returns the head and any bytes that
/// arrived after the head terminator (they belong to the tunnel).
///
/// # Errors
///
/// Returns the typed refusal for oversized, malformed, or truncated heads.
pub fn read_head<R: Read>(reader: &mut R) -> Result<(RequestHead, Vec<u8>), RequestError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some((head_end, body_start)) = find_terminator(&buf) {
            let head = parse_head(&buf[..head_end])?;
            return Ok((head, buf[body_start..].to_vec()));
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(RequestError::Oversized("head"));
        }
        if !buf.contains(&b'\n') && buf.len() > MAX_REQUEST_LINE {
            return Err(RequestError::Oversized("request-line"));
        }
        let n = reader
            .read(&mut chunk)
            .map_err(|err| RequestError::Io(err.kind().to_string()))?;
        if n == 0 {
            return Err(RequestError::Malformed("eof-before-head"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = buf.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(a), Some(b)) if b + 1 < a => Some((b, b + 2)),
        (Some(a), _) => Some((a, a + 4)),
        (None, Some(b)) => Some((b, b + 2)),
        (None, None) => None,
    }
}

/// Parse the bytes of one head (without the blank-line terminator).
///
/// # Errors
///
/// Returns `MethodNotAllowed` for any method other than `CONNECT`, `Oversized`
/// when a bound is exceeded, and `Malformed` for anything else unusable.
pub fn parse_head(head: &[u8]) -> Result<RequestHead, RequestError> {
    if head.iter().any(|b| *b == 0 || (*b >= 0x80)) {
        return Err(RequestError::Malformed("non-ascii-or-nul"));
    }
    let text = std::str::from_utf8(head).map_err(|_| RequestError::Malformed("utf8"))?;
    let mut lines = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let request_line = lines.next().unwrap_or_default();
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(RequestError::Oversized("request-line"));
    }
    let mut header_lines = 0usize;
    for line in lines {
        header_lines += 1;
        if header_lines > MAX_HEADER_LINES {
            return Err(RequestError::Oversized("headers"));
        }
        if line.bytes().any(|b| b < 0x20 && b != b'\t') {
            return Err(RequestError::Malformed("header-control-char"));
        }
    }
    if request_line.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(RequestError::Malformed("request-line-control-char"));
    }
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(RequestError::Malformed("request-line-shape"));
    };
    if method.is_empty() || target.is_empty() {
        return Err(RequestError::Malformed("request-line-shape"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError::Malformed("http-version"));
    }
    if method != "CONNECT" {
        let shown: String = method.chars().take(16).collect();
        return Err(RequestError::MethodNotAllowed(shown));
    }
    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        header_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_head_and_returns_leftover_bytes() {
        let mut input: &[u8] =
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n\x16\x03\x01";
        let (head, leftover) = read_head(&mut input).unwrap();
        assert_eq!(head.method, "CONNECT");
        assert_eq!(head.target, "api.anthropic.com:443");
        assert_eq!(head.version, "HTTP/1.1");
        assert_eq!(head.header_lines, 1);
        assert_eq!(leftover, b"\x16\x03\x01");
        let mut bare_lf: &[u8] = b"CONNECT a.example:443 HTTP/1.0\n\n";
        let (head, leftover) = read_head(&mut bare_lf).unwrap();
        assert_eq!(head.version, "HTTP/1.0");
        assert!(leftover.is_empty());
    }

    #[test]
    fn refuses_non_connect_methods_before_any_target_parsing() {
        let mut get: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        let err = read_head(&mut get).unwrap_err();
        assert_eq!(err, RequestError::MethodNotAllowed("GET".into()));
        assert_eq!(err.status(), 405);
        let mut lower: &[u8] = b"connect a.example:443 HTTP/1.1\r\n\r\n";
        assert!(matches!(
            read_head(&mut lower).unwrap_err(),
            RequestError::MethodNotAllowed(m) if m == "connect"
        ));
        let mut very_long: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA / HTTP/1.1\r\n\r\n";
        assert!(matches!(
            read_head(&mut very_long).unwrap_err(),
            RequestError::MethodNotAllowed(m) if m.len() == 16
        ));
    }

    #[test]
    fn refuses_malformed_heads() {
        let cases: [(&[u8], &str); 7] = [
            (
                b"CONNECT  a.example:443 HTTP/1.1\r\n\r\n",
                "request-line-shape",
            ),
            (b"CONNECT a.example:443\r\n\r\n", "request-line-shape"),
            (b"CONNECT a.example:443 HTTP/2\r\n\r\n", "http-version"),
            (
                b"CONNECT a.example:443 HTTP/1.1 extra\r\n\r\n",
                "request-line-shape",
            ),
            (
                b"CONNECT a.example:443 HTTP/1.1\r\nX: \x01\r\n\r\n",
                "header-control-char",
            ),
            (
                b"CONNECT a.ex\x00ample:443 HTTP/1.1\r\n\r\n",
                "non-ascii-or-nul",
            ),
            (
                b"CONNECT a.ex\xffample:443 HTTP/1.1\r\n\r\n",
                "non-ascii-or-nul",
            ),
        ];
        for (raw, reason) in cases {
            let mut input = raw;
            assert_eq!(
                read_head(&mut input).unwrap_err(),
                RequestError::Malformed(reason),
                "input {raw:?}"
            );
        }
        let mut truncated: &[u8] = b"CONNECT a.example:443 HTTP/1.1\r\n";
        assert_eq!(
            read_head(&mut truncated).unwrap_err(),
            RequestError::Malformed("eof-before-head")
        );
    }

    #[test]
    fn refuses_oversized_heads_without_reading_forever() {
        let line = format!(
            "CONNECT {}:443 HTTP/1.1\r\n\r\n",
            "a".repeat(MAX_REQUEST_LINE)
        );
        let mut input = line.as_bytes();
        let err = read_head(&mut input).unwrap_err();
        assert_eq!(err, RequestError::Oversized("request-line"));
        assert_eq!(err.status(), 431);
        let mut headers = String::from("CONNECT a.example:443 HTTP/1.1\r\n");
        for i in 0..(MAX_HEADER_LINES + 1) {
            headers.push_str(&format!("X-{i}: y\r\n"));
        }
        headers.push_str("\r\n");
        let mut input = headers.as_bytes();
        assert_eq!(
            read_head(&mut input).unwrap_err(),
            RequestError::Oversized("headers")
        );
        let endless = std::io::repeat(b'A');
        let mut endless = endless.take(u64::MAX);
        assert_eq!(
            read_head(&mut endless).unwrap_err(),
            RequestError::Oversized("request-line")
        );
        let mut big = String::from("CONNECT a.example:443 HTTP/1.1\r\n");
        while big.len() < MAX_HEAD_BYTES {
            big.push_str("X: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\r\n");
        }
        let mut input = big.as_bytes();
        assert!(matches!(
            read_head(&mut input).unwrap_err(),
            RequestError::Oversized(_)
        ));
    }
}
