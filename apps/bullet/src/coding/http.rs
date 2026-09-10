//! Loopback HTTP/1.1 client for farmd coding and projection reads.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub(super) struct HttpResponse {
    pub(super) status: u16,
    pub(super) body: Value,
    pub(super) set_cookie: Option<String>,
}

pub(super) fn request(
    farmd: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Result<HttpResponse, String> {
    let (host, port) = parse_loopback(farmd)?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut message = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if !payload.is_empty() {
        message.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    message.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    ));
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|error| format!("connect {farmd}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| format!("farmd socket timeout: {error}"))?;
    stream
        .write_all(message.as_bytes())
        .map_err(|error| format!("write farmd: {error}"))?;
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read farmd: {error}"))?;
    parse_http(&bytes)
}

pub(super) fn exchange_bootstrap(
    farmd: &str,
    origin: &str,
    token: &str,
) -> Result<(String, String), String> {
    let response = request(
        farmd,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", origin)],
        Some(&json!({ "bootstrap_token": token })),
    )?;
    if response.status != 200 {
        return Err(format!(
            "farmd bootstrap returned HTTP {}: {}",
            response.status, response.body
        ));
    }
    let csrf = response.body["csrf_token"]
        .as_str()
        .ok_or("farmd bootstrap omitted csrf_token")?
        .to_string();
    let cookie = response
        .set_cookie
        .ok_or("farmd bootstrap omitted Set-Cookie")?
        .split(';')
        .next()
        .unwrap_or_default()
        .to_string();
    if cookie.is_empty() {
        return Err("farmd bootstrap cookie pair was empty".into());
    }
    Ok((cookie, csrf))
}

pub(super) fn parse_loopback(farmd: &str) -> Result<(String, u16), String> {
    let rest = farmd
        .strip_prefix("http://")
        .ok_or("farmd must be an http:// loopback URL")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or("farmd URL is missing a host")?;
    let addr: std::net::SocketAddr = authority
        .parse()
        .map_err(|_| "farmd must contain an explicit loopback address and port")?;
    if !addr.ip().is_loopback() {
        return Err("farmd must be loopback".into());
    }
    Ok((addr.ip().to_string(), addr.port()))
}

fn parse_http(bytes: &[u8]) -> Result<HttpResponse, String> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or("farmd response omitted the header terminator")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or("farmd response omitted an HTTP status")?;
    let set_cookie = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("set-cookie")
            .then(|| value.trim().to_string())
    });
    Ok(HttpResponse {
        status,
        body: decode_body(body),
        set_cookie,
    })
}

fn decode_body(body: &str) -> Value {
    if body.trim().is_empty() {
        return Value::Null;
    }
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).unwrap_or(Value::Null)
}
