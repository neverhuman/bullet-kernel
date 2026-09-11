//! Bounded loopback HTTP client. No proxy, redirects, or secret-bearing diagnostics.

use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE, SET_COOKIE};
use reqwest::{Method, Url};
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Value,
    pub(crate) set_cookie: Option<String>,
    pub(crate) sequence: Option<u64>,
}

pub(crate) fn request(
    farmd: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Result<HttpResponse, String> {
    request_query(farmd, method, path, &[], headers, body)
}

pub(crate) fn request_query(
    farmd: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Result<HttpResponse, String> {
    request_inner(farmd, method, path, query, headers, body, false).map(|(response, _)| response)
}

/// Session discovery has one fixed authenticated endpoint. Its acknowledgement
/// is required before consuming the model that names the previously unknown ID.
pub(crate) fn observe_session(
    farmd: &str,
    origin: &str,
    cookie: &str,
) -> Result<(HttpResponse, String), String> {
    let (response, session) = request_inner(
        farmd,
        "GET",
        "/api/v1/auth/session",
        &[],
        &[("Origin", origin), ("Cookie", cookie)],
        None,
        true,
    )?;
    Ok((response, session.ok_or("FARMD_SESSION_ACK_MISSING")?))
}

fn request_inner(
    farmd: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: Option<&Value>,
    observe_session: bool,
) -> Result<(HttpResponse, Option<String>), String> {
    parse_loopback(farmd)?;
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#', '\\']) {
        return Err("FARMD_PATH_INVALID: expected an absolute API path".into());
    }
    let mut expected_session = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-bullet-expected-session") {
            if expected_session.replace(*value).is_some() {
                return Err("FARMD_EXPECTED_SESSION_AMBIGUOUS".into());
            }
            validate_secret(value, "sid").map_err(|_| "FARMD_EXPECTED_SESSION_INVALID")?;
        }
    }
    let mut url = Url::parse(farmd).map_err(|_| "FARMD_URL_INVALID")?;
    // Paths are assigned, never resolved as a new authority.
    url.set_path(path);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| "FARMD_METHOD_INVALID")?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "FARMD_CLIENT_UNAVAILABLE")?;
    let mut request = client.request(method, url);
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "FARMD_HEADER_INVALID")?;
        let mut value = HeaderValue::from_str(value).map_err(|_| "FARMD_HEADER_INVALID")?;
        value.set_sensitive(true);
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().map_err(|_| {
        "FARMD_REQUEST_FAILED: reconnect and reconcile the original command before retrying"
    })?;
    // An authenticated caller's expected owner must be acknowledged before any
    // body, cookie, projection or absence result can be consumed.
    let session_id = if expected_session.is_some() || observe_session {
        let mut acknowledgements = response.headers().get_all("x-bullet-session-id").iter();
        let acknowledged = acknowledgements.next().ok_or("FARMD_SESSION_ACK_MISSING")?;
        if acknowledgements.next().is_some() {
            return Err("FARMD_SESSION_ACK_AMBIGUOUS".into());
        }
        if expected_session.is_some_and(|expected| acknowledged.as_bytes() != expected.as_bytes()) {
            return Err("FARMD_SESSION_ACK_MISMATCH".into());
        }
        let session = acknowledged
            .to_str()
            .map_err(|_| "FARMD_SESSION_ACK_INVALID")?;
        validate_secret(session, "sid").map_err(|_| "FARMD_SESSION_ACK_INVALID")?;
        Some(session.to_owned())
    } else {
        None
    };
    let status = response.status().as_u16();
    let sequences = response
        .headers()
        .get_all("x-bullet-as-of-sequence")
        .iter()
        .collect::<Vec<_>>();
    if sequences.len() > 1 {
        return Err("FARMD_SEQUENCE_AMBIGUOUS".into());
    }
    let sequence = sequences
        .first()
        .map(|v| {
            let text = v.to_str().map_err(|_| "FARMD_SEQUENCE_INVALID")?;
            if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
                return Err("FARMD_SEQUENCE_INVALID");
            }
            text.parse::<u64>().map_err(|_| "FARMD_SEQUENCE_INVALID")
        })
        .transpose()?;
    if response.status().is_redirection() {
        return Err("FARMD_REDIRECT_REFUSED".into());
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES)
    {
        return Err("FARMD_RESPONSE_TOO_LARGE".into());
    }
    let cookies = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .collect::<Vec<_>>();
    if cookies.len() > 1 {
        return Err("FARMD_COOKIE_AMBIGUOUS".into());
    }
    let set_cookie = cookies
        .first()
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| "FARMD_COOKIE_INVALID")?;
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .trim();
    if status != 204
        && !matches!(
            content_type,
            "application/json" | "application/problem+json"
        )
    {
        return Err("FARMD_CONTENT_TYPE_INVALID: expected JSON".into());
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "FARMD_RESPONSE_INCOMPLETE")?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("FARMD_RESPONSE_TOO_LARGE".into());
    }
    let body = if status == 204 && bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<bullet_harness_core::strict_json::StrictJson>(&bytes)
            .map_err(|_| "FARMD_JSON_INVALID: response was not unambiguous UTF-8 JSON")?
            .0
    };
    Ok((
        HttpResponse {
            status,
            body,
            set_cookie,
            sequence,
        },
        session_id,
    ))
}

pub(crate) fn exchange_bootstrap(
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
        return Err(format!("FARMD_BOOTSTRAP_REFUSED: HTTP {}", response.status));
    }
    let model: crate::client::models::BootstrapResponse = crate::client::decode(&response.body)?;
    let csrf = model.csrf_token.as_str();
    let cookie = response
        .set_cookie
        .as_deref()
        .ok_or("FARMD_COOKIE_MISSING")?
        .split(';')
        .next()
        .unwrap_or_default();
    let bearer = cookie
        .strip_prefix("bullet_session=")
        .ok_or("FARMD_COOKIE_INVALID")?;
    validate_secret(bearer, "ses")?;
    validate_secret(csrf, "csrf")?;
    Ok((cookie.to_owned(), csrf.to_owned()))
}

pub(crate) fn validate_secret(value: &str, prefix: &str) -> Result<(), String> {
    let hex = value
        .strip_prefix(prefix)
        .and_then(|v| v.strip_prefix('_'))
        .ok_or("FARMD_CREDENTIAL_INVALID")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err("FARMD_CREDENTIAL_INVALID".into());
    }
    Ok(())
}

pub(crate) fn parse_loopback(farmd: &str) -> Result<(String, u16), String> {
    let rest = farmd
        .strip_prefix("http://")
        .ok_or("farmd must be an http:// loopback URL")?;
    let addr: std::net::SocketAddr = rest
        .strip_suffix('/')
        .unwrap_or(rest)
        .parse()
        .map_err(|_| "farmd must contain only an explicit loopback address and port")?;
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err("farmd must be loopback with a nonzero port".into());
    }
    Ok((addr.ip().to_string(), addr.port()))
}

#[cfg(test)]
mod tests;
