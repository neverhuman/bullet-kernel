//! One-time local-browser bootstrap, server-side session, and CSRF checks.

use crate::api::{SharedState, BROWSER_SESSION_SECONDS};
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const BOOTSTRAP_SECONDS: u64 = 600;
const SESSION_COOKIE: &str = "bullet_session";
const CSRF_HEADER: &str = "x-bullet-csrf";

#[derive(Clone)]
enum Bootstrap {
    Disabled,
    Available { digest: Digest, expires_at: Instant },
    Consumed,
}

#[derive(Clone)]
struct Session {
    bearer: Digest,
    csrf: Digest,
    expires_at: Instant,
}

/// In-memory browser authority. Secrets are retained only as digests.
#[derive(Clone)]
pub(crate) struct AuthState {
    origin: String,
    bootstrap: Bootstrap,
    session: Option<Session>,
    worker: Option<Digest>,
}

struct IssuedSession {
    bearer: String,
    csrf: String,
}

impl AuthState {
    pub(crate) fn disabled(origin: String) -> Self {
        Self {
            origin,
            bootstrap: Bootstrap::Disabled,
            session: None,
            worker: None,
        }
    }

    pub(crate) fn new(token: &str, origin: String) -> Result<Self, String> {
        validate_origin(&origin)?;
        validate_token("boot", token)?;
        Ok(Self {
            origin,
            bootstrap: Bootstrap::Available {
                digest: secret_digest("bootstrap", token),
                expires_at: Instant::now() + Duration::from_secs(BOOTSTRAP_SECONDS),
            },
            session: None,
            worker: None,
        })
    }

    pub(crate) fn with_worker_token(mut self, token: &str) -> Result<Self, String> {
        validate_token("wrk", token)?;
        self.worker = Some(secret_digest("worker", token));
        Ok(self)
    }

    fn exchange(&mut self, headers: &HeaderMap, token: &str) -> Result<IssuedSession, ApiError> {
        self.require_origin(headers)?;
        validate_token("boot", token).map_err(|_| bootstrap_invalid())?;
        match &self.bootstrap {
            Bootstrap::Disabled => {
                return Err(ApiError::protocol(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "BOOTSTRAP_UNAVAILABLE",
                    "This process was not started with browser bootstrap authority.",
                    "Restart bullet-farmd through its CLI and use the emitted one-time token.",
                ));
            }
            Bootstrap::Consumed => {
                return Err(ApiError::protocol(
                    StatusCode::UNAUTHORIZED,
                    "BOOTSTRAP_CONSUMED",
                    "The one-time bootstrap token has already been exchanged.",
                    "Use the existing session or restart bullet-farmd for a fresh token.",
                ));
            }
            Bootstrap::Available { expires_at, .. } if Instant::now() >= *expires_at => {
                self.bootstrap = Bootstrap::Consumed;
                return Err(ApiError::protocol(
                    StatusCode::UNAUTHORIZED,
                    "BOOTSTRAP_EXPIRED",
                    "The one-time bootstrap token expired before exchange.",
                    "Restart bullet-farmd and exchange the new token within ten minutes.",
                ));
            }
            Bootstrap::Available { digest, .. }
                if !constant_time_equal(*digest, secret_digest("bootstrap", token)) =>
            {
                return Err(bootstrap_invalid());
            }
            Bootstrap::Available { .. } => {}
        }
        let bearer = random_token("ses").map_err(ApiError::Internal)?;
        let csrf = random_token("csrf").map_err(ApiError::Internal)?;
        self.bootstrap = Bootstrap::Consumed;
        self.session = Some(Session {
            bearer: secret_digest("session", &bearer),
            csrf: secret_digest("csrf", &csrf),
            expires_at: Instant::now() + Duration::from_secs(BROWSER_SESSION_SECONDS),
        });
        Ok(IssuedSession { bearer, csrf })
    }

    pub(crate) fn authorize_read(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let bearer = cookie_value(headers)?;
        let session = self.current_session()?;
        if !constant_time_equal(session.bearer, secret_digest("session", bearer)) {
            return Err(session_invalid());
        }
        Ok(())
    }

    pub(crate) fn authorize_mutation(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        self.require_origin(headers)?;
        self.authorize_read(headers)?;
        let csrf = single_header(headers, CSRF_HEADER)?.ok_or_else(|| {
            ApiError::protocol(
                StatusCode::FORBIDDEN,
                "CSRF_REQUIRED",
                "The mutation is missing its session-bound CSRF token.",
                "Send the bootstrap response token in X-Bullet-CSRF.",
            )
        })?;
        let session = self.current_session()?;
        if !constant_time_equal(session.csrf, secret_digest("csrf", csrf)) {
            return Err(ApiError::protocol(
                StatusCode::FORBIDDEN,
                "CSRF_INVALID",
                "The CSRF token is not bound to the active browser session.",
                "Bootstrap again only after restarting the local daemon.",
            ));
        }
        Ok(())
    }

    pub(crate) fn authorize_worker(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let expected = self.worker.ok_or_else(worker_unavailable)?;
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let value = values
            .next()
            .ok_or_else(worker_required)?
            .to_str()
            .map_err(|_| worker_invalid())?;
        if values.next().is_some() {
            return Err(worker_invalid());
        }
        let token = value.strip_prefix("Bearer ").ok_or_else(worker_invalid)?;
        validate_token("wrk", token).map_err(|_| worker_invalid())?;
        if !constant_time_equal(expected, secret_digest("worker", token)) {
            return Err(worker_invalid());
        }
        Ok(())
    }

    fn current_session(&self) -> Result<&Session, ApiError> {
        self.session
            .as_ref()
            .filter(|session| Instant::now() < session.expires_at)
            .ok_or_else(session_invalid)
    }

    fn require_origin(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let origin = single_header(headers, header::ORIGIN.as_str())?.ok_or_else(|| {
            ApiError::protocol(
                StatusCode::FORBIDDEN,
                "ORIGIN_REQUIRED",
                "Browser mutations require an exact Origin header.",
                "Send the request from the configured loopback Portal origin.",
            )
        })?;
        if origin != self.origin {
            return Err(ApiError::protocol(
                StatusCode::FORBIDDEN,
                "ORIGIN_DENIED",
                "The request Origin is not the configured loopback Portal origin.",
                "Use the exact Portal origin printed by bullet-farmd.",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapRequest {
    bootstrap_token: String,
}

#[derive(Serialize)]
struct BootstrapResponse {
    status: &'static str,
    csrf_token: String,
    expires_in_seconds: u64,
}

pub(crate) async fn bootstrap(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Result<Json<BootstrapRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let body = body.map_err(|_| ApiError::invalid_json())?.0;
    let issued = state
        .auth
        .lock()
        .await
        .exchange(&headers, &body.bootstrap_token)?;
    let cookie = format!(
        "{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={BROWSER_SESSION_SECONDS}",
        issued.bearer
    );
    let mut response = Json(BootstrapResponse {
        status: "AUTHENTICATED",
        csrf_token: issued.csrf,
        expires_in_seconds: BROWSER_SESSION_SECONDS,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|error| ApiError::Internal(format!("session cookie: {error}")))?,
    );
    Ok(response)
}

/// Generate an opaque token from the platform CSPRNG.
pub fn random_token(prefix: &str) -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("operating-system entropy: {error}"))?;
    Ok(format!("{prefix}_{}", Digest::of(&bytes).to_hex()))
}

fn validate_token(prefix: &str, token: &str) -> Result<(), String> {
    let Some(value) = token.strip_prefix(&format!("{prefix}_")) else {
        return Err(format!("token must start with {prefix}_"));
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("token must contain 256 lowercase hexadecimal bits".into());
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), String> {
    let authority = origin
        .strip_prefix("http://")
        .ok_or("Portal origin must use local http")?;
    if authority.contains(['/', '?', '#', '@']) {
        return Err("Portal origin must not contain credentials, path, query, or fragment".into());
    }
    let address = authority
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "Portal origin must contain an explicit loopback address and port")?;
    if !address.ip().is_loopback() {
        return Err("Portal origin must be loopback".into());
    }
    Ok(())
}

fn secret_digest(domain: &str, token: &str) -> Digest {
    Digest::of(format!("bullet-farmd.{domain}.v1\0{token}").as_bytes())
}

fn constant_time_equal(left: Digest, right: Digest) -> bool {
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|value| value.to_str().map_err(|_| session_invalid()))
        .transpose()?;
    if values.next().is_some() {
        return Err(session_invalid());
    }
    Ok(value)
}

fn cookie_value(headers: &HeaderMap) -> Result<&str, ApiError> {
    let cookie = single_header(headers, header::COOKIE.as_str())?.ok_or_else(session_required)?;
    let mut matched = cookie.split(';').filter_map(|entry| {
        let (name, value) = entry.trim().split_once('=')?;
        (name == SESSION_COOKIE).then_some(value)
    });
    let value = matched.next().ok_or_else(session_required)?;
    if matched.next().is_some() || validate_token("ses", value).is_err() {
        return Err(session_invalid());
    }
    Ok(value)
}

fn bootstrap_invalid() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "BOOTSTRAP_INVALID",
        "The one-time bootstrap token is malformed or invalid.",
        "Copy the exact token printed by the local bullet-farmd process.",
    )
}

fn session_required() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "SESSION_REQUIRED",
        "The request has no authenticated Bullet Farm browser session.",
        "Exchange the one-time local CLI bootstrap token first.",
    )
}

fn session_invalid() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "SESSION_INVALID",
        "The browser session is invalid, expired, or ambiguous.",
        "Restart bullet-farmd and exchange its new one-time bootstrap token.",
    )
}

fn worker_unavailable() -> ApiError {
    ApiError::protocol(
        StatusCode::SERVICE_UNAVAILABLE,
        "WORKER_AUTHORITY_UNAVAILABLE",
        "This daemon was not started with internal worker authority.",
        "Restart bullet-farmd with a protected worker token file.",
    )
}

fn worker_required() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "WORKER_AUTHORITY_REQUIRED",
        "The internal operation requires its independent worker bearer.",
        "Read the configured worker token file from the authorized local worker only.",
    )
}

fn worker_invalid() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "WORKER_AUTHORITY_INVALID",
        "The internal worker bearer is malformed, ambiguous, or invalid.",
        "Send exactly one Authorization header containing the configured worker bearer.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_worker_authority_fails_closed_before_header_parsing() {
        let headers = HeaderMap::new();
        let error = AuthState::disabled("http://127.0.0.1:7420".into())
            .authorize_worker(&headers)
            .expect_err("disabled worker");
        assert!(matches!(
            error,
            ApiError::Protocol {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "WORKER_AUTHORITY_UNAVAILABLE",
                ..
            }
        ));
    }
}
