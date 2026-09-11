//! One-time local-browser bootstrap, server-side session, and CSRF checks.

pub(crate) mod read;
pub(crate) mod sessions;

use crate::api::{SharedState, BROWSER_SESSION_SECONDS};
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bullet_adapters::SqliteLedger;
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSession, OperatorSessionError, OperatorSessionStore,
    SessionIssue,
};
use bullet_application::LedgerError;
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};

const BOOTSTRAP_SECONDS: u64 = 600;
const SESSION_COOKIE: &str = "bullet_session";
const CSRF_HEADER: &str = "x-bullet-csrf";

/// Configuration plus an admitted durable authentication connection.
/// No bearer, CSRF token or mutable session authority is cached in memory.
pub(crate) struct AuthState {
    origin: String,
    bootstrap: Option<Digest>,
    store: Option<SqliteLedger>,
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
            bootstrap: None,
            store: None,
            worker: None,
        }
    }

    pub(crate) fn new(token: &str, origin: String) -> Result<Self, String> {
        validate_origin(&origin)?;
        validate_token("boot", token)?;
        Ok(Self {
            origin,
            bootstrap: Some(secret_digest("bootstrap", token)),
            store: None,
            worker: None,
        })
    }

    pub(crate) fn with_store(mut self, mut store: SqliteLedger) -> Result<Self, LedgerError> {
        if let Some(digest) = self.bootstrap {
            store
                .register_operator_bootstrap(&BootstrapRegistration {
                    digest,
                    proposed_operator_id: random_token("opr").map_err(LedgerError::Store)?,
                    origin: self.origin.clone(),
                    lifetime_seconds: u32::try_from(BOOTSTRAP_SECONDS)
                        .map_err(|err| LedgerError::Store(err.to_string()))?,
                })
                .map_err(|err| match err {
                    OperatorSessionError::Store(err) => err,
                    err => LedgerError::Store(err.to_string()),
                })?;
        }
        self.store = Some(store);
        Ok(self)
    }

    pub(crate) fn with_worker_token(mut self, token: &str) -> Result<Self, String> {
        validate_token("wrk", token)?;
        self.worker = Some(secret_digest("worker", token));
        Ok(self)
    }

    fn exchange(&mut self, headers: &HeaderMap, token: &str) -> Result<IssuedSession, ApiError> {
        self.require_origin(headers)?;
        validate_token("boot", token).map_err(|_| bootstrap_invalid())?;
        let expected = self.bootstrap.ok_or_else(|| {
            ApiError::protocol(
                StatusCode::SERVICE_UNAVAILABLE,
                "BOOTSTRAP_UNAVAILABLE",
                "This process was not started with browser bootstrap authority.",
                "Start bullet-farmd with a protected one-time bootstrap token.",
            )
        })?;
        if !constant_time_equal(expected, secret_digest("bootstrap", token)) {
            return Err(bootstrap_invalid());
        }
        let bearer = random_token("ses").map_err(ApiError::Internal)?;
        let csrf = random_token("csrf").map_err(ApiError::Internal)?;
        let request = SessionIssue {
            bootstrap_digest: expected,
            session_id: random_token("sid").map_err(ApiError::Internal)?,
            bearer_digest: secret_digest("session", &bearer),
            csrf_digest: secret_digest("csrf", &csrf),
            origin: self.origin.clone(),
            lifetime_seconds: u32::try_from(BROWSER_SESSION_SECONDS)
                .map_err(|err| ApiError::Internal(err.to_string()))?,
        };
        self.store
            .as_mut()
            .ok_or_else(session_invalid)?
            .exchange_operator_bootstrap(&request)
            .map_err(store_error)?;
        Ok(IssuedSession { bearer, csrf })
    }

    pub(crate) fn authorize_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<OperatorSession, ApiError> {
        if headers.contains_key(header::ORIGIN) {
            self.require_origin(headers)?;
        }
        let bearer = cookie_value(headers)?;
        self.session_by_digest(secret_digest("session", bearer))
    }

    fn session_by_digest(&self, digest: Digest) -> Result<OperatorSession, ApiError> {
        self.store
            .as_ref()
            .ok_or_else(session_invalid)?
            .read_operator_session(digest, &self.origin)
            .map_err(store_error)
    }

    pub(crate) fn authorize_mutation(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        self.require_origin(headers)?;
        let session = self.authorize_session(headers)?;
        let csrf = csrf_value(headers)?;
        if !constant_time_equal(session.csrf_digest, secret_digest("csrf", csrf)) {
            return Err(csrf_invalid());
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
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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

fn csrf_value(headers: &HeaderMap) -> Result<&str, ApiError> {
    single_header(headers, CSRF_HEADER)?.ok_or_else(|| {
        ApiError::protocol(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "The mutation is missing its session-bound CSRF token.",
            "Send the bootstrap response token in X-Bullet-CSRF.",
        )
    })
}

fn csrf_invalid() -> ApiError {
    ApiError::protocol(
        StatusCode::FORBIDDEN,
        "CSRF_INVALID",
        "The CSRF token is not bound to the presented browser session.",
        "Use the CSRF token issued with this session.",
    )
}

fn store_error(error: OperatorSessionError) -> ApiError {
    match error {
        OperatorSessionError::Store(error) => error.into(),
        OperatorSessionError::InvalidRequest => {
            ApiError::Internal("server authentication request is invalid".into())
        }
        OperatorSessionError::BootstrapInvalid => bootstrap_invalid(),
        OperatorSessionError::SessionInvalid => session_invalid(),
        OperatorSessionError::CsrfInvalid => csrf_invalid(),
        OperatorSessionError::BootstrapConsumed => ApiError::protocol(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_CONSUMED",
            "The one-time bootstrap token has already been exchanged.",
            "Use the issued session or configure a fresh one-time bootstrap token.",
        ),
        OperatorSessionError::BootstrapExpired => ApiError::protocol(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_EXPIRED",
            "The one-time bootstrap token expired before exchange.",
            "Configure a fresh token and exchange it within ten minutes.",
        ),
    }
}

fn bootstrap_invalid() -> ApiError {
    ApiError::protocol(
        StatusCode::UNAUTHORIZED,
        "BOOTSTRAP_INVALID",
        "The one-time bootstrap token is malformed or invalid.",
        "Supply the exact protected bootstrap token through private interactive or stdin input.",
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
        "The browser session is invalid, expired, revoked, or ambiguous.",
        "Authenticate with a fresh protected bootstrap token through private input.",
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
