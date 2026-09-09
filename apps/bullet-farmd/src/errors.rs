//! Typed problem-details error mapping (spec section 27.9). Store failures
//! are 500s and never leak raw store strings; domain refusals map to stable
//! reason codes.

use axum::http::{header::CONTENT_TYPE, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bullet_application::LedgerError;
use bullet_domain::{Digest, DomainError};
use serde::Serialize;

/// RFC 9457 problem-details body.
#[derive(Serialize)]
pub struct Problem {
    /// Problem type URI.
    pub r#type: String,
    /// Human-readable title.
    pub title: String,
    /// HTTP status.
    pub status: u16,
    /// Human-readable occurrence detail without internal store text.
    pub detail: String,
    /// URI identifying this occurrence.
    pub instance: String,
    /// Stable machine-readable reason code.
    pub code: String,
    /// Request id returned to callers and logs.
    pub request_id: String,
    /// Correlation id for log lookup.
    pub correlation_id: String,
    /// Whether the caller may retry unchanged.
    pub retryable: bool,
    /// Actionable operator or client recovery guidance.
    pub repair: String,
}

/// API failure. Conversion from ledger errors picks the status class.
pub enum ApiError {
    /// The addressed resource does not exist.
    NotFound(String),
    /// The request itself is malformed or illegal.
    Invalid(DomainError),
    /// The request conflicts with current authority state.
    Conflict(DomainError),
    /// A request-level protocol rule was violated.
    BadRequest(&'static str),
    /// The requested exclusive event cursor is no longer replayable.
    ReplayUnavailable(String),
    /// The database schema is not supported by this pre-1.0 binary.
    UnsupportedSchema(String),
    /// The durable store failed. Logged; the detail is not exposed.
    Internal(String),
    /// A server-owned integer cannot be represented exactly by JSON clients.
    UnsafeInteger(&'static str),
    /// An HTTP protocol or browser-authority rule was refused.
    Protocol {
        /// HTTP status.
        status: StatusCode,
        /// Stable reason code.
        code: &'static str,
        /// Safe public explanation.
        detail: &'static str,
        /// Safe repair guidance.
        repair: &'static str,
    },
}

impl From<LedgerError> for ApiError {
    fn from(value: LedgerError) -> Self {
        match value {
            LedgerError::Store(detail) => Self::Internal(detail),
            LedgerError::UnsupportedSchema { detail } => Self::UnsupportedSchema(detail),
            LedgerError::Domain(err) => Self::from(err),
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        match err {
            DomainError::StaleAuthority(_)
            | DomainError::Fence(_)
            | DomainError::Idempotency(_)
            | DomainError::Conflict(_) => Self::Conflict(err),
            _ => Self::Invalid(err),
        }
    }
}

fn title_for(code: &str) -> &'static str {
    match code {
        "STALE_AUTHORITY" => "Stale authority token",
        "FENCE_REUSE" => "Fence invariant violated",
        "IDEMPOTENCY_CONFLICT" => "Idempotency conflict",
        "GRAPH_CONFLICT" => "Graph conflict",
        "INVALID_ID" => "Invalid identifier",
        "INVALID_LEASE_TTL" => "Invalid lease lifetime",
        "INVALID_TRANSITION" => "Invalid state transition",
        "ENCODING_FAILURE" => "Canonical encoding failed",
        "UNKNOWN_STATE" => "Unknown state label",
        "CONFLICTING_CURSOR" => "Conflicting event cursors",
        "INVALID_CURSOR" => "Invalid event cursor",
        "REPLAY_UNAVAILABLE" => "Event replay unavailable",
        "NOT_FOUND" => "Resource not found",
        "UNSUPPORTED_SCHEMA" => "Unsupported database schema",
        "STORE_FAILURE" => "Ledger store failure",
        "API_INTEGER_OUT_OF_RANGE" => "API integer out of range",
        "INVALID_JSON" => "Invalid JSON request",
        "BOOTSTRAP_UNAVAILABLE" => "Browser bootstrap unavailable",
        "BOOTSTRAP_CONSUMED" => "Browser bootstrap already consumed",
        "BOOTSTRAP_EXPIRED" => "Browser bootstrap expired",
        "BOOTSTRAP_INVALID" => "Invalid browser bootstrap",
        "SESSION_REQUIRED" => "Browser session required",
        "SESSION_INVALID" => "Invalid browser session",
        "CSRF_REQUIRED" => "CSRF token required",
        "CSRF_INVALID" => "Invalid CSRF token",
        "ORIGIN_REQUIRED" => "Origin required",
        "ORIGIN_DENIED" => "Origin denied",
        "WORKER_AUTHORITY_UNAVAILABLE" => "Worker authority unavailable",
        "WORKER_AUTHORITY_REQUIRED" => "Worker authority required",
        "WORKER_AUTHORITY_INVALID" => "Invalid worker authority",
        "MUTATION_ENDPOINT_REMOVED" => "Mutation endpoint removed",
        "API_VERSION_RETIRED" => "API version retired",
        _ => "Request failed",
    }
}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, String, bool) {
        match self {
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND".into(), false),
            Self::Invalid(err) => (StatusCode::BAD_REQUEST, err.reason_code().into(), false),
            Self::Conflict(err) => (StatusCode::CONFLICT, err.reason_code().into(), false),
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, (*code).into(), false),
            Self::ReplayUnavailable(_) => (StatusCode::GONE, "REPLAY_UNAVAILABLE".into(), false),
            Self::UnsupportedSchema(_) => (
                StatusCode::PRECONDITION_FAILED,
                "UNSUPPORTED_SCHEMA".into(),
                false,
            ),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_FAILURE".into(),
                true,
            ),
            Self::UnsafeInteger(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "API_INTEGER_OUT_OF_RANGE".into(),
                false,
            ),
            Self::Protocol { status, code, .. } => (*status, (*code).into(), false),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, retryable) = self.status_and_code();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let correlation_id = format!(
            "corr_{}",
            &Digest::of(format!("{code}:{nanos}").as_bytes()).to_hex()[..16]
        );
        let request_id = format!(
            "req_{}",
            &Digest::of(format!("request:{code}:{nanos}").as_bytes()).to_hex()[..16]
        );
        if let Self::Internal(detail) = &self {
            tracing::error!(detail, %request_id, %correlation_id, "ledger store failure");
        }
        if let Self::UnsupportedSchema(detail) = &self {
            tracing::error!(
                detail,
                %request_id,
                %correlation_id,
                "database requires export and removal before restart"
            );
        }
        if let Self::UnsafeInteger(field) = &self {
            tracing::error!(field, %request_id, %correlation_id, "unsafe API integer refused");
        }
        let detail = match &self {
            Self::NotFound(resource) => format!("{resource} was not found"),
            Self::Invalid(_) => "The request violates a validated domain invariant.".into(),
            Self::Conflict(_) => "The request conflicts with current durable authority.".into(),
            Self::BadRequest(_) => "Supply exactly one non-negative decimal event cursor.".into(),
            Self::ReplayUnavailable(detail) => detail.clone(),
            Self::UnsupportedSchema(_) => {
                "This database schema is not supported by this pre-1.0 binary.".into()
            }
            Self::Internal(_) => "The durable ledger could not produce a trusted result.".into(),
            Self::UnsafeInteger(_) => {
                "A server-owned integer exceeds the exact JavaScript-safe range and was not serialized."
                    .into()
            }
            Self::Protocol { detail, .. } => (*detail).into(),
        };
        let repair = match &self {
            Self::ReplayUnavailable(_) => {
                "Fetch a fresh projection snapshot, then reconnect with its as_of_sequence as the exclusive cursor."
            }
            Self::UnsupportedSchema(_) => {
                "Export any data you need, remove the unsupported database, and restart to initialize the current schema."
            }
            Self::Internal(_) => {
                "Retry once; if the failure persists, use request_id and correlation_id to inspect farmd logs and run bullet-family doctor."
            }
            Self::UnsafeInteger(_) => {
                "Freeze API delivery, inspect the named counter in farmd logs, and reconcile its durable source before retrying."
            }
            Self::NotFound(_) => {
                "Refresh the owning projection and retry only if the resource appears there."
            }
            Self::BadRequest(_) => {
                "Remove duplicate or unknown cursor fields and send either after or Last-Event-ID, not both."
            }
            Self::Invalid(_) => "Correct the identified request field before retrying.",
            Self::Conflict(_) => {
                "Refresh durable authority state before constructing a new request."
            }
            Self::Protocol { repair, .. } => repair,
        };
        let problem = Problem {
            r#type: format!(
                "https://bullet.farm/problems/{}",
                code.to_lowercase().replace('_', "-")
            ),
            title: title_for(&code).to_string(),
            status: status.as_u16(),
            detail,
            instance: format!("urn:bullet:request:{request_id}"),
            code,
            request_id,
            correlation_id,
            retryable,
            repair: repair.into(),
        };
        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl ApiError {
    pub(crate) fn protocol(
        status: StatusCode,
        code: &'static str,
        detail: &'static str,
        repair: &'static str,
    ) -> Self {
        Self::Protocol {
            status,
            code,
            detail,
            repair,
        }
    }

    pub(crate) fn invalid_json() -> Self {
        Self::protocol(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            "The request body is missing, malformed, oversized, or contains unknown fields.",
            "Send exactly the fields declared by the current OpenAPI schema as application/json.",
        )
    }
}
