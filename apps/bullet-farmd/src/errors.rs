//! Typed problem-details error mapping (spec section 27.9). Store failures
//! are 500s and never leak raw store strings; domain refusals map to stable
//! reason codes.

use axum::http::StatusCode;
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
    /// Stable machine-readable reason code.
    pub code: String,
    /// Correlation id for log lookup.
    pub correlation_id: String,
    /// Whether the caller may retry unchanged.
    pub retryable: bool,
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
    /// The database schema is not supported by this pre-1.0 binary.
    UnsupportedSchema(String),
    /// The durable store failed. Logged; the detail is not exposed.
    Internal(String),
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
        "INVALID_TRANSITION" => "Invalid state transition",
        "ENCODING_FAILURE" => "Canonical encoding failed",
        "UNKNOWN_STATE" => "Unknown state label",
        "CONFLICTING_CURSOR" => "Conflicting event cursors",
        "INVALID_CURSOR" => "Invalid event cursor",
        "NOT_FOUND" => "Resource not found",
        "UNSUPPORTED_SCHEMA" => "Unsupported database schema",
        "STORE_FAILURE" => "Ledger store failure",
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
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(detail) = &self {
            tracing::error!(detail, "ledger store failure");
        }
        if let Self::UnsupportedSchema(detail) = &self {
            tracing::error!(
                detail,
                "database requires export and removal before restart"
            );
        }
        let (status, code, retryable) = self.status_and_code();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let correlation_id = format!(
            "corr_{}",
            &Digest::of(format!("{code}:{nanos}").as_bytes()).to_hex()[..16]
        );
        let problem = Problem {
            r#type: format!(
                "https://bullet.farm/problems/{}",
                code.to_lowercase().replace('_', "-")
            ),
            title: title_for(&code).to_string(),
            status: status.as_u16(),
            code,
            correlation_id,
            retryable,
        };
        (status, Json(problem)).into_response()
    }
}
