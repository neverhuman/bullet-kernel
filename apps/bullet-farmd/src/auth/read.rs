//! Shared read boundary. An open stream never extends session authority.

use super::AuthState;
use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use bullet_domain::Digest;

pub(crate) async fn require_session(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let operator_read = request.uri().path().starts_with("/api/v1/")
        && matches!(*request.method(), Method::GET | Method::HEAD);
    if operator_read {
        state.auth.lock().await.authorize_read(request.headers())?;
    }
    let mut response = next.run(request).await;
    if operator_read {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    Ok(response)
}

/// A digest of the session that opened a stream, never the cookie itself.
pub(crate) struct ReadPermit(Digest);

impl ReadPermit {
    pub(crate) fn issue(auth: &AuthState, headers: &HeaderMap) -> Result<Self, ApiError> {
        Ok(Self(auth.authorize_session(headers)?.bearer_digest))
    }

    pub(crate) fn is_current(&self, auth: &AuthState) -> bool {
        auth.session_by_digest(self.0).is_ok()
    }
}

#[cfg(test)]
mod tests;
