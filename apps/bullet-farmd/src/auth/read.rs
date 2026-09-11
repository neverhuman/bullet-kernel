//! Shared read boundary. An open stream never extends session authority.

use super::AuthState;
use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
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
    let session = if operator_read {
        let session = state
            .auth
            .lock()
            .await
            .authorize_session(request.headers())?;
        if super::single_header(request.headers(), "x-bullet-expected-session")?
            .is_some_and(|expected| expected != session.session_id)
        {
            return Err(ApiError::protocol(
                StatusCode::FORBIDDEN,
                "SESSION_CHANGED",
                "The presented session differs from the session selected by this client.",
                "Discard the old view and authenticate the current operator before retrying.",
            ));
        }
        Some(session.session_id)
    } else {
        None
    };
    let mut response = next.run(request).await;
    if operator_read {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if let Some(session) = session {
        response.headers_mut().insert(
            "x-bullet-session-id",
            HeaderValue::from_str(&session)
                .map_err(|_| ApiError::Internal("stored session identity is invalid".into()))?,
        );
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
