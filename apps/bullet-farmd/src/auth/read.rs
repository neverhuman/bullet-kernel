//! Shared operator session boundary. An open stream never extends authority.

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
    let operator_mutation = *request.method() == Method::POST
        && matches!(
            request.uri().path(),
            "/api/v1/commands" | "/api/v1/auth/revoke"
        );
    let scoped = operator_read || operator_mutation;
    let session = if scoped {
        let auth = state.auth.lock().await;
        // Preserve mutation Origin/CSRF refusal order before parsing a body or
        // checking the optional selector. The handler still revalidates authority.
        if operator_mutation {
            auth.authorize_mutation(request.headers())?;
        }
        let session = auth.authorize_session(request.headers())?;
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
    if scoped {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    // The authenticated subject remains the acknowledgement after self-revocation.
    // Re-authenticating here would lose the committed revocation response.
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
