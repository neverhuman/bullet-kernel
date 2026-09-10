//! Nonsecret session status and authenticated self-revocation.

use super::{cookie_value, csrf_value, secret_digest, store_error, SESSION_COOKIE};
use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bullet_application::operator_sessions::OperatorSessionStore;
use chrono::{DateTime, SecondsFormat};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct OperatorSessionView {
    status: &'static str,
    operator_id: String,
    session_id: String,
    issued_at: String,
    expires_at: String,
}

#[derive(Serialize)]
struct SessionRevocationView {
    status: &'static str,
    operator_id: String,
    session_id: String,
    revoked_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeSessionRequest {}

fn timestamp(seconds: i64) -> Result<String, ApiError> {
    DateTime::from_timestamp(seconds, 0)
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Secs, true))
        .ok_or_else(|| ApiError::Internal("stored session time is invalid".into()))
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = state.auth.lock().await.authorize_session(&headers)?;
    let mut response = Json(OperatorSessionView {
        status: "AUTHENTICATED",
        operator_id: session.operator_id,
        session_id: session.session_id,
        issued_at: timestamp(session.issued_at)?,
        expires_at: timestamp(session.expires_at)?,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Result<Json<RevokeSessionRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let mut auth = state.auth.lock().await;
    auth.authorize_mutation(&headers)?;
    let _body = body.map_err(|_| ApiError::invalid_json())?.0;
    let bearer = secret_digest("session", cookie_value(&headers)?);
    let csrf = secret_digest("csrf", csrf_value(&headers)?);
    let origin = auth.origin.clone();
    let revoked = auth
        .store
        .as_mut()
        .ok_or_else(super::session_invalid)?
        .revoke_operator_session(bearer, csrf, &origin)
        .map_err(store_error)?;
    let mut response = Json(SessionRevocationView {
        status: "REVOKED",
        operator_id: revoked.operator_id,
        session_id: revoked.session_id,
        revoked_at: timestamp(revoked.revoked_at)?,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        ))
        .map_err(|_| ApiError::Internal("session cookie expiry is invalid".into()))?,
    );
    Ok(response)
}
