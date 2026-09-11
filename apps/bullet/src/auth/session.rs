//! Server session identity is observed before accepting a revocation acknowledgement.
use super::{http, Credentials};
use crate::client::{
    decode,
    models::{OperatorSessionView, SessionRevocationView},
};

pub(crate) fn status(credentials: &Credentials) -> Result<OperatorSessionView, String> {
    let (response, acknowledged_session) =
        http::observe_session(&credentials.farmd, &credentials.origin, &credentials.cookie)?;
    if response.status != 200 {
        return Err(format!("AUTH_SESSION_REFUSED: HTTP {}", response.status));
    }
    let view: OperatorSessionView = decode(&response.body)?;
    if view.session_id != acknowledged_session {
        return Err("AUTH_SESSION_SUBJECT_MISMATCH".into());
    }
    let issued = chrono::DateTime::parse_from_rfc3339(&view.issued_at)
        .map_err(|_| "AUTH_SESSION_TIME_INVALID")?;
    let expires = chrono::DateTime::parse_from_rfc3339(&view.expires_at)
        .map_err(|_| "AUTH_SESSION_TIME_INVALID")?;
    if expires <= issued || expires - issued > chrono::Duration::seconds(28_800) {
        return Err("AUTH_SESSION_TIME_INVALID".into());
    }
    Ok(view)
}

pub(super) fn revoke(credentials: &Credentials) -> Result<SessionRevocationView, String> {
    let original = status(credentials)?;
    let response = http::request(
        &credentials.farmd,
        "POST",
        "/api/v1/auth/revoke",
        &[
            ("Cookie", &credentials.cookie),
            ("Origin", &credentials.origin),
            ("X-Bullet-CSRF", &credentials.csrf),
        ],
        Some(&serde_json::json!({})),
    )
    .map_err(|_| "AUTH_REVOCATION_UNKNOWN: preserve credentials and check bullet auth status")?;
    if response.status != 200 {
        return Err(format!(
            "AUTH_REVOCATION_REFUSED: HTTP {}; local credentials retained",
            response.status
        ));
    }
    let view: SessionRevocationView = decode(&response.body)?;
    if view.operator_id != original.operator_id || view.session_id != original.session_id {
        return Err("AUTH_REVOCATION_SUBJECT_MISMATCH: local credentials retained".into());
    }
    let at = chrono::DateTime::parse_from_rfc3339(&view.revoked_at)
        .map_err(|_| "AUTH_REVOCATION_TIME_INVALID")?;
    let issued = chrono::DateTime::parse_from_rfc3339(&original.issued_at)
        .map_err(|_| "AUTH_SESSION_TIME_INVALID")?;
    let expires = chrono::DateTime::parse_from_rfc3339(&original.expires_at)
        .map_err(|_| "AUTH_SESSION_TIME_INVALID")?;
    if at < issued || at >= expires {
        return Err("AUTH_REVOCATION_TIME_INVALID".into());
    }
    Ok(view)
}

#[cfg(test)]
mod tests;
