//! Runtime agreement with JSON's JavaScript-safe integer contract.

use crate::errors::ApiError;

/// Largest integer JavaScript can represent exactly.
pub(crate) const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

fn require(value: u64, field: &'static str) -> Result<(), ApiError> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(ApiError::UnsafeInteger(field))
    }
}

pub(crate) fn health_reclaimed(value: u64) -> Result<(), ApiError> {
    require(value, "HealthReap.reclaimed")
}

pub(crate) fn outbox_sequence(value: u64) -> Result<(), ApiError> {
    require(value, "OutboxItem.seq")
}

pub(crate) fn event_sequence(value: u64) -> Result<(), ApiError> {
    require(value, "EventEnvelope.seq")
}

pub(crate) fn snapshot_watermark(value: u64) -> Result<(), ApiError> {
    require(value, "Snapshot.as_of_sequence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::Value;

    type Validator = fn(u64) -> Result<(), ApiError>;

    const FIELDS: &[(Validator, &str)] = &[
        (health_reclaimed, "HealthReap.reclaimed"),
        (outbox_sequence, "OutboxItem.seq"),
        (event_sequence, "EventEnvelope.seq"),
        (snapshot_watermark, "Snapshot.as_of_sequence"),
    ];

    #[tokio::test]
    async fn exact_maximum_is_admitted_and_maximum_plus_one_is_typed_refusal() {
        for (validate, field) in FIELDS {
            assert!(validate(MAX_SAFE_INTEGER).is_ok(), "{field}");
            let error = validate(MAX_SAFE_INTEGER + 1).expect_err(field);
            assert!(matches!(error, ApiError::UnsafeInteger(actual) if actual == *field));
        }

        let response = snapshot_watermark(MAX_SAFE_INTEGER + 1)
            .expect_err("unsafe watermark")
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("problem body");
        let problem: Value = serde_json::from_slice(&body).expect("problem JSON");
        assert_eq!(problem["code"], "API_INTEGER_OUT_OF_RANGE");
        assert_eq!(problem["retryable"], false);
    }
}
