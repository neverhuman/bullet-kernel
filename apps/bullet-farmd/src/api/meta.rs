//! Contract and liveness answers: `/openapi.yaml` and `/health`.

use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

const OPENAPI: &str = include_str!("../../../../contracts/openapi.yaml");

/// Liveness answer. `portal` names the embedded Portal bundle subject and is
/// absent when this binary serves no Portal.
#[derive(Serialize)]
pub(crate) struct Health {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    portal: Option<&'static str>,
}

pub(crate) async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        portal: super::portal::health_field(),
    })
}

pub(crate) async fn openapi() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        OPENAPI,
    )
}
