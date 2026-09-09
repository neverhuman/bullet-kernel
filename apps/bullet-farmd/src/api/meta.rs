//! Contract and liveness answers: `/openapi.yaml` and `/health`.

use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

const OPENAPI: &str = include_str!("../../../../contracts/openapi.yaml");

/// Liveness answer. `portal` names the embedded Portal bundle subject and is
/// absent when this binary serves no Portal. `reap` reports the writer-lease
/// maintenance tick and is absent until that tick has completed a sweep, so a
/// daemon whose tick has never fired answers exactly `{"status":"ok"}` as it
/// always did. Both are additive: nothing that was in this body ever leaves it.
#[derive(Serialize)]
pub(crate) struct Health {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    portal: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reap: Option<crate::reaper::ReapRun>,
}

pub(crate) async fn health(State(state): State<SharedState>) -> Result<Json<Health>, ApiError> {
    let reap = state.reaper.snapshot().await;
    if let Some(run) = &reap {
        super::safe_integer::health_reclaimed(run.reclaimed)?;
    }
    Ok(Json(Health {
        status: "ok",
        portal: super::portal::health_field(),
        reap,
    }))
}

pub(crate) async fn openapi() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        OPENAPI,
    )
}
