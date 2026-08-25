//! Spec section 25.8 Context Lineage: immutable initial plan-derived capsules.

use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::INITIAL_CONTEXT_CAPSULE_SCHEMA;
use bullet_domain::{Digest, TaskClass};
use serde::Serialize;

#[derive(Serialize)]
struct ContextCapsuleRow {
    schema_version: &'static str,
    id: String,
    mission_id: String,
    work_package_id: String,
    plan_revision_id: String,
    revision: u64,
    parent_id: Option<String>,
    task_class: TaskClass,
    objective_digest: String,
    package_title_digest: String,
    content_digest: String,
    compression: &'static str,
    dropped_decision_digests: Vec<String>,
    recorded_at: String,
}

#[derive(Serialize)]
struct ContextLineageView {
    capsules: Vec<ContextCapsuleRow>,
}

/// Return Context Capsule subjects from one ledger snapshot.
pub(crate) async fn context_lineage(
    State(state): State<SharedState>,
) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (capsules, as_of_sequence) = ledger.read_snapshot(|ledger| {
        let capsules = ledger
            .list_context_capsules()?
            .into_iter()
            .map(|capsule| ContextCapsuleRow {
                schema_version: INITIAL_CONTEXT_CAPSULE_SCHEMA,
                id: capsule.id.to_string(),
                mission_id: capsule.mission_id.to_string(),
                work_package_id: capsule.work_package_id.to_string(),
                plan_revision_id: capsule.plan_revision_id.to_string(),
                revision: capsule.revision,
                parent_id: None,
                task_class: capsule.task_class,
                objective_digest: Digest::of(capsule.objective.as_bytes()).to_hex(),
                package_title_digest: Digest::of(capsule.package_title.as_bytes()).to_hex(),
                content_digest: capsule.content_digest.to_hex(),
                compression: "none",
                dropped_decision_digests: Vec::new(),
                recorded_at: capsule.recorded_at,
            })
            .collect();
        Ok(ContextLineageView { capsules })
    })?;
    snapshot_response(capsules, as_of_sequence)
}
