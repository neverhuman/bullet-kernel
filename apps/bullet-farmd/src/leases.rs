//! Read-only readiness projection. Runner mutation RPC is intentionally not
//! mounted on the public browser API until its separate authenticated transport
//! is implemented.

use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::{Ledger, LedgerError, StoredGraph};
use bullet_domain::{VariantId, WorkPackageId};
use serde::Serialize;

fn graph_for_package<L: Ledger>(
    ledger: &L,
    package: &WorkPackageId,
) -> Result<Option<(StoredGraph, VariantId)>, LedgerError> {
    for mission in ledger.list_missions()? {
        let Some(graph) = ledger.get_graph(&mission.id)? else {
            continue;
        };
        if let Some(variant_id) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == *package)
            .map(|variant| variant.id.clone())
        {
            return Ok(Some((graph, variant_id)));
        }
    }
    Ok(None)
}

#[derive(Serialize)]
struct ReadyViewBody {
    work_package_id: String,
    mission_id: String,
    variant_id: String,
    title: String,
    enqueued_at: String,
}

pub(crate) async fn next_ready(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(|ledger| {
        let Some(row) = ledger.ready_rows()?.into_iter().next() else {
            return Ok(None);
        };
        let (graph, variant_id) = graph_for_package(ledger, &row.work_package_id)?
            .ok_or_else(|| LedgerError::Store("ready row has no owning graph variant".into()))?;
        let title = graph
            .packages
            .iter()
            .find(|package| package.id == row.work_package_id)
            .map(|package| package.title.clone())
            .ok_or_else(|| LedgerError::Store("ready row package is absent from graph".into()))?;
        Ok(Some(ReadyViewBody {
            work_package_id: row.work_package_id.to_string(),
            mission_id: graph.mission.id.to_string(),
            variant_id: variant_id.to_string(),
            title,
            enqueued_at: row.enqueued_at,
        }))
    })?;
    snapshot_response(view, as_of_sequence)
}
