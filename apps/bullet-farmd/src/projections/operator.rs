//! One transaction for the composed operator console and Shift Brief.
//! Existing projection builders share the same ledger view; one corrupt subject
//! refuses the entire response instead of publishing a partial composition.

use super::{audit, context_lineage, fleet, merge_rail, quality_lab, sessions};
use crate::api::{
    mission_views, outbox_sequence, snapshot_response, MissionView, OutboxView, SharedState,
};
use crate::errors::ApiError;
use crate::leases;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::{Ledger, LedgerError};
use bullet_domain::Mission;
use serde::Serialize;

#[derive(Serialize)]
struct OperatorSnapshotView {
    missions: Vec<Mission>,
    graphs: Vec<MissionView>,
    outbox: OutboxView,
    ready: Option<leases::ReadyViewBody>,
    fleet: fleet::FleetView,
    sessions: sessions::SessionSupervisorView,
    context_lineage: context_lineage::ContextLineageView,
    merge_rail: merge_rail::MergeRailView,
    quality_lab: quality_lab::QualityLabView,
    audit: audit::AuditView,
}

fn read<L: Ledger + ProjectionReader>(ledger: &L) -> Result<OperatorSnapshotView, LedgerError> {
    let latest = ledger.latest_event_sequence()?;
    let events = ledger.list_events_after(latest.saturating_sub(audit::TAIL_WINDOW), 64)?;
    let audit = audit::build(latest, events)
        .map_err(|_| LedgerError::Store("operator snapshot audit tail is invalid".into()))?;
    Ok(OperatorSnapshotView {
        missions: ledger.list_missions()?,
        graphs: mission_views(ledger)?,
        outbox: OutboxView {
            items: ledger.outbox_all()?,
        },
        ready: leases::read(ledger)?,
        fleet: fleet::read(ledger)?,
        sessions: sessions::read(ledger)?,
        context_lineage: context_lineage::read(ledger)?,
        merge_rail: merge_rail::read(ledger)?,
        quality_lab: quality_lab::read(ledger)?,
        audit,
    })
}

pub(crate) async fn operator_snapshot(
    State(state): State<SharedState>,
) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, sequence) = ledger.read_snapshot(read)?;
    for item in &view.outbox.items {
        outbox_sequence(item.seq)?;
    }
    snapshot_response(view, sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_adapters::SqliteLedger;
    use bullet_application::run_demo;

    #[test]
    fn concurrent_commit_cannot_mix_operator_projection_subjects() {
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir = builder.tempdir().expect("private fixture directory");
        let db = dir.path().join("ledger.sqlite");
        let reader = SqliteLedger::open(&db).expect("reader");
        let mut writer = SqliteLedger::open(&db).expect("writer");
        let (before, sequence) = reader
            .read_snapshot(|ledger| {
                assert_eq!(ledger.latest_event_sequence()?, 0);
                run_demo(&mut writer).expect("independent writer commits during read snapshot");
                read(ledger)
            })
            .expect("same transaction despite external commit");
        let before = serde_json::to_value(before).expect("projection JSON");
        assert_eq!(sequence, 0);
        assert_eq!(before["audit"]["latest_sequence"], sequence);
        for field in ["missions", "graphs"] {
            assert_eq!(before[field].as_array().expect(field).len(), 0);
        }
        assert_eq!(before["sessions"]["attempts"].as_array().unwrap().len(), 0);
        assert_eq!(
            before["context_lineage"]["capsules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let (after, sequence) = reader.read_snapshot(read).expect("next complete snapshot");
        let after = serde_json::to_value(after).expect("projection JSON");
        assert!(sequence > 0);
        assert_eq!(after["audit"]["latest_sequence"], sequence);
        assert_eq!(after["missions"].as_array().unwrap().len(), 1);
        assert_eq!(after["graphs"][0]["mission"], after["missions"][0]);
        assert_eq!(after["sessions"]["attempts"].as_array().unwrap().len(), 2);
        assert_eq!(
            after["context_lineage"]["capsules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
