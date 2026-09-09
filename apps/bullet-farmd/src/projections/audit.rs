//! Spec section 25.15 Incidents and Audit: a bounded tail of the durable
//! event log read atomically with its watermark. Every returned event passes
//! the same envelope integrity check as the SSE stream, and a sequence gap
//! inside the tail is a store failure, never a shorter list.

use crate::api::{snapshot_response, validate_event, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::{Ledger, LedgerEvent};
use serde::Serialize;

/// Maximum events in one tail read.
pub(crate) const TAIL_WINDOW: u64 = 64;

#[derive(Serialize)]
pub(crate) struct AuditEvent {
    id: String,
    seq: u64,
    at: String,
    kind: String,
    body: String,
    stream_id: Option<String>,
    correlation_id: Option<String>,
}

/// Audit projection body.
#[derive(Serialize)]
pub(crate) struct AuditView {
    latest_sequence: u64,
    tail_window: u64,
    events: Vec<AuditEvent>,
}

pub(crate) fn build(latest_sequence: u64, events: Vec<LedgerEvent>) -> Result<AuditView, ApiError> {
    let mut expected = latest_sequence
        .saturating_sub(TAIL_WINDOW)
        .saturating_add(1)
        .min(latest_sequence.saturating_add(1));
    let mut rows = Vec::with_capacity(events.len());
    for event in events {
        validate_event(&event)?;
        if event.seq != expected {
            return Err(ApiError::Internal(format!(
                "durable event tail has a sequence gap before {}",
                event.seq
            )));
        }
        expected = expected.saturating_add(1);
        let id = event
            .event_id
            .ok_or_else(|| ApiError::Internal("durable event id is absent".into()))?;
        rows.push(AuditEvent {
            id,
            seq: event.seq,
            at: event.at,
            kind: event.kind,
            body: event.body,
            stream_id: event.stream_id,
            correlation_id: event.correlation_id,
        });
    }
    if expected != latest_sequence.saturating_add(1) {
        return Err(ApiError::Internal(
            "durable event tail is shorter than its watermark".into(),
        ));
    }
    Ok(AuditView {
        latest_sequence,
        tail_window: TAIL_WINDOW,
        events: rows,
    })
}

pub(crate) async fn audit(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let ((latest, events), as_of_sequence) = ledger.read_snapshot(|ledger| {
        let latest = ledger.latest_event_sequence()?;
        let after = latest.saturating_sub(TAIL_WINDOW);
        let limit = usize::try_from(TAIL_WINDOW)
            .map_err(|err| bullet_application::LedgerError::Store(err.to_string()))?;
        Ok((latest, ledger.list_events_after(after, limit)?))
    })?;
    if latest != as_of_sequence {
        return Err(ApiError::Internal(
            "snapshot returned inconsistent audit watermark".into(),
        ));
    }
    let view = build(latest, events)?;
    snapshot_response(view, as_of_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::Digest;

    fn event(seq: u64) -> LedgerEvent {
        let kind = "fixture";
        let body = seq.to_string();
        LedgerEvent {
            seq,
            at: "2026-08-25T00:00:00.000Z".into(),
            kind: kind.into(),
            body: body.clone(),
            event_id: Some(Digest::of(format!("evt:{seq}:{kind}:{body}").as_bytes()).to_hex()),
            stream_id: None,
            sequence: Some(seq),
            causation_id: None,
            correlation_id: None,
            authority_token_hash: None,
        }
    }

    #[test]
    fn empty_log_projects_zero_events_at_watermark_zero() {
        let view = build(0, Vec::new()).ok().expect("empty tail");
        assert_eq!((view.latest_sequence, view.events.len()), (0, 0));
    }

    #[test]
    fn contiguous_tail_is_accepted_and_gaps_or_shortfalls_are_failures() {
        let view = build(3, vec![event(1), event(2), event(3)])
            .ok()
            .expect("contiguous");
        assert_eq!(view.events.len(), 3);
        assert!(build(3, vec![event(1), event(3)]).is_err());
        assert!(build(3, vec![event(1), event(2)]).is_err());
        let mut corrupt = event(1);
        corrupt.event_id = Some("bad".into());
        assert!(build(1, vec![corrupt]).is_err());
        let view = build(100, (37..=100).map(event).collect())
            .ok()
            .expect("bounded tail");
        assert_eq!(view.events.first().map(|row| row.seq), Some(37));
    }
}
