//! Event normalizer behavior over the public API: monotonic sequences,
//! duplicate/out-of-order/stale anomalies, malformed lines, serde names.

use bullet_harness_core::{AgentEventKind, AgentSessionId, EventNormalizer, NativeMeta};
use serde_json::json;
use std::collections::BTreeSet;

fn normalizer() -> EventNormalizer {
    EventNormalizer::new(AgentSessionId::new("ses-test"), "sim")
}

#[test]
fn kinds_are_26_and_unique() {
    let names: BTreeSet<_> = AgentEventKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), 26);
}

#[test]
fn kind_serde_uses_dotted_names() {
    let text = serde_json::to_string(&AgentEventKind::TurnDelta).unwrap();
    assert_eq!(text, "\"turn.delta\"");
    let back: AgentEventKind = serde_json::from_str("\"protocol.error\"").unwrap();
    assert_eq!(back, AgentEventKind::ProtocolError);
}

#[test]
fn sequences_are_monotonic() {
    let mut n = normalizer();
    let a = n.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none());
    let b = n.accept(AgentEventKind::TurnDelta, json!({}), &NativeMeta::none());
    assert!(b.sequence > a.sequence);
    assert_ne!(a.event_id, b.event_id);
}

#[test]
fn duplicate_native_event_becomes_anomaly() {
    let mut n = normalizer();
    let meta = NativeMeta {
        event_id: Some("n1".into()),
        sequence: None,
    };
    let first = n.accept(AgentEventKind::TurnDelta, json!({}), &meta);
    assert_eq!(first.kind, AgentEventKind::TurnDelta);
    let dup = n.accept(AgentEventKind::TurnDelta, json!({}), &meta);
    assert_eq!(dup.kind, AgentEventKind::ProtocolError);
    assert_eq!(dup.payload["reason_code"], "DUPLICATE_EVENT");
}

#[test]
fn out_of_order_native_sequence_becomes_anomaly() {
    let mut n = normalizer();
    let newer = NativeMeta {
        event_id: None,
        sequence: Some(5),
    };
    let older = NativeMeta {
        event_id: None,
        sequence: Some(3),
    };
    n.accept(AgentEventKind::TurnDelta, json!({}), &newer);
    let late = n.accept(AgentEventKind::TurnDelta, json!({}), &older);
    assert_eq!(late.payload["reason_code"], "OUT_OF_ORDER_EVENT");
}

#[test]
fn delta_after_turn_close_is_stale() {
    let mut n = normalizer();
    n.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none());
    n.accept(
        AgentEventKind::TurnCompleted,
        json!({}),
        &NativeMeta::none(),
    );
    let stale = n.accept(AgentEventKind::TurnDelta, json!({}), &NativeMeta::none());
    assert_eq!(stale.payload["reason_code"], "STALE_EVENT");
    let usage = n.accept(
        AgentEventKind::UsageReported,
        json!({}),
        &NativeMeta::none(),
    );
    assert_eq!(usage.kind, AgentEventKind::UsageReported);
}

#[test]
fn malformed_line_is_kept_as_anomaly() {
    let mut n = normalizer();
    let e = n.malformed("not-json{");
    assert_eq!(e.kind, AgentEventKind::ProtocolError);
    assert_eq!(e.payload["reason_code"], "MALFORMED_EVENT");
    assert_eq!(e.payload["detail"]["raw"], "not-json{");
}
