//! Honest accounting helpers for the deterministic simulator event stream.

use bullet_harness_core::{AgentEvent, AgentEventKind, SessionHandle};
use serde_json::Value;

/// Cost in one usage payload, wherever the provider put it.
fn payload_cost(payload: &Value) -> Option<f64> {
    payload
        .get("total_cost_usd")
        .and_then(Value::as_f64)
        .or_else(|| payload.get("cost_usd").and_then(Value::as_f64))
}

/// Sum of every reported usage cost across a session's events.
#[must_use]
pub fn events_cost(events: &[AgentEvent]) -> Option<f64> {
    let mut total = None;
    for event in events {
        if event.kind == AgentEventKind::UsageReported {
            if let Some(cost) = payload_cost(&event.payload) {
                total = Some(total.unwrap_or(0.0) + cost);
            }
        }
    }
    total
}

/// Provider-native session id from events, falling back to the handle.
#[must_use]
pub fn events_session(events: &[AgentEvent], handle: &SessionHandle) -> Option<String> {
    events
        .iter()
        .rev()
        .find_map(|event| event.native_session_id.clone())
        .or_else(|| handle.native_session_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cost_reads_both_provider_spellings_and_stays_honest() {
        assert_eq!(payload_cost(&json!({ "total_cost_usd": 0.5 })), Some(0.5));
        assert_eq!(payload_cost(&json!({ "cost_usd": 0.004 })), Some(0.004));
        assert_eq!(
            payload_cost(&json!({ "usage": { "input_tokens": 3 } })),
            None
        );
    }
}
