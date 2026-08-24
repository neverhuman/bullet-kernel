//! One bounded provider turn: start a session, send a prompt, harvest the
//! result text plus honest usage. Failures are typed strings, never panics.

use bullet_harness_core::{
    AgentEvent, AgentEventKind, AgentSessionId, HarnessAdapter, SessionHandle, StartSession, Turn,
};
use futures::StreamExt;
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

/// Outcome of one bounded provider turn.
#[derive(Clone, Debug)]
pub struct TurnRecord {
    /// Provider-native session id when reported.
    pub session: Option<String>,
    /// Final result text of the turn.
    pub text: Option<String>,
    /// Reported spend in USD; `None` is honest not-reported, never zero.
    pub cost_usd: Option<f64>,
    /// Wall time of the whole turn in milliseconds.
    pub wall_ms: u64,
    /// Typed failure when the turn did not complete.
    pub failure: Option<String>,
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max).collect();
    format!("{cut}…")
}

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

fn close_of(events: &[AgentEvent]) -> Option<(AgentEventKind, Value)> {
    let mut last = None;
    for event in events {
        if matches!(
            event.kind,
            AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed
        ) {
            last = Some((event.kind, event.payload.clone()));
        }
    }
    last
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Run one bounded turn: fresh session, one prompt, terminate.
pub async fn one_turn(
    adapter: &dyn HarnessAdapter,
    session_seed: &str,
    workdir: &Path,
    artifact_dir: &Path,
    prompt: &str,
    wall: Duration,
) -> TurnRecord {
    let started = Instant::now();
    let request = StartSession {
        session_id: AgentSessionId::new(session_seed),
        workdir: workdir.to_path_buf(),
        artifact_dir: artifact_dir.to_path_buf(),
        model: None,
        structured_schema: None,
        max_budget_usd: None, // the CappedAdapter injects the ADR 0001 cap
        wall_timeout: wall,
    };
    let handle = match adapter.start(request).await {
        Ok(handle) => handle,
        Err(err) => {
            return TurnRecord {
                session: None,
                text: None,
                cost_usd: None,
                wall_ms: elapsed_ms(started),
                failure: Some(format!("ADAPTER_START:{}: {err}", err.reason_code())),
            }
        }
    };
    let sent = adapter
        .send(
            &handle,
            Turn {
                prompt: prompt.to_string(),
            },
        )
        .await;
    let events: Vec<AgentEvent> = adapter.events(&handle).collect().await;
    let _ = adapter.terminate(&handle).await;
    let mut record = TurnRecord {
        session: events_session(&events, &handle),
        text: None,
        cost_usd: events_cost(&events),
        wall_ms: elapsed_ms(started),
        failure: None,
    };
    if let Err(err) = sent {
        record.failure = Some(format!("ADAPTER_SEND:{}: {err}", err.reason_code()));
        return record;
    }
    match close_of(&events) {
        Some((AgentEventKind::TurnCompleted, payload)) => {
            if let Some(native) = payload.get("native_session_id").and_then(Value::as_str) {
                record.session = Some(native.to_string());
            }
            record.text = payload
                .get("text")
                .and_then(Value::as_str)
                .map(ToString::to_string);
        }
        Some((_, payload)) => {
            record.failure = Some(format!(
                "TURN_FAILED: {}",
                truncate(&payload.to_string(), 300)
            ));
        }
        None => {
            record.failure =
                Some("NO_TURN_CLOSE: stream ended without a close envelope".to_string());
        }
    }
    record
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

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("ééééé", 2), "éé…");
    }
}
