//! Claude Code stream-json line parsing. Every raw line is kept in the
//! session artifact; unknown-but-valid JSON types are skipped, malformed
//! lines become protocol.error anomalies.

use bullet_domain::Observation;
use bullet_harness_core::{
    AgentEventKind, EventNormalizer, NativeMeta, PatchProposal, ProfileIdentity, RunOutcome,
};
use serde_json::{json, Value};

/// Normalize one finished invocation's stdout into envelopes.
pub fn normalize_outcome(
    normalizer: &mut EventNormalizer,
    outcome: &RunOutcome,
) -> Vec<bullet_harness_core::AgentEvent> {
    let mut events = Vec::new();
    let mut saw_turn_end = false;
    for line in &outcome.stdout_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => {
                for (kind, payload) in map_value(normalizer, &value) {
                    if matches!(
                        kind,
                        AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed
                    ) {
                        saw_turn_end = true;
                    }
                    events.push(normalizer.accept(kind, payload, &NativeMeta::none()));
                }
            }
            Err(_) => events.push(normalizer.malformed(trimmed)),
        }
    }
    if !saw_turn_end {
        let payload = json!({
            "reason": "stream ended without a result event",
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "stderr_tail": tail(&outcome.stderr, 400),
        });
        events.push(normalizer.accept(AgentEventKind::TurnFailed, payload, &NativeMeta::none()));
    }
    events
}

fn tail(text: &str, max: usize) -> String {
    let start = text.len().saturating_sub(max);
    text[start..].to_string()
}

fn map_value(normalizer: &mut EventNormalizer, value: &Value) -> Vec<(AgentEventKind, Value)> {
    match value.get("type").and_then(Value::as_str) {
        Some("system") => map_system(normalizer, value),
        Some("assistant") => map_message(value, true),
        Some("user") => map_message(value, false),
        Some("result") => map_result(value),
        _ => Vec::new(),
    }
}

fn map_system(normalizer: &mut EventNormalizer, value: &Value) -> Vec<(AgentEventKind, Value)> {
    if value.get("subtype").and_then(Value::as_str) != Some("init") {
        return Vec::new();
    }
    if let Some(native) = value.get("session_id").and_then(Value::as_str) {
        normalizer.set_native_session(native);
    }
    if let Some(model) = value.get("model").and_then(Value::as_str) {
        normalizer.set_model(model);
    }
    vec![
        (AgentEventKind::SessionReady, value.clone()),
        (
            AgentEventKind::SessionIdentity,
            json!({ "session_id": value.get("session_id"), "model": value.get("model") }),
        ),
    ]
}

fn map_message(value: &Value, assistant: bool) -> Vec<(AgentEventKind, Value)> {
    let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut events = Vec::new();
    for item in content {
        match item.get("type").and_then(Value::as_str) {
            Some("text") if assistant => {
                events.push((
                    AgentEventKind::TurnDelta,
                    json!({ "text": item.get("text") }),
                ));
            }
            Some("thinking") if assistant => {
                events.push((
                    AgentEventKind::ThinkingDelta,
                    json!({ "text": item.get("thinking") }),
                ));
            }
            Some("tool_use") if assistant => {
                events.push((
                    AgentEventKind::ToolRequested,
                    json!({ "tool": item.get("name"), "input": item.get("input") }),
                ));
            }
            Some("tool_result") if !assistant => {
                events.push((
                    AgentEventKind::ToolCompleted,
                    json!({ "is_error": item.get("is_error") }),
                ));
            }
            _ => {}
        }
    }
    events
}

fn map_result(value: &Value) -> Vec<(AgentEventKind, Value)> {
    let mut events = Vec::new();
    let usage = value.get("usage").cloned().unwrap_or(Value::Null);
    let cost = value.get("total_cost_usd").cloned().unwrap_or(Value::Null);
    if !usage.is_null() || !cost.is_null() {
        events.push((
            AgentEventKind::UsageReported,
            json!({ "usage": usage, "total_cost_usd": cost, "duration_ms": value.get("duration_ms") }),
        ));
    }
    let is_error = value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || value
            .get("subtype")
            .and_then(Value::as_str)
            .is_some_and(|s| s != "success");
    if is_error {
        events.push((
            AgentEventKind::TurnFailed,
            json!({ "reason": value.get("subtype"), "result": value.get("result") }),
        ));
        return events;
    }
    let proposal = extract_proposal(value);
    events.push((
        AgentEventKind::TurnCompleted,
        json!({
            "proposal": proposal,
            "text": value.get("result"),
            "native_session_id": value.get("session_id"),
        }),
    ));
    events
}

fn extract_proposal(value: &Value) -> Value {
    if let Some(structured) = value.get("structured_output") {
        if let Ok(p) = PatchProposal::from_value(structured) {
            return serde_json::to_value(p).unwrap_or(Value::Null);
        }
    }
    if let Some(text) = value.get("result").and_then(Value::as_str) {
        if let Ok(p) = PatchProposal::extract_from_text(text) {
            return serde_json::to_value(p).unwrap_or(Value::Null);
        }
    }
    Value::Null
}

/// Parse `claude auth status` JSON output into an identity observation.
#[must_use]
pub fn parse_auth_status(text: &str) -> Observation<ProfileIdentity> {
    let Some(start) = text.find('{') else {
        return Observation::Unknown {
            source: "claude auth status".to_string(),
            reason: "no json in output".to_string(),
        };
    };
    let Ok(value) = serde_json::from_str::<Value>(text[start..].trim()) else {
        return Observation::Unknown {
            source: "claude auth status".to_string(),
            reason: "output not valid json".to_string(),
        };
    };
    if value.get("loggedIn").and_then(Value::as_bool) != Some(true) {
        return Observation::Unknown {
            source: "claude auth status".to_string(),
            reason: "not logged in".to_string(),
        };
    }
    Observation::value(ProfileIdentity {
        provider: "claude".to_string(),
        email: value
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_string),
        account_id: value
            .get("orgId")
            .and_then(Value::as_str)
            .map(str::to_string),
        subscription: value
            .get("subscriptionType")
            .and_then(Value::as_str)
            .map(str::to_string),
        auth_method: value
            .get("authMethod")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_harness_core::AgentSessionId;

    fn outcome(lines: &[&str], exit: i32) -> RunOutcome {
        RunOutcome {
            stdout_lines: lines.iter().map(|s| (*s).to_string()).collect(),
            stderr: String::new(),
            exit_code: Some(exit),
            timed_out: false,
            wall: std::time::Duration::from_millis(5),
        }
    }

    fn normalizer() -> EventNormalizer {
        EventNormalizer::new(AgentSessionId::new("ses-claude-test"), "claude")
    }

    #[test]
    fn happy_stream_maps_to_envelopes() {
        let proposal = r#"{\"intent_summary\":\"x\",\"changes\":[{\"path\":\"PONG.txt\",\"op\":\"create\",\"contents\":\"PONG\"}],\"gate_ids\":[\"repo.gate.v1\"],\"claims\":[],\"uncertainties\":[],\"done\":true}"#;
        let lines = [
            r#"{"type":"system","subtype":"init","session_id":"abc-123","model":"claude-x","tools":[]}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}"#,
            &format!(
                r#"{{"type":"result","subtype":"success","is_error":false,"result":"{}","total_cost_usd":0.01,"usage":{{"input_tokens":10,"output_tokens":5}},"session_id":"abc-123"}}"#,
                proposal
            ),
        ];
        let mut n = normalizer();
        let refs: Vec<&str> = lines.iter().map(AsRef::as_ref).collect();
        let events = normalize_outcome(&mut n, &outcome(&refs, 0));
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AgentEventKind::SessionReady));
        assert!(kinds.contains(&AgentEventKind::TurnDelta));
        assert!(kinds.contains(&AgentEventKind::UsageReported));
        let completed = events
            .iter()
            .find(|e| e.kind == AgentEventKind::TurnCompleted)
            .expect("completed");
        assert_eq!(
            completed.payload["proposal"]["changes"][0]["path"],
            "PONG.txt"
        );
        assert_eq!(completed.native_session_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn malformed_line_and_missing_result_are_typed() {
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&["nonsense {"], 1));
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AgentEventKind::ProtocolError));
        assert!(kinds.contains(&AgentEventKind::TurnFailed));
    }

    #[test]
    fn error_result_maps_to_turn_failed() {
        let line = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"boom"}"#;
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&[line], 1));
        assert!(events.iter().any(|e| e.kind == AgentEventKind::TurnFailed));
        assert!(!events
            .iter()
            .any(|e| e.kind == AgentEventKind::TurnCompleted));
    }

    #[test]
    fn auth_status_parses_and_fails_closed() {
        let logged_in =
            r#"{"loggedIn":true,"email":"ben@veox.ai","orgId":"o1","subscriptionType":"max"}"#;
        match parse_auth_status(logged_in) {
            Observation::Value { value } => {
                assert_eq!(value.email.as_deref(), Some("ben@veox.ai"));
                assert_eq!(value.subscription.as_deref(), Some("max"));
            }
            other => panic!("expected identity, got {other:?}"),
        }
        assert!(matches!(
            parse_auth_status(r#"{"loggedIn":false}"#),
            Observation::Unknown { .. }
        ));
        assert!(matches!(
            parse_auth_status("garbage"),
            Observation::Unknown { .. }
        ));
    }
}
