//! Cursor Agent stream-json parsing. The provider enforces no output
//! schema, so the PatchProposal is extracted from the final result text and
//! validated locally; failure to parse is an honest null.

use bullet_domain::Observation;
use bullet_harness_core::{
    AgentEvent, AgentEventKind, EventNormalizer, NativeMeta, PatchProposal, ProfileIdentity,
    RunOutcome,
};
use serde_json::{json, Value};

/// Normalize one finished invocation's stdout into envelopes.
pub fn normalize_outcome(
    normalizer: &mut EventNormalizer,
    outcome: &RunOutcome,
) -> Vec<AgentEvent> {
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
        });
        events.push(normalizer.accept(AgentEventKind::TurnFailed, payload, &NativeMeta::none()));
    }
    events
}

fn map_value(normalizer: &mut EventNormalizer, value: &Value) -> Vec<(AgentEventKind, Value)> {
    match value.get("type").and_then(Value::as_str) {
        Some("system") => {
            for key in ["chatId", "chat_id", "session_id"] {
                if let Some(native) = value.get(key).and_then(Value::as_str) {
                    normalizer.set_native_session(native);
                    break;
                }
            }
            if let Some(model) = value.get("model").and_then(Value::as_str) {
                normalizer.set_model(model);
            }
            vec![(AgentEventKind::SessionReady, value.clone())]
        }
        Some("assistant") => value
            .pointer("/message/content")
            .and_then(Value::as_array)
            .map(|content| {
                content
                    .iter()
                    .filter_map(|item| match item.get("type").and_then(Value::as_str) {
                        Some("text") => Some((
                            AgentEventKind::TurnDelta,
                            json!({ "text": item.get("text") }),
                        )),
                        Some("tool_use") => Some((
                            AgentEventKind::ToolRequested,
                            json!({ "tool": item.get("name") }),
                        )),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Some("result") => map_result(value),
        _ => Vec::new(),
    }
}

fn map_result(value: &Value) -> Vec<(AgentEventKind, Value)> {
    let mut events = Vec::new();
    if value.get("usage").is_some() || value.get("total_cost_usd").is_some() {
        events.push((
            AgentEventKind::UsageReported,
            json!({
                "usage": value.get("usage"),
                "total_cost_usd": value.get("total_cost_usd"),
                "duration_ms": value.get("duration_ms"),
            }),
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
    let proposal = value
        .get("result")
        .and_then(Value::as_str)
        .and_then(|text| PatchProposal::extract_from_text(text).ok())
        .and_then(|p| serde_json::to_value(p).ok())
        .unwrap_or(Value::Null);
    events.push((
        AgentEventKind::TurnCompleted,
        json!({ "proposal": proposal, "text": value.get("result") }),
    ));
    events
}

/// Parse `cursor-agent status` text output into an identity observation.
#[must_use]
pub fn parse_status(text: &str) -> Observation<ProfileIdentity> {
    let marker = "Logged in as ";
    let Some(index) = text.find(marker) else {
        return Observation::Unknown {
            source: "cursor-agent status".to_string(),
            reason: "no 'Logged in as' marker".to_string(),
        };
    };
    let email = text[index + marker.len()..]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    if email.is_empty() || !email.contains('@') {
        return Observation::Unknown {
            source: "cursor-agent status".to_string(),
            reason: "marker present but no email token".to_string(),
        };
    }
    Observation::value(ProfileIdentity {
        provider: "cursor".to_string(),
        email: Some(email),
        account_id: None,
        subscription: None,
        auth_method: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_harness_core::AgentSessionId;
    use std::time::Duration;

    fn outcome(lines: &[&str], exit: i32) -> RunOutcome {
        RunOutcome {
            stdout_lines: lines.iter().map(|s| (*s).to_string()).collect(),
            stderr: String::new(),
            exit_code: Some(exit),
            timed_out: false,
            wall: Duration::from_millis(5),
        }
    }

    fn normalizer() -> EventNormalizer {
        EventNormalizer::new(AgentSessionId::new("ses-cursor-test"), "cursor")
    }

    #[test]
    fn stream_with_json_result_yields_proposal() {
        let result = r#"{\"intent_summary\":\"x\",\"changes\":[{\"path\":\"PONG.txt\",\"op\":\"create\",\"contents\":\"PONG\"}],\"gate_ids\":[\"repo.gate.v1\"],\"claims\":[],\"uncertainties\":[],\"done\":true}"#;
        let lines = [
            r#"{"type":"system","subtype":"init","chatId":"chat-7","model":"m"}"#.to_string(),
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"emitting json"}]}}"#.to_string(),
            format!(r#"{{"type":"result","subtype":"success","result":"{result}","duration_ms":900}}"#),
        ];
        let refs: Vec<&str> = lines.iter().map(AsRef::as_ref).collect();
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&refs, 0));
        let completed = events
            .iter()
            .find(|e| e.kind == AgentEventKind::TurnCompleted)
            .expect("completed");
        assert_eq!(completed.payload["proposal"]["changes"][0]["op"], "create");
        assert_eq!(completed.native_session_id.as_deref(), Some("chat-7"));
    }

    #[test]
    fn prose_result_is_an_honest_null_proposal() {
        let line =
            r#"{"type":"result","subtype":"success","result":"I made a plan but here is prose"}"#;
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&[line], 0));
        let completed = events
            .iter()
            .find(|e| e.kind == AgentEventKind::TurnCompleted)
            .expect("completed");
        assert!(completed.payload["proposal"].is_null());
    }

    #[test]
    fn missing_result_and_malformed_lines_fail_typed() {
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&["garbage {{"], 1));
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AgentEventKind::ProtocolError));
        assert!(kinds.contains(&AgentEventKind::TurnFailed));
    }

    #[test]
    fn status_parses_and_fails_closed() {
        match parse_status("\u{2713} Logged in as ben@veox.ai\nPlan: pro") {
            Observation::Value { value } => {
                assert_eq!(value.email.as_deref(), Some("ben@veox.ai"));
            }
            other => panic!("expected identity, got {other:?}"),
        }
        assert!(matches!(
            parse_status("Not logged in"),
            Observation::Unknown { .. }
        ));
        assert!(matches!(
            parse_status("Logged in as "),
            Observation::Unknown { .. }
        ));
    }
}
