//! Codex `exec --json` NDJSON parsing. Supports both the thread/turn/item
//! event shape and the older `msg`-wrapped shape; the PatchProposal comes
//! from the `-o` last-message file, never from a provider claim.

use bullet_domain::Observation;
use bullet_harness_core::{
    AgentEvent, AgentEventKind, EventNormalizer, NativeMeta, PatchProposal, ProfileIdentity,
    RunOutcome,
};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

/// Normalize one finished invocation and its last-message file.
pub fn normalize_outcome(
    normalizer: &mut EventNormalizer,
    outcome: &RunOutcome,
    last_message: Option<&str>,
) -> Vec<AgentEvent> {
    let mut events = Vec::new();
    let mut failed = false;
    for line in &outcome.stdout_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => {
                for (kind, payload) in map_value(normalizer, &value) {
                    if kind == AgentEventKind::TurnFailed {
                        failed = true;
                    }
                    events.push(normalizer.accept(kind, payload, &NativeMeta::none()));
                }
            }
            Err(_) => events.push(normalizer.malformed(trimmed)),
        }
    }
    if failed {
        return events;
    }
    if outcome.timed_out || outcome.exit_code != Some(0) {
        let stderr_tail: String = outcome
            .stderr
            .chars()
            .rev()
            .take(400)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let payload = json!({
            "reason": "process did not exit cleanly",
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "stderr_tail": stderr_tail,
        });
        events.push(normalizer.accept(AgentEventKind::TurnFailed, payload, &NativeMeta::none()));
        return events;
    }
    let (proposal, text) = match last_message {
        Some(text) => (
            PatchProposal::extract_from_text(text)
                .ok()
                .and_then(|p| serde_json::to_value(p).ok())
                .unwrap_or(Value::Null),
            Value::String(text.to_string()),
        ),
        None => (Value::Null, Value::Null),
    };
    let payload = json!({ "proposal": proposal, "text": text });
    events.push(normalizer.accept(AgentEventKind::TurnCompleted, payload, &NativeMeta::none()));
    events
}

fn map_value(normalizer: &mut EventNormalizer, value: &Value) -> Vec<(AgentEventKind, Value)> {
    if let Some(kind) = value.get("type").and_then(Value::as_str) {
        return map_typed(normalizer, kind, value);
    }
    if let Some(msg) = value.get("msg") {
        return map_msg(normalizer, msg);
    }
    Vec::new()
}

fn map_typed(
    normalizer: &mut EventNormalizer,
    kind: &str,
    value: &Value,
) -> Vec<(AgentEventKind, Value)> {
    match kind {
        "thread.started" => {
            if let Some(thread) = value.get("thread_id").and_then(Value::as_str) {
                normalizer.set_native_session(thread);
            }
            vec![(AgentEventKind::SessionReady, value.clone())]
        }
        "turn.started" => Vec::new(),
        "item.started" => match value.pointer("/item/type").and_then(Value::as_str) {
            Some("command_execution") => vec![(
                AgentEventKind::ToolStarted,
                json!({ "command": value.pointer("/item/command") }),
            )],
            _ => Vec::new(),
        },
        "item.completed" => map_item(value),
        "turn.completed" => vec![(
            AgentEventKind::UsageReported,
            json!({ "usage": value.get("usage") }),
        )],
        "turn.failed" | "error" => vec![(AgentEventKind::TurnFailed, value.clone())],
        _ => Vec::new(),
    }
}

fn map_item(value: &Value) -> Vec<(AgentEventKind, Value)> {
    match value.pointer("/item/type").and_then(Value::as_str) {
        Some("agent_message") => vec![(
            AgentEventKind::TurnDelta,
            json!({ "text": value.pointer("/item/text") }),
        )],
        Some("reasoning") => vec![(
            AgentEventKind::ThinkingDelta,
            json!({ "text": value.pointer("/item/text") }),
        )],
        Some("command_execution") => vec![(
            AgentEventKind::ToolCompleted,
            json!({
                "command": value.pointer("/item/command"),
                "exit_code": value.pointer("/item/exit_code"),
            }),
        )],
        _ => Vec::new(),
    }
}

fn map_msg(normalizer: &mut EventNormalizer, msg: &Value) -> Vec<(AgentEventKind, Value)> {
    match msg.get("type").and_then(Value::as_str) {
        Some("session_configured") => {
            if let Some(session) = msg.get("session_id").and_then(Value::as_str) {
                normalizer.set_native_session(session);
            }
            vec![(AgentEventKind::SessionReady, msg.clone())]
        }
        Some("agent_message") => vec![(
            AgentEventKind::TurnDelta,
            json!({ "text": msg.get("message") }),
        )],
        Some("agent_reasoning") => vec![(
            AgentEventKind::ThinkingDelta,
            json!({ "text": msg.get("text") }),
        )],
        Some("token_count") => vec![(AgentEventKind::UsageReported, msg.clone())],
        Some("error") => vec![(AgentEventKind::TurnFailed, msg.clone())],
        _ => Vec::new(),
    }
}

pub(crate) fn append_raw(path: &Path, outcome: &RunOutcome) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        for line in &outcome.stdout_lines {
            let _ = writeln!(file, "{line}");
        }
        if !outcome.stderr.is_empty() {
            let _ = writeln!(file, "{}", json!({ "stderr": outcome.stderr }));
        }
    }
}

/// Parse `~/.codex/auth.json` into an identity observation.
#[must_use]
pub fn parse_auth_json(text: &str) -> Observation<ProfileIdentity> {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Observation::Unknown {
            source: "codex auth.json".to_string(),
            reason: "not valid json".to_string(),
        };
    };
    let account_id = value
        .pointer("/tokens/account_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    if account_id.is_none() {
        return Observation::Unknown {
            source: "codex auth.json".to_string(),
            reason: "no tokens.account_id".to_string(),
        };
    }
    Observation::value(ProfileIdentity {
        provider: "codex".to_string(),
        email: None,
        account_id,
        subscription: None,
        auth_method: value
            .get("auth_mode")
            .and_then(Value::as_str)
            .map(str::to_string),
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
        EventNormalizer::new(AgentSessionId::new("ses-codex-test"), "codex")
    }

    const LAST: &str = r#"{"intent_summary":"x","changes":[{"path":"PONG.txt","op":"create","contents":"PONG"}],"gate_ids":["repo.gate.v1"],"claims":[],"uncertainties":[],"done":true}"#;

    #[test]
    fn thread_events_and_last_message_map() {
        let lines = [
            r#"{"type":"thread.started","thread_id":"th_1"}"#,
            r#"{"type":"turn.started"}"#,
            r#"{"type":"item.completed","item":{"type":"agent_message","text":"writing"}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}"#,
        ];
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&lines, 0), Some(LAST));
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
        assert_eq!(completed.native_session_id.as_deref(), Some("th_1"));
    }

    #[test]
    fn msg_shape_and_failures_map() {
        let lines = [
            r#"{"id":"0","msg":{"type":"session_configured","session_id":"s_9"}}"#,
            r#"{"id":"1","msg":{"type":"agent_message","message":"hi"}}"#,
            r#"{"id":"2","msg":{"type":"error","message":"boom"}}"#,
        ];
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&lines, 0), Some(LAST));
        assert!(events.iter().any(|e| e.kind == AgentEventKind::TurnFailed));
        assert!(!events
            .iter()
            .any(|e| e.kind == AgentEventKind::TurnCompleted));
    }

    #[test]
    fn nonzero_exit_without_events_is_turn_failed() {
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&["not json {"], 2), None);
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AgentEventKind::ProtocolError));
        assert!(kinds.contains(&AgentEventKind::TurnFailed));
    }

    #[test]
    fn auth_json_parses_and_fails_closed() {
        let good = r#"{"auth_mode":"chatgpt","tokens":{"account_id":"016926d0-c801"}}"#;
        match parse_auth_json(good) {
            Observation::Value { value } => {
                assert!(value.account_id.unwrap().starts_with("016926d0"));
                assert_eq!(value.auth_method.as_deref(), Some("chatgpt"));
            }
            other => panic!("expected identity, got {other:?}"),
        }
        assert!(matches!(parse_auth_json("{}"), Observation::Unknown { .. }));
        assert!(matches!(
            parse_auth_json("junk"),
            Observation::Unknown { .. }
        ));
    }
}
