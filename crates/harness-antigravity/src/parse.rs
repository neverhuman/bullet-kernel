//! Antigravity text output handling: the whole stdout is one final text;
//! a fenced ```diff block is extracted best-effort. There is no structured
//! surface, so a proposal is always null here.

use bullet_harness_core::{AgentEvent, AgentEventKind, EventNormalizer, NativeMeta, RunOutcome};
use serde_json::{json, Value};

/// Normalize one finished text invocation into envelopes.
pub fn normalize_outcome(
    normalizer: &mut EventNormalizer,
    outcome: &RunOutcome,
) -> Vec<AgentEvent> {
    let mut events = Vec::new();
    let text = outcome.stdout_lines.join("\n");
    if outcome.timed_out || outcome.exit_code != Some(0) {
        let payload = json!({
            "reason": "process did not exit cleanly",
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "stderr_tail": outcome.stderr.chars().rev().take(400).collect::<String>()
                .chars().rev().collect::<String>(),
        });
        events.push(normalizer.accept(AgentEventKind::TurnFailed, payload, &NativeMeta::none()));
        return events;
    }
    let diff = extract_diff(&text).map_or(Value::Null, Value::String);
    let payload = json!({ "proposal": null, "text": text, "diff": diff });
    events.push(normalizer.accept(AgentEventKind::TurnCompleted, payload, &NativeMeta::none()));
    events
}

/// Extract the first fenced ```diff block, if any.
#[must_use]
pub fn extract_diff(text: &str) -> Option<String> {
    let fence = "```diff";
    let start = text.find(fence)? + fence.len();
    let rest = &text[start..];
    let end = rest.find("```")?;
    let body = rest[..end].trim();
    if body.is_empty() {
        None
    } else {
        Some(body.to_string())
    }
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
        EventNormalizer::new(AgentSessionId::new("ses-agy-test"), "agy")
    }

    #[test]
    fn text_with_diff_fence_is_extracted() {
        let lines = [
            "Here is the change:",
            "```diff",
            "--- /dev/null",
            "+++ b/PONG.txt",
            "@@ -0,0 +1 @@",
            "+PONG",
            "```",
            "Done.",
        ];
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&lines, 0));
        let completed = events
            .iter()
            .find(|e| e.kind == AgentEventKind::TurnCompleted)
            .expect("completed");
        assert!(
            completed.payload["proposal"].is_null(),
            "text-only, never a proposal"
        );
        let diff = completed.payload["diff"].as_str().expect("diff extracted");
        assert!(diff.contains("+PONG"));
    }

    #[test]
    fn plain_text_has_null_diff() {
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&["no diff here"], 0));
        let completed = &events[0];
        assert_eq!(completed.kind, AgentEventKind::TurnCompleted);
        assert!(completed.payload["diff"].is_null());
    }

    #[test]
    fn nonzero_exit_is_turn_failed() {
        let mut n = normalizer();
        let events = normalize_outcome(&mut n, &outcome(&["partial"], 3));
        assert_eq!(events[0].kind, AgentEventKind::TurnFailed);
    }

    #[test]
    fn empty_fence_is_none() {
        assert!(extract_diff("```diff\n\n```").is_none());
        assert!(extract_diff("nothing").is_none());
    }
}
