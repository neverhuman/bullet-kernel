//! Exact read-only tool request/result lifecycle for dogfood transcripts.

use super::{basic_event_subject, exact_fields};
use crate::protocol::{
    valid_native_id, ClaudeStreamTranscript, Phase, MAX_ASSISTANT_CONTENT_ITEMS,
};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

impl ClaudeStreamTranscript {
    pub(super) fn admit_tool_request(
        &mut self,
        item: &Map<String, Value>,
    ) -> Result<Value, HarnessError> {
        let item_required = ["type", "id", "name", "input"];
        // Real builds add `caller` to the tool_use item; it names who
        // requested the tool, not what it may do.
        let item_ok = if self.profile.admits_vendor_fields() {
            item_required.iter().all(|key| item.contains_key(*key))
        } else {
            exact_fields(item, &item_required, &[])
        };
        if !item_ok
            || item.get("type").and_then(Value::as_str) != Some("tool_use")
            || !item.get("input").is_some_and(Value::is_object)
        {
            return self.fail("unadmitted read-only tool request");
        }
        let Some(tool_use_id) = item.get("id").and_then(Value::as_str) else {
            return self.fail("read-only tool request lacks an id");
        };
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            return self.fail("read-only tool request lacks a name");
        };
        if !valid_native_id(tool_use_id) {
            return self.fail("read-only tool request exceeds admission");
        }
        // A request naming a tool outside the allowlist is not, by itself, an
        // escape: the runtime refuses it. Claude Code in plan mode routinely
        // asks for `Write` to save its plan file and is told "No such tool
        // available: Write. Write is disabled for this session" -- observed on
        // 2.1.266. Poisoning on the REQUEST made real turns fail at random
        // after they had been billed, and it graded the containment by what
        // the model wanted rather than by what it got. The request is recorded
        // instead, and its result is required to be an error below: an
        // unadmitted tool that actually SUCCEEDS still poisons the transcript.
        let admitted = self.profile.tool_allowlist().contains(&name);
        if !admitted && !self.profile.admits_vendor_fields() {
            return self.fail("read-only tool request exceeds admission");
        }
        if self.seen_tool_use_ids.contains(tool_use_id)
            || self.outstanding_tool_use_ids.contains(tool_use_id)
        {
            return self.fail("tool request id is duplicate or already outstanding");
        }
        self.seen_tool_use_ids.insert(tool_use_id.to_string());
        self.outstanding_tool_use_ids
            .insert(tool_use_id.to_string());
        if !admitted {
            self.refused_tool_use_ids.insert(tool_use_id.to_string());
        }
        Ok(json!({
            "tool_use_id": tool_use_id,
            "name": name,
            "admitted": admitted,
            "authoritative": false,
        }))
    }

    /// Consume one `user` frame carrying results for exact outstanding tools.
    pub(super) fn tool_result(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Active, "tool result")?;
        let envelope_required = [
            "type",
            "uuid",
            "session_id",
            "message",
            "parent_tool_use_id",
        ];
        // Real `user` frames carry `timestamp`, `isSynthetic` and a
        // `tool_use_result` echo (a string on 2.1.266). None of them is
        // authority; the admitted content array below is.
        let envelope_ok = if self.profile.admits_vendor_fields() {
            envelope_required
                .iter()
                .all(|key| object.contains_key(*key))
        } else {
            exact_fields(object, &envelope_required, &[])
        };
        if !envelope_ok || !object.get("parent_tool_use_id").is_some_and(Value::is_null) {
            return self.fail("tool result envelope is not an exact main-session frame");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("tool result has invalid event subject");
        };
        self.require_native_session(session_id)?;
        let Some(message) = object.get("message").and_then(Value::as_object) else {
            return self.fail("tool result message is not an object");
        };
        let message_ok = if self.profile.admits_vendor_fields() {
            ["role", "content"]
                .iter()
                .all(|key| message.contains_key(*key))
        } else {
            exact_fields(message, &["role", "content"], &[])
        };
        if !message_ok || message.get("role").and_then(Value::as_str) != Some("user") {
            return self.fail("tool result message subject is malformed");
        }
        let Some(content) = message.get("content").and_then(Value::as_array) else {
            return self.fail("tool result content is not an array");
        };
        if content.is_empty() || content.len() > MAX_ASSISTANT_CONTENT_ITEMS {
            return self.fail("tool result content item count is outside admission");
        }

        // A synthetic user frame is the CLI instructing the model, not a tool
        // result and not model output: 2.1.266 emits
        // `[structured-output-enforce] You MUST call the StructuredOutput
        // tool` this way whenever `--json-schema` is set. It carries only text,
        // settles no outstanding request, and yields no event, so admitting it
        // records nothing and grants nothing -- but refusing it refused every
        // schema-bearing turn.
        if self.profile.admits_vendor_fields()
            && object.get("isSynthetic").and_then(Value::as_bool) == Some(true)
        {
            let text_only = content.iter().all(|item| {
                item.as_object()
                    .and_then(|item| item.get("type"))
                    .and_then(Value::as_str)
                    == Some("text")
            });
            if text_only {
                self.record_event(uuid)?;
                self.synthetic_user_frames = self.synthetic_user_frames.saturating_add(1);
                return Ok(Vec::new());
            }
        }

        let mut ids = Vec::with_capacity(content.len());
        for item in content {
            let Some(item) = item.as_object() else {
                return self.fail("tool result content item is not an object");
            };
            if item.get("type").and_then(Value::as_str) != Some("tool_result")
                || !exact_fields(item, &["type", "tool_use_id", "content"], &["is_error"])
                || !item.get("is_error").is_none_or(Value::is_boolean)
            {
                return self.fail("unadmitted tool result content item");
            }
            let Some(tool_use_id) = item.get("tool_use_id").and_then(Value::as_str) else {
                return self.fail("tool result lacks its request id");
            };
            if !valid_native_id(tool_use_id) {
                return self.fail("tool result request id is malformed");
            }
            ids.push(tool_use_id);
        }
        if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
            || ids
                .iter()
                .any(|id| !self.outstanding_tool_use_ids.contains(*id))
        {
            return self.fail("tool result is duplicate or has no outstanding request");
        }

        self.record_event(uuid)?;
        let mut mapped = Vec::with_capacity(content.len());
        for (index, (item, tool_use_id)) in content.iter().zip(ids).enumerate() {
            let Some(item) = item.as_object() else {
                return self.fail("validated tool result content changed shape");
            };
            if !self.outstanding_tool_use_ids.remove(tool_use_id) {
                return self.fail("validated outstanding tool id disappeared");
            }
            let failed = item
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // The security property, stated exactly: no tool outside the
            // allowlist may ever report success. A refusal is the containment
            // working; a success is an escape.
            if self.refused_tool_use_ids.remove(tool_use_id) && !failed {
                return self.fail("a tool outside the read-only allowlist reported success");
            }
            let kind = if failed {
                AgentEventKind::ToolFailed
            } else {
                AgentEventKind::ToolCompleted
            };
            mapped.push(self.event(
                kind,
                json!({
                    "tool_use_id": tool_use_id,
                    "is_error": failed,
                    "authoritative": false,
                }),
                &format!("{uuid}:tool_result:{index}"),
            ));
        }
        Ok(mapped)
    }
}
