//! Exact read-only tool request/result lifecycle for dogfood transcripts.

use super::{basic_event_subject, exact_fields};
use crate::protocol::{
    valid_native_id, ClaudeStreamTranscript, Phase, MAX_ASSISTANT_CONTENT_ITEMS,
    READ_ONLY_TOOL_ALLOWLIST,
};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

impl ClaudeStreamTranscript {
    pub(super) fn admit_tool_request(
        &mut self,
        item: &Map<String, Value>,
    ) -> Result<Value, HarnessError> {
        if !exact_fields(item, &["type", "id", "name", "input"], &[])
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
        if !valid_native_id(tool_use_id) || !READ_ONLY_TOOL_ALLOWLIST.contains(&name) {
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
        Ok(json!({
            "tool_use_id": tool_use_id,
            "name": name,
            "authoritative": false,
        }))
    }

    /// Consume one `user` frame carrying results for exact outstanding tools.
    pub(super) fn tool_result(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Active, "tool result")?;
        if !exact_fields(
            object,
            &[
                "type",
                "uuid",
                "session_id",
                "message",
                "parent_tool_use_id",
            ],
            &[],
        ) || !object.get("parent_tool_use_id").is_some_and(Value::is_null)
        {
            return self.fail("tool result envelope is not an exact main-session frame");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("tool result has invalid event subject");
        };
        self.require_native_session(session_id)?;
        let Some(message) = object.get("message").and_then(Value::as_object) else {
            return self.fail("tool result message is not an object");
        };
        if !exact_fields(message, &["role", "content"], &[])
            || message.get("role").and_then(Value::as_str) != Some("user")
        {
            return self.fail("tool result message subject is malformed");
        }
        let Some(content) = message.get("content").and_then(Value::as_array) else {
            return self.fail("tool result content is not an array");
        };
        if content.is_empty() || content.len() > MAX_ASSISTANT_CONTENT_ITEMS {
            return self.fail("tool result content item count is outside admission");
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
