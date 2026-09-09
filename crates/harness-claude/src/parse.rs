//! Strict ingestion for the pinned Claude bidirectional stream transcript.

mod results;
mod tools;

use crate::protocol::{
    basic_event_subject, empty_array, empty_optional_array, event_subject, exact_fields,
    model_matches, protocol, unique_string_array, valid_native_id, valid_uuid,
    ClaudeStreamTranscript, Phase, TranscriptProfile, MAX_ASSISTANT_CONTENT_ITEMS,
    MAX_STREAM_JSON_FRAME_BYTES, READ_ONLY_TOOL_ALLOWLIST,
};
use bullet_harness_core::{decode_strict_json, AgentEvent, AgentEventKind, HarnessError};
use serde_json::{json, Map, Value};

impl ClaudeStreamTranscript {
    /// Consume one newline-delimited Claude stream-JSON frame.
    ///
    /// # Errors
    ///
    /// Any malformed, duplicate, out-of-phase, or wrong-subject frame poisons
    /// the transcript permanently.
    pub fn ingest_line(&mut self, line: &str) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase == Phase::Poisoned {
            return Err(protocol("transcript is poisoned"));
        }
        if self.phase == Phase::Terminal {
            return self.fail("late frame after terminal outcome");
        }
        if line.is_empty()
            || line.len() > MAX_STREAM_JSON_FRAME_BYTES
            || line.contains(['\n', '\r', '\0'])
        {
            return self.fail("invalid stream-JSON frame boundary");
        }
        self.inbound_frames = self
            .inbound_frames
            .checked_add(1)
            .ok_or_else(|| protocol("stream-JSON frame counter overflow"))?;
        if self.inbound_frames > self.profile.max_stream_json_frames() {
            return self.fail("stream-JSON transcript frame limit exceeded");
        }
        let value: Value = match decode_strict_json(line) {
            Ok(value) => value,
            Err(_) => return self.fail("malformed stream-JSON"),
        };
        let Some(object) = value.as_object() else {
            return self.fail("stream-JSON frame is not an object");
        };
        let canonical = serde_json::to_string(&value)
            .map_err(|error| protocol(format!("frame canonicalization failed: {error}")))?;
        if !self.seen_frames.insert(canonical) {
            return self.fail("duplicate stream-JSON frame");
        }
        match object.get("type").and_then(Value::as_str) {
            // Route on subtype, not just type: `system` is the CLI's status
            // channel. 2.1.266 emits `system/thinking_tokens` progress frames
            // mid-turn, and sending every `system` frame to the init handler
            // refused them as "system/init is invalid in phase Active" -- after
            // the turn had been billed. A non-init system frame carries no
            // authority: it cannot name a tool, a session, or a proposal, so it
            // yields no event and changes no state.
            Some("system")
                if self.profile.admits_vendor_fields()
                    && object.get("subtype").and_then(Value::as_str) != Some("init") =>
            {
                Ok(Vec::new())
            }
            Some("system") => self.system_init(object),
            Some("assistant") => self.assistant(object),
            Some("result") => self.result(object),
            Some("user") if self.profile.admits_tool_use() => self.tool_result(object),
            // Quota telemetry. It carries no admission meaning and the CLI
            // emits it unprompted on a subscription account; it still counts
            // against the frame budget above.
            Some("rate_limit_event") if self.profile.admits_vendor_fields() => Ok(Vec::new()),
            Some(_) => self.fail("unadmitted stream-JSON type"),
            None => self.fail("stream-JSON frame lacks string type"),
        }
    }

    fn system_init(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::AwaitSessionInit, "system/init")?;
        let required = [
            "type",
            "subtype",
            "uuid",
            "session_id",
            "apiKeySource",
            "claude_code_version",
            "cwd",
            "tools",
            "mcp_servers",
            "model",
            "permissionMode",
            "slash_commands",
            "output_style",
            "agents",
            "skills",
            "plugins",
            "analytics_disabled",
            "product_feedback_disabled",
        ];
        let optional = [
            "plugin_errors",
            "plugin_warnings",
            "mcp_server_errors",
            "capabilities",
        ];
        // ConformanceV1 keeps its closed field set. The dogfood profile admits
        // unknown non-authority keys: a real 2.1.266 init carries
        // fast_mode_state, memory_paths and messaging_socket_path, none of
        // which mean anything for admission, and refusing them refused the
        // whole turn AFTER it had been billed.
        let fields_ok = if self.profile.admits_vendor_fields() {
            required.iter().all(|key| object.contains_key(*key))
        } else {
            exact_fields(object, &required, &optional)
        };
        if !fields_ok
            || object.get("subtype").and_then(Value::as_str) != Some("init")
            || object.get("claude_code_version").and_then(Value::as_str)
                != Some(self.expected_runtime_version.as_str())
            || object.get("cwd").and_then(Value::as_str) != Some(self.expected_cwd.as_str())
            || object.get("permissionMode").and_then(Value::as_str) != Some("plan")
            || !object
                .get("apiKeySource")
                .and_then(Value::as_str)
                .is_some_and(valid_native_id)
            || object.get("output_style").and_then(Value::as_str) != Some("default")
            // These two are org-privacy telemetry hints, not authority. A
            // personal subscription reports false for both and cannot be made
            // to report true by any environment the containment can set
            // (product_feedback_disabled is driven by org ZDR policy), so
            // pinning them to true refused every real turn on a real account.
            // They stay pinned on the frozen conformance subject and are
            // observed, not gated, under dogfood.
            || (!self.profile.admits_vendor_fields()
                && (object.get("analytics_disabled").and_then(Value::as_bool) != Some(true)
                    || object
                        .get("product_feedback_disabled")
                        .and_then(Value::as_bool)
                        != Some(true)))
            || !object.get("analytics_disabled").is_some_and(Value::is_boolean)
            || !object
                .get("product_feedback_disabled")
                .is_some_and(Value::is_boolean)
            || !empty_array(object, "mcp_servers")
            || !empty_array(object, "slash_commands")
            // `agents` lists the agent TYPES the build knows, not authority the
            // turn holds: dispatching one needs the `Task` tool, which the
            // allowlist below excludes. A real 2.1.266 always reports several.
            || (!self.profile.admits_vendor_fields() && !empty_array(object, "agents"))
            || !empty_array(object, "skills")
            || !empty_array(object, "plugins")
            || !empty_optional_array(object, "plugin_errors")
            || !empty_optional_array(object, "plugin_warnings")
            || !empty_optional_array(object, "mcp_server_errors")
        {
            return self.fail("system/init does not preserve the pinned read-only subject");
        }
        let tools = match unique_string_array(object, "tools") {
            Some(tools) => tools,
            None => return self.fail("system/init tools are malformed"),
        };
        match self.profile {
            TranscriptProfile::ConformanceV1 => {
                if tools != READ_ONLY_TOOL_ALLOWLIST {
                    return self
                        .fail("system/init tools differ from the exact read-only admission");
                }
            }
            TranscriptProfile::DogfoodReadOnlyV0 => {
                // Set membership, not order: the real CLI may order or omit
                // tools. Anything outside the read-only allowlist (Bash, Write,
                // Edit, …) still poisons the transcript, so a provider that was
                // granted write authority can never be parsed as read-only.
                if tools.is_empty()
                    || !tools
                        .iter()
                        .all(|tool| self.profile.tool_allowlist().contains(tool))
                {
                    return self.fail("system/init tools exceed the read-only allowlist");
                }
            }
        }
        if object.contains_key("capabilities")
            && unique_string_array(object, "capabilities").is_none()
        {
            return self.fail("system/init capabilities are malformed or duplicate");
        }
        let (uuid, session_id, model) = match event_subject(object) {
            Some(subject) => subject,
            None => return self.fail("system/init has invalid event subject"),
        };
        self.record_event(uuid)?;
        self.native_session_id = Some(session_id.to_string());
        self.model = Some(model.to_string());
        self.normalizer.set_native_session(session_id);
        self.normalizer.set_model(model);
        self.phase = Phase::Active;
        Ok(vec![
            self.event(
                AgentEventKind::SessionIdentity,
                json!({"native_session_id": session_id, "model": model}),
                &format!("{uuid}:identity"),
            ),
            self.event(
                AgentEventKind::SessionReady,
                json!({"claude_code_version": self.expected_runtime_version}),
                &format!("{uuid}:ready"),
            ),
            self.event(
                AgentEventKind::TurnStarted,
                json!({"invocation_id": self.invocation_id}),
                &format!("{uuid}:turn"),
            ),
        ])
    }

    fn assistant(&mut self, object: &Map<String, Value>) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Active, "assistant")?;
        if self.assistant_messages >= self.profile.max_assistant_messages() {
            return self.fail("assistant message limit exceeded");
        }
        let envelope_required = [
            "type",
            "uuid",
            "session_id",
            "message",
            "parent_tool_use_id",
        ];
        // A real assistant frame also carries `timestamp` and `request_id`.
        let envelope_ok = if self.profile.admits_vendor_fields() {
            envelope_required
                .iter()
                .all(|key| object.contains_key(*key))
        } else {
            exact_fields(object, &envelope_required, &["error"])
        };
        if !envelope_ok || !object.get("parent_tool_use_id").is_some_and(Value::is_null) {
            return self.fail("assistant envelope is not an exact main-session message");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("assistant has invalid event subject");
        };
        if !valid_uuid(uuid) {
            return self.fail("assistant has invalid event subject");
        }
        self.require_native_session(session_id)?;
        // Provider text and tags are untrusted, including after JSON decoding.
        // Refuse errors without turning their detail into public diagnostics or
        // admitting synthetic message bodies, usage, or a terminal outcome.
        if !object.get("error").is_none_or(Value::is_null)
            || object.get("is_api_error_message").and_then(Value::as_bool) == Some(true)
        {
            return self.fail("provider reported an assistant error; detail withheld");
        }
        if !object
            .get("is_api_error_message")
            .is_none_or(|value| value.is_null() || value.as_bool() == Some(false))
        {
            return self.fail("assistant error marker is malformed");
        }
        let Some(message) = object.get("message").and_then(Value::as_object) else {
            return self.fail("assistant.message is not an object");
        };
        let required = [
            "id",
            "type",
            "role",
            "model",
            "content",
            "stop_reason",
            "stop_sequence",
            "usage",
        ];
        let message_ok = if self.profile.admits_vendor_fields() {
            required.iter().all(|key| message.contains_key(*key))
        } else {
            exact_fields(message, &required, &["container", "context_management"])
        };
        if !message_ok
            || message.get("type").and_then(Value::as_str) != Some("message")
            || message.get("role").and_then(Value::as_str) != Some("assistant")
            || !message
                .get("model")
                .and_then(Value::as_str)
                .is_some_and(|message_model| match self.profile {
                    TranscriptProfile::ConformanceV1 => {
                        Some(message_model) == self.model.as_deref()
                    }
                    TranscriptProfile::DogfoodReadOnlyV0 => self
                        .model
                        .as_deref()
                        .is_some_and(|session| model_matches(session, message_model)),
                })
            || !message.get("usage").is_some_and(Value::is_object)
            || !message.get("stop_sequence").is_some_and(Value::is_null)
            || !message.get("stop_reason").is_some_and(|value| {
                value.is_null()
                    || value.as_str() == Some("end_turn")
                    || (self.profile.admits_tool_use() && value.as_str() == Some("tool_use"))
            })
        {
            return self.fail("assistant message subject is malformed or mismatched");
        }
        let Some(message_id) = message.get("id").and_then(Value::as_str) else {
            return self.fail("assistant message lacks id");
        };
        if !valid_native_id(message_id) {
            return self.fail("assistant message id is invalid or duplicate");
        }
        // 2.1.266 streams one logical assistant message as several frames --
        // observed 24 frames carrying 8 distinct ids, split by content block
        // (thinking, text, tool_use). Treating every repeat as a replay refused
        // every real turn after it had been billed.
        let continuation = self.profile.admits_vendor_fields()
            && self.last_message_id.as_deref() == Some(message_id);
        if !continuation && !self.seen_message_ids.insert(message_id.to_string()) {
            return self.fail("assistant message id is invalid or duplicate");
        }
        self.last_message_id = Some(message_id.to_owned());
        let Some(content) = message.get("content").and_then(Value::as_array) else {
            return self.fail("assistant content is not an array");
        };
        if content.is_empty() || content.len() > MAX_ASSISTANT_CONTENT_ITEMS {
            return self.fail("assistant content item count is outside admission");
        }
        let mut mapped = Vec::new();
        for (index, item) in content.iter().enumerate() {
            let Some(item) = item.as_object() else {
                return self.fail("assistant content item is not an object");
            };
            let (kind, payload) = match item.get("type").and_then(Value::as_str) {
                Some("text")
                    if exact_fields(item, &["type", "text"], &[])
                        && item.get("text").is_some_and(Value::is_string) =>
                {
                    (
                        AgentEventKind::TurnDelta,
                        json!({"text": item.get("text"), "authoritative": false}),
                    )
                }
                Some("thinking")
                    if exact_fields(item, &["type", "thinking", "signature"], &[])
                        && item.get("thinking").is_some_and(Value::is_string)
                        && item.get("signature").is_some_and(Value::is_string) =>
                {
                    (
                        AgentEventKind::ThinkingDelta,
                        json!({"text": item.get("thinking")}),
                    )
                }
                Some("tool_use") if self.profile.admits_tool_use() => (
                    AgentEventKind::ToolRequested,
                    self.admit_tool_request(item)?,
                ),
                Some("tool_use") => {
                    return self.fail("tool use is outside the frozen V1 transcript");
                }
                _ => return self.fail("unadmitted assistant content item"),
            };
            mapped.push(self.event(kind, payload, &format!("{uuid}:content:{index}")));
        }
        self.record_event(uuid)?;
        if !continuation {
            self.assistant_messages += 1;
        }
        Ok(mapped)
    }

    fn record_event(&mut self, uuid: &str) -> Result<(), HarnessError> {
        if !valid_uuid(uuid) || !self.seen_event_ids.insert(uuid.to_string()) {
            return self.fail("provider event uuid is invalid or duplicate");
        }
        Ok(())
    }

    fn require_native_session(&mut self, session_id: &str) -> Result<(), HarnessError> {
        if self.native_session_id.as_deref() != Some(session_id) {
            return self.fail("provider event names the wrong native session");
        }
        Ok(())
    }
}
