//! Strict ingestion for the pinned Claude bidirectional stream transcript.

mod tools;

use crate::protocol::{
    basic_event_subject, empty_array, empty_optional_array, event_subject, exact_fields, protocol,
    unique_string_array, valid_native_id, valid_result_common, valid_uuid, ClaudeStreamOutcome,
    ClaudeStreamTranscript, Phase, TranscriptProfile, MAX_ASSISTANT_CONTENT_ITEMS,
    MAX_STREAM_JSON_FRAME_BYTES, READ_ONLY_TOOL_ALLOWLIST,
};
use bullet_harness_core::{
    decode_strict_json, AgentEvent, AgentEventKind, HarnessError, PatchProposal,
};
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
            Err(error) => return self.fail(format!("malformed stream-JSON: {error}")),
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
            Some("system") => self.system_init(object),
            Some("assistant") => self.assistant(object),
            Some("result") => self.result(object),
            Some("user") if self.profile.admits_tool_use() => self.tool_result(object),
            Some(other) => self.fail(format!("unadmitted stream-JSON type {other:?}")),
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
        if !exact_fields(object, &required, &optional)
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
            || object.get("analytics_disabled").and_then(Value::as_bool) != Some(true)
            || object
                .get("product_feedback_disabled")
                .and_then(Value::as_bool)
                != Some(true)
            || !empty_array(object, "mcp_servers")
            || !empty_array(object, "slash_commands")
            || !empty_array(object, "agents")
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
                        .all(|tool| READ_ONLY_TOOL_ALLOWLIST.contains(tool))
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
        if !exact_fields(
            object,
            &[
                "type",
                "uuid",
                "session_id",
                "message",
                "parent_tool_use_id",
            ],
            &["error"],
        ) || !object.get("parent_tool_use_id").is_some_and(Value::is_null)
            || !object.get("error").is_none_or(Value::is_null)
        {
            return self.fail("assistant envelope is not an exact main-session message");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("assistant has invalid event subject");
        };
        self.require_native_session(session_id)?;
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
        if !exact_fields(message, &required, &["container", "context_management"])
            || message.get("type").and_then(Value::as_str) != Some("message")
            || message.get("role").and_then(Value::as_str) != Some("assistant")
            || message.get("model").and_then(Value::as_str) != self.model.as_deref()
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
        if !valid_native_id(message_id) || !self.seen_message_ids.insert(message_id.to_string()) {
            return self.fail("assistant message id is invalid or duplicate");
        }
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
        self.assistant_messages += 1;
        Ok(mapped)
    }

    fn result(&mut self, object: &Map<String, Value>) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::Active {
            return self.fail("result is out of phase");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("result has invalid event subject");
        };
        self.require_native_session(session_id)?;
        self.record_event(uuid)?;
        if !valid_result_common(object) {
            return self.fail("result common subject is malformed");
        }
        let Some(subtype) = object.get("subtype").and_then(Value::as_str) else {
            return self.fail("result lacks subtype");
        };
        if subtype == "success" {
            self.success_result(object, uuid)
        } else {
            self.failure_result(object, uuid, subtype)
        }
    }

    fn success_result(
        &mut self,
        object: &Map<String, Value>,
        uuid: &str,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        // A conformance turn is one model, one turn. A real read-only turn may
        // bill a helper model and may count turns differently once tools are
        // involved, so the dogfood profile requires the bound model to be
        // present and the count to be positive and within what was observed,
        // rather than an exact single-model equality it cannot satisfy.
        let model_usage_matches = self.model.as_deref().is_some_and(|model| {
            object
                .get("modelUsage")
                .and_then(Value::as_object)
                .is_some_and(|usage| {
                    usage.contains_key(model)
                        && match self.profile {
                            TranscriptProfile::ConformanceV1 => usage.len() == 1,
                            TranscriptProfile::DogfoodReadOnlyV0 => !usage.is_empty(),
                        }
                })
        });
        let num_turns_matches =
            object
                .get("num_turns")
                .and_then(Value::as_u64)
                .is_some_and(|turns| match self.profile {
                    TranscriptProfile::ConformanceV1 => turns == self.assistant_messages,
                    TranscriptProfile::DogfoodReadOnlyV0 => {
                        turns > 0 && turns <= self.assistant_messages
                    }
                });
        if self.phase != Phase::Active
            || self.assistant_messages == 0
            || !self.outstanding_tool_use_ids.is_empty()
            || !num_turns_matches
            || !model_usage_matches
            || object.get("is_error").and_then(Value::as_bool) != Some(false)
            || object.get("stop_reason").and_then(Value::as_str) != Some("end_turn")
            || !object.get("result").is_some_and(Value::is_string)
            || object.get("errors").is_some()
        {
            return self.fail("success result disagrees with the active terminal subject");
        }
        let Some(structured) = object.get("structured_output") else {
            return self.fail("success result lacks structured_output");
        };
        let proposal = match PatchProposal::from_value(structured) {
            Ok(proposal) => proposal,
            Err(error) => return self.fail(format!("terminal PatchProposal invalid: {error}")),
        };
        if proposal.gate_ids != self.admitted_gate_ids {
            return self.fail("terminal PatchProposal gate_ids differ from admission");
        }
        let events = vec![
            self.event(
                AgentEventKind::UsageReported,
                json!({"usage": object.get("usage"), "total_cost_usd": object.get("total_cost_usd")}),
                &format!("{uuid}:usage"),
            ),
            self.event(
                AgentEventKind::TurnCompleted,
                json!({"proposal": proposal, "terminal_event_id": uuid}),
                uuid,
            ),
        ];
        self.outcome = Some(ClaudeStreamOutcome::Proposal(proposal));
        self.phase = Phase::Terminal;
        Ok(events)
    }

    fn failure_result(
        &mut self,
        object: &Map<String, Value>,
        uuid: &str,
        subtype: &str,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        let allowed = matches!(
            subtype,
            "error_max_turns"
                | "error_during_execution"
                | "error_max_budget_usd"
                | "error_max_structured_output_retries"
        );
        let errors = object.get("errors").and_then(Value::as_array);
        if !allowed
            || object.get("is_error").and_then(Value::as_bool) != Some(true)
            || errors.is_none_or(|errors| {
                errors.is_empty() || errors.iter().any(|error| !error.is_string())
            })
            || object.get("structured_output").is_some()
            || object.get("result").is_some()
        {
            return self.fail("failure result has invalid terminal shape");
        }
        let event = self.event(
            AgentEventKind::TurnFailed,
            json!({"subtype": subtype, "terminal_event_id": uuid}),
            uuid,
        );
        self.outcome = Some(ClaudeStreamOutcome::Failed(subtype.to_string()));
        self.phase = Phase::Terminal;
        Ok(vec![event])
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
