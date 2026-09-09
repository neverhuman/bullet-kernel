//! Validated terminal results; ConformanceV1 retains its original event sequence.

use crate::protocol::{
    basic_event_subject, valid_result_common, ClaudeStreamOutcome, ClaudeStreamTranscript, Phase,
    TranscriptProfile,
};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError, PatchProposal};
use serde_json::{json, Map, Value};

impl ClaudeStreamTranscript {
    pub(super) fn result(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::Active {
            return self.fail("result is out of phase");
        }
        let Some((uuid, session_id)) = basic_event_subject(object) else {
            return self.fail("result has invalid event subject");
        };
        self.require_native_session(session_id)?;
        self.record_event(uuid)?;
        if !valid_result_common(object, self.profile.admits_vendor_fields()) {
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
                    // `num_turns` is the CLI's own accounting of its internal
                    // conversation, not a count of anything this transcript
                    // names. A real turn streams one assistant message across
                    // several frames and interleaves tool-result turns, so it
                    // reported 5 turns for 3 assistant messages: the old bound
                    // refused a clean turn after it had been billed. What the
                    // bound is actually for is catching work we did not see,
                    // so it is stated against frames we did see, and the
                    // stronger hidden-work signals are checked outright below.
                    TranscriptProfile::DogfoodReadOnlyV0 => {
                        turns > 0 && turns <= self.inbound_frames
                    }
                });
        if self.phase != Phase::Active
            || self.assistant_messages == 0
            || !self.outstanding_tool_use_ids.is_empty()
            || !num_turns_matches
            || !model_usage_matches
            || object.get("is_error").and_then(Value::as_bool) != Some(false)
            // A schema-bearing turn ends by calling StructuredOutput, so the
            // terminal stop_reason is `tool_use`, not `end_turn`. The frozen
            // conformance subject has no tools and keeps `end_turn` only.
            || !object
                .get("stop_reason")
                .and_then(Value::as_str)
                .is_some_and(|reason| {
                    reason == "end_turn"
                        || (self.profile.admits_tool_use() && reason == "tool_use")
                })
            || !object.get("result").is_some_and(Value::is_string)
            || object.get("errors").is_some()
        {
            return self.fail("success result disagrees with the active terminal subject");
        }
        // Hidden work is the thing the turn count was reaching for and could
        // not see. A sub-agent runs its own conversation that never appears in
        // this transcript, so a read-only dogfood turn admits none: zero
        // spawned, zero depth, and nothing left queued behind the result.
        if self.profile == TranscriptProfile::DogfoodReadOnlyV0 {
            let subagents_quiet = object
                .get("subagent_stats")
                .and_then(Value::as_object)
                .is_some_and(|stats| {
                    stats.get("spawned").and_then(Value::as_u64) == Some(0)
                        && stats.get("max_depth").and_then(Value::as_u64) == Some(0)
                });
            if !subagents_quiet {
                return self.fail("the turn ran sub-agent work this transcript never showed");
            }
            if object.get("queued_turn_count").and_then(Value::as_u64) != Some(0) {
                return self.fail("the turn ended with work still queued behind the result");
            }
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
        let mut events = Vec::new();
        if self.profile == TranscriptProfile::DogfoodReadOnlyV0 {
            events.push(self.event(
                AgentEventKind::UsageReported,
                json!({"usage": object.get("usage"), "total_cost_usd": object.get("total_cost_usd")}),
                &format!("{uuid}:usage"),
            ));
        }
        events.push(self.event(
            AgentEventKind::TurnFailed,
            json!({"subtype": subtype, "terminal_event_id": uuid}),
            uuid,
        ));
        self.outcome = Some(ClaudeStreamOutcome::Failed(subtype.to_string()));
        self.phase = Phase::Terminal;
        Ok(events)
    }
}
