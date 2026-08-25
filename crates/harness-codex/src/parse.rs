use crate::protocol::{
    nested_str, nonempty_string, parse_frame, protocol, turn_subject, valid_initialize_response,
    valid_native_id, valid_thread, AppServerOutcome, CodexAppServerTranscript, Frame, Pending,
    Phase,
};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError};
use serde_json::{json, Map, Value};

impl CodexAppServerTranscript {
    /// Consume exactly one stable App Server JSONL frame.
    pub fn ingest_line(&mut self, line: &str) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase == Phase::Poisoned {
            return Err(protocol("transcript is poisoned"));
        }
        if self.phase == Phase::Terminal {
            return self.fail("late frame after terminal outcome");
        }
        if self.inbound_frames >= Self::MAX_TRANSCRIPT_FRAMES {
            return self.fail("transcript frame limit exceeded");
        }
        self.inbound_frames += 1;
        let frame = match parse_frame(line) {
            Ok(frame) => frame,
            Err(reason) => return self.fail(reason),
        };
        match frame {
            Frame::Response { id, result } => self.response(id, result),
            Frame::Notification {
                method,
                params,
                canonical,
            } => {
                if !self.seen_notifications.insert(canonical) {
                    return self.fail("duplicate notification frame");
                }
                self.notification(&method, &params)
            }
        }
    }

    fn response(&mut self, id: u64, result: Value) -> Result<Vec<AgentEvent>, HarnessError> {
        if !self.seen_responses.insert(id) {
            return self.fail(format!("duplicate response id {id}"));
        }
        let Some((expected_id, pending)) = self.pending.take() else {
            return self.fail(format!("unexpected response id {id}"));
        };
        if id != expected_id {
            return self.fail(format!("response id {id} does not match {expected_id}"));
        }
        match pending {
            Pending::Initialize => {
                if self.phase != Phase::Initializing || !valid_initialize_response(&result) {
                    return self.fail("invalid initialize response");
                }
                self.phase = Phase::AwaitInitialized;
                Ok(vec![self.event(
                    AgentEventKind::SessionStarted,
                    json!({"protocol": "codex_app_server_jsonl"}),
                    format!("response:{id}"),
                )])
            }
            Pending::ThreadStart => self.thread_response(result, id),
            Pending::TurnStart => self.turn_response(result, id),
            Pending::TurnInterrupt => self.interrupt_response(result, id),
        }
    }

    fn notification(
        &mut self,
        method: &str,
        params: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        match method {
            "thread/started" => self.thread_started(params),
            "turn/started" => self.turn_started(params),
            "item/started" => self.item_event(params, false),
            "item/completed" => self.item_event(params, true),
            "item/agentMessage/delta" => {
                self.delta(params, AgentEventKind::TurnDelta, "agentMessage")
            }
            "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
                self.delta(params, AgentEventKind::ThinkingDelta, "reasoning")
            }
            "turn/completed" => self.turn_completed(params),
            _ => self.fail(format!("unadmitted notification method {method:?}")),
        }
    }

    fn thread_response(
        &mut self,
        result: Value,
        request_id: u64,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::ThreadStarting || self.thread_response.is_some() {
            return self.fail("unexpected thread/start response");
        }
        let Some(result_object) = result.as_object() else {
            return self.fail("thread/start result is not an object");
        };
        let Some(id) = nested_str(Some(result_object), "thread", "id") else {
            return self.fail("thread/start response lacks thread.id");
        };
        if !valid_native_id(id) {
            return self.fail("thread/start response has invalid thread.id");
        }
        let Some(thread) = result_object.get("thread").and_then(Value::as_object) else {
            return self.fail("thread/start response lacks thread object");
        };
        if result_object.get("approvalPolicy").and_then(Value::as_str) != Some("never")
            || result_object.get("sandbox").and_then(Value::as_str) != Some("read-only")
            || result_object.get("cwd").and_then(Value::as_str) != self.thread_cwd.as_deref()
            || !nonempty_string(result_object, "model")
            || !nonempty_string(result_object, "modelProvider")
            || !result_object
                .get("approvalsReviewer")
                .is_some_and(Value::is_string)
            || !valid_thread(
                thread,
                id,
                &self.expected_runtime_version,
                self.thread_cwd.as_deref(),
            )
        {
            return self.fail("thread/start response does not preserve read-only subject");
        }
        self.thread_response = Some(id.to_string());
        self.normalizer.set_native_session(id);
        let ready = self.finish_thread_start()?;
        let mut events = vec![self.event(
            AgentEventKind::SessionIdentity,
            json!({"request_id": request_id}),
            format!("response:{request_id}"),
        )];
        if ready {
            events.push(self.event(
                AgentEventKind::SessionReady,
                json!({"thread_id": id}),
                "thread:ready",
            ));
        }
        Ok(events)
    }

    fn thread_started(
        &mut self,
        params: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::ThreadStarting || self.thread_notification.is_some() {
            return self.fail("duplicate or out-of-phase thread/started");
        }
        let Some(thread) = params.get("thread").and_then(Value::as_object) else {
            return self.fail("thread/started lacks thread.id");
        };
        let Some(id) = thread.get("id").and_then(Value::as_str) else {
            return self.fail("thread/started lacks thread.id");
        };
        if !valid_native_id(id) {
            return self.fail("thread/started has invalid thread.id");
        }
        if !valid_thread(
            thread,
            id,
            &self.expected_runtime_version,
            self.thread_cwd.as_deref(),
        ) {
            return self.fail("thread/started has invalid thread subject");
        }
        self.thread_notification = Some(id.to_string());
        let ready = self.finish_thread_start()?;
        Ok(if ready {
            vec![self.event(
                AgentEventKind::SessionReady,
                json!({"thread_id": id}),
                "thread:ready",
            )]
        } else {
            Vec::new()
        })
    }

    fn finish_thread_start(&mut self) -> Result<bool, HarnessError> {
        let (Some(response), Some(notification)) =
            (&self.thread_response, &self.thread_notification)
        else {
            return Ok(false);
        };
        if response != notification {
            return self.fail("thread/start subjects disagree");
        }
        self.phase = Phase::ThreadReady;
        Ok(true)
    }

    fn turn_response(
        &mut self,
        result: Value,
        request_id: u64,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::TurnStarting || self.turn_response.is_some() {
            return self.fail("unexpected turn/start response");
        }
        let Some((id, status)) = turn_subject(result.as_object()) else {
            return self.fail("turn/start response lacks turn subject");
        };
        if !valid_native_id(id) || status != "inProgress" {
            return self.fail("turn/start response is not valid inProgress");
        }
        self.turn_response = Some(id.to_string());
        let ready = self.finish_turn_start()?;
        Ok(if ready {
            vec![self.event(
                AgentEventKind::TurnStarted,
                json!({"request_id": request_id}),
                "turn:started",
            )]
        } else {
            Vec::new()
        })
    }

    fn turn_started(
        &mut self,
        params: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_exact_thread(params)?;
        if self.phase != Phase::TurnStarting || self.turn_notification.is_some() {
            return self.fail("duplicate or out-of-phase turn/started");
        }
        let Some((id, status)) = turn_subject(Some(params)) else {
            return self.fail("turn/started lacks turn subject");
        };
        if !valid_native_id(id) || status != "inProgress" {
            return self.fail("turn/started is not valid inProgress");
        }
        self.turn_notification = Some(id.to_string());
        let ready = self.finish_turn_start()?;
        Ok(if ready {
            vec![self.event(
                AgentEventKind::TurnStarted,
                json!({"turn_id": id}),
                "turn:started",
            )]
        } else {
            Vec::new()
        })
    }

    fn finish_turn_start(&mut self) -> Result<bool, HarnessError> {
        let (Some(response), Some(notification)) = (&self.turn_response, &self.turn_notification)
        else {
            return Ok(false);
        };
        if response != notification {
            return self.fail("turn/start subjects disagree");
        }
        self.phase = Phase::Active;
        Ok(true)
    }

    fn item_event(
        &mut self,
        params: &Map<String, Value>,
        completed: bool,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_active_subject(params)?;
        let Some(item) = params.get("item").and_then(Value::as_object) else {
            return self.fail("item event lacks item object");
        };
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            return self.fail("item event lacks item.id");
        };
        if !valid_native_id(id) {
            return self.fail("item event has invalid item.id");
        }
        let kind = match item.get("type").and_then(Value::as_str) {
            Some("agentMessage") => "agentMessage",
            Some("reasoning") => "reasoning",
            Some("commandExecution") => "commandExecution",
            Some("fileChange") => return self.fail("provider file changes are never admitted"),
            Some(other) => return self.fail(format!("unadmitted item type {other:?}")),
            None => return self.fail("item event lacks item.type"),
        };
        let timestamp_field = if completed {
            "completedAtMs"
        } else {
            "startedAtMs"
        };
        let Some(timestamp) = params.get(timestamp_field).and_then(Value::as_i64) else {
            return self.fail(format!("item event lacks {timestamp_field}"));
        };
        if timestamp < 0 {
            return self.fail("item event timestamp is negative");
        }
        match (self.item_states.get(id), completed) {
            (None, false) => {
                if self.item_states.len() >= Self::MAX_ITEMS {
                    return self.fail("item limit exceeded");
                }
                self.item_states
                    .insert(id.to_string(), (kind.to_string(), timestamp, false));
                Ok(if kind == "commandExecution" {
                    vec![self.event(
                        AgentEventKind::ToolStarted,
                        json!({"item_id": id}),
                        format!("item:{id}:started"),
                    )]
                } else {
                    Vec::new()
                })
            }
            (Some((started_kind, started_at, false)), true)
                if started_kind == kind && timestamp >= *started_at =>
            {
                self.item_states
                    .insert(id.to_string(), (kind.to_string(), *started_at, true));
                self.completed_item(item, id, kind)
            }
            _ => self.fail("duplicate, missing-start, or reordered item event"),
        }
    }

    fn completed_item(
        &mut self,
        item: &Map<String, Value>,
        id: &str,
        kind: &str,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        match kind {
            "agentMessage" => {
                if self.final_message.is_some() {
                    return self.fail("multiple completed agent messages are not admitted");
                }
                let Some(text) = item.get("text").and_then(Value::as_str) else {
                    return self.fail("completed agentMessage lacks text");
                };
                self.final_message = Some((id.to_string(), text.to_string()));
                Ok(vec![self.event(
                    AgentEventKind::TurnDelta,
                    json!({"text": text, "final": true}),
                    format!("item:{id}:completed"),
                )])
            }
            "commandExecution" => Ok(vec![self.event(
                AgentEventKind::ToolCompleted,
                json!({"item": item}),
                format!("item:{id}:completed"),
            )]),
            "reasoning" => Ok(Vec::new()),
            _ => self.fail("unreachable item type"),
        }
    }

    fn delta(
        &mut self,
        params: &Map<String, Value>,
        event_kind: AgentEventKind,
        item_kind: &str,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_active_subject(params)?;
        let Some(item_id) = params.get("itemId").and_then(Value::as_str) else {
            return self.fail("delta lacks itemId");
        };
        if !self
            .item_states
            .get(item_id)
            .is_some_and(|(kind, _, completed)| kind == item_kind && !completed)
        {
            return self.fail("delta does not name a matching active item");
        }
        let Some(text) = params.get("delta").and_then(Value::as_str) else {
            return self.fail("delta payload is not text");
        };
        Ok(vec![self.event(
            event_kind,
            json!({"text": text}),
            format!("delta:{item_id}"),
        )])
    }

    fn turn_completed(
        &mut self,
        params: &Map<String, Value>,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_exact_thread(params)?;
        if !matches!(self.phase, Phase::Active | Phase::Interrupting) || self.terminal_seen {
            return self.fail("duplicate or out-of-phase turn/completed");
        }
        let Some((id, status)) = turn_subject(Some(params)) else {
            return self.fail("turn/completed lacks turn subject");
        };
        if id != self.turn_id()? {
            return self.fail("turn/completed names a different turn");
        }
        self.terminal_seen = true;
        let event = match status {
            "completed" if !self.cancel_requested => self.completed_turn(params, id)?,
            "interrupted" if self.cancel_requested => self.interrupted_turn(id),
            "failed" if !self.cancel_requested => self.failed_turn(params, id),
            _ => return self.fail("terminal status disagrees with cancellation state"),
        };
        Ok(vec![event])
    }

    fn interrupted_turn(&mut self, id: &str) -> AgentEvent {
        self.outcome = Some(if self.timed_out {
            AppServerOutcome::TimedOut
        } else {
            AppServerOutcome::Interrupted
        });
        if self.cancel_acknowledged {
            self.phase = Phase::Terminal;
        }
        let reason = if self.timed_out {
            "timeout"
        } else {
            "interrupted"
        };
        self.event(
            AgentEventKind::TurnFailed,
            json!({"reason": reason}),
            format!("turn:{id}:interrupted"),
        )
    }

    fn failed_turn(&mut self, params: &Map<String, Value>, id: &str) -> AgentEvent {
        let reason = params
            .get("turn")
            .and_then(Value::as_object)
            .and_then(|turn| turn.get("error"))
            .and_then(Value::as_object)
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("App Server reported failure")
            .to_string();
        self.outcome = Some(AppServerOutcome::Failed(reason.clone()));
        self.phase = Phase::Terminal;
        self.event(
            AgentEventKind::TurnFailed,
            json!({"reason": reason}),
            format!("turn:{id}:failed"),
        )
    }

    fn interrupt_response(
        &mut self,
        result: Value,
        request_id: u64,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase != Phase::Interrupting
            || !self.cancel_requested
            || self.cancel_acknowledged
            || !result.as_object().is_some_and(Map::is_empty)
        {
            return self.fail("invalid turn/interrupt acknowledgement");
        }
        self.cancel_acknowledged = true;
        if self.terminal_seen {
            self.phase = Phase::Terminal;
        }
        Ok(vec![self.event(
            AgentEventKind::InterruptAcknowledged,
            json!({"timed_out": self.timed_out}),
            format!("response:{request_id}"),
        )])
    }

    fn require_active_subject(&mut self, params: &Map<String, Value>) -> Result<(), HarnessError> {
        if self.phase != Phase::Active {
            return self.fail("event arrived outside active turn");
        }
        self.require_exact_thread(params)?;
        match params.get("turnId").and_then(Value::as_str) {
            Some(id) if id == self.turn_id()? => Ok(()),
            _ => self.fail("event names a different turn"),
        }
    }

    fn require_exact_thread(&mut self, params: &Map<String, Value>) -> Result<(), HarnessError> {
        match params.get("threadId").and_then(Value::as_str) {
            Some(id) if id == self.thread_id()? => Ok(()),
            _ => self.fail("event names a different thread"),
        }
    }
}
