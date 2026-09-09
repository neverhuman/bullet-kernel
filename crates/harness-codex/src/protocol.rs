//! Pure stable Codex App Server JSONL request/state boundary.
use bullet_harness_core::{
    decode_strict_json, proposal::validate_gate_ids, AgentEvent, AgentEventKind, AgentSessionId,
    EventNormalizer, HarnessError, InvocationId, NativeMeta, PatchProposal,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
const MAX_CLIENT_VERSION_BYTES: usize = 128;
const FRAME_BYTES_LIMIT: usize = 1024 * 1024;
const TRANSCRIPT_FRAME_LIMIT: usize = 128;
const ITEM_LIMIT: usize = 32;
pub(super) enum Frame {
    Response {
        id: u64,
        result: Value,
    },
    Notification {
        method: String,
        params: Map<String, Value>,
        canonical: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    Initializing,
    AwaitInitialized,
    Initialized,
    ThreadStarting,
    ThreadReady,
    TurnStarting,
    Active,
    Interrupting,
    Terminal,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Pending {
    Initialize,
    ThreadStart,
    TurnStart,
    TurnInterrupt,
}
/// Terminal result of one offline transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppServerOutcome {
    /// A schema-valid proposal with the exact admitted gate list.
    Proposal(PatchProposal),
    /// Explicit operator cancellation completed and was acknowledged.
    Interrupted,
    /// Deadline cancellation completed and was acknowledged.
    TimedOut,
    /// App Server reported a failed turn.
    Failed(String),
}
/// Pure protocol machine; transport requires separate signed admission.
pub struct CodexAppServerTranscript {
    pub(super) phase: Phase,
    client_version: String,
    pub(super) expected_runtime_version: String,
    next_id: u64,
    pub(super) pending: Option<(u64, Pending)>,
    pub(super) seen_responses: BTreeSet<u64>,
    pub(super) seen_notifications: BTreeSet<String>,
    pub(super) inbound_frames: usize,
    pub(super) normalizer: EventNormalizer,
    pub(super) admitted_gate_ids: Vec<String>,
    pub(super) thread_response: Option<String>,
    pub(super) thread_notification: Option<String>,
    pub(super) thread_cwd: Option<String>,
    pub(super) turn_response: Option<String>,
    pub(super) turn_notification: Option<String>,
    pub(super) item_states: BTreeMap<String, (String, i64, bool)>,
    pub(super) final_message: Option<(String, String)>,
    pub(super) cancel_requested: bool,
    pub(super) cancel_acknowledged: bool,
    pub(super) timed_out: bool,
    pub(super) terminal_seen: bool,
    pub(super) outcome: Option<AppServerOutcome>,
    event_serial: u64,
}
impl CodexAppServerTranscript {
    /// Maximum encoded size of any inbound or outbound App Server frame.
    pub const MAX_FRAME_BYTES: usize = FRAME_BYTES_LIMIT;
    /// Maximum inbound frames accepted by one transcript.
    pub const MAX_TRANSCRIPT_FRAMES: usize = TRANSCRIPT_FRAME_LIMIT;
    /// Maximum distinct provider items accepted by one turn.
    pub const MAX_ITEMS: usize = ITEM_LIMIT;
    /// Create a machine bound to a session, invocation, versions, and gates.
    ///
    /// # Errors
    /// Refuses invalid client versions and invalid/duplicate gate identifiers.
    pub fn new(
        session_id: AgentSessionId,
        invocation_id: InvocationId,
        client_version: impl Into<String>,
        expected_runtime_version: impl Into<String>,
        admitted_gate_ids: Vec<String>,
    ) -> Result<Self, HarnessError> {
        let client_version = client_version.into();
        let expected_runtime_version = expected_runtime_version.into();
        if !valid_version(&client_version) || !valid_version(&expected_runtime_version) {
            return Err(protocol("invalid client version binding"));
        }
        validate_gate_ids(&admitted_gate_ids)?;
        let mut normalizer = EventNormalizer::new(session_id, "codex");
        normalizer.set_invocation(invocation_id);
        Ok(Self {
            phase: Phase::New,
            client_version,
            expected_runtime_version,
            next_id: 1,
            pending: None,
            seen_responses: BTreeSet::new(),
            seen_notifications: BTreeSet::new(),
            inbound_frames: 0,
            normalizer,
            admitted_gate_ids,
            thread_response: None,
            thread_notification: None,
            thread_cwd: None,
            turn_response: None,
            turn_notification: None,
            item_states: BTreeMap::new(),
            final_message: None,
            cancel_requested: false,
            cancel_acknowledged: false,
            timed_out: false,
            terminal_seen: false,
            outcome: None,
            event_serial: 0,
        })
    }
    /// Build the one required stable initialization request.
    pub fn initialize_request(&mut self) -> Result<Value, HarnessError> {
        self.require_phase(Phase::New, "initialize")?;
        self.phase = Phase::Initializing;
        let version = self.client_version.clone();
        self.request(
            Pending::Initialize,
            "initialize",
            json!({
                "clientInfo": {
                    "name": "bullet-farm",
                    "title": "Bullet Farm",
                    "version": version,
                }
            }),
        )
    }
    /// Build stable `initialized`; no separate `hello` method exists.
    pub fn initialized_notification(&mut self) -> Result<Value, HarnessError> {
        self.require_phase(Phase::AwaitInitialized, "initialized")?;
        self.phase = Phase::Initialized;
        Ok(json!({"method": "initialized", "params": {}}))
    }
    /// Start a new App Server thread. No resume/fork authority is exposed.
    pub fn thread_start_request(&mut self, cwd: &str) -> Result<Value, HarnessError> {
        self.require_phase(Phase::Initialized, "thread/start")?;
        if cwd.is_empty() {
            return self.fail("thread/start requires nonempty cwd");
        }
        self.thread_cwd = Some(cwd.to_string());
        self.phase = Phase::ThreadStarting;
        self.request(
            Pending::ThreadStart,
            "thread/start",
            json!({
                "cwd": cwd,
                "approvalPolicy": "never",
                "sandbox": "read-only",
                "ephemeral": true,
            }),
        )
    }
    /// Start one read-only turn with the exact `PatchProposal` schema.
    pub fn turn_start_request(&mut self, prompt: &str, cwd: &str) -> Result<Value, HarnessError> {
        self.require_phase(Phase::ThreadReady, "turn/start")?;
        if prompt.is_empty() || cwd.is_empty() {
            return self.fail("turn/start requires nonempty prompt and cwd");
        }
        if self.thread_cwd.as_deref() != Some(cwd) {
            return self.fail("turn/start cwd differs from established thread cwd");
        }
        let thread_id = self.thread_id()?.to_string();
        let output_schema: Value = serde_json::from_str(
            bullet_harness_core::proposal::schema_source(),
        )
        .map_err(|error| protocol(format!("embedded PatchProposal schema invalid: {error}")))?;
        self.phase = Phase::TurnStarting;
        self.request(
            Pending::TurnStart,
            "turn/start",
            json!({
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "cwd": cwd,
                "approvalPolicy": "never",
                "sandboxPolicy": {"type": "readOnly"},
                "outputSchema": output_schema,
            }),
        )
    }
    /// Request cancellation for the active exact turn.
    pub fn interrupt_request(&mut self) -> Result<Value, HarnessError> {
        self.cancel(false)
    }
    /// Expire the deadline; an acknowledged interruption can never be PASS.
    pub fn timeout_request(&mut self) -> Result<Value, HarnessError> {
        self.cancel(true)
    }
    /// Return the terminal outcome only after all required acknowledgements.
    pub fn outcome(&self) -> Result<&AppServerOutcome, HarnessError> {
        if self.phase != Phase::Terminal {
            return Err(protocol("turn has no complete terminal outcome"));
        }
        self.outcome
            .as_ref()
            .ok_or_else(|| protocol("terminal outcome missing"))
    }
    fn cancel(&mut self, timed_out: bool) -> Result<Value, HarnessError> {
        self.require_phase(Phase::Active, "turn/interrupt")?;
        let thread_id = self.thread_id()?.to_string();
        let turn_id = self.turn_id()?.to_string();
        self.cancel_requested = true;
        self.timed_out = timed_out;
        self.phase = Phase::Interrupting;
        self.request(
            Pending::TurnInterrupt,
            "turn/interrupt",
            json!({"threadId": thread_id, "turnId": turn_id}),
        )
    }
    fn request(
        &mut self,
        kind: Pending,
        method: &str,
        params: Value,
    ) -> Result<Value, HarnessError> {
        let id = self.next_id;
        let frame = json!({"method": method, "id": id, "params": params});
        let Ok(encoded) = serde_json::to_vec(&frame) else {
            return self.fail("outbound request serialization failed");
        };
        if encoded.len() > Self::MAX_FRAME_BYTES {
            return self.fail("outbound request exceeds frame limit");
        }
        self.next_id += 1;
        self.pending = Some((id, kind));
        Ok(frame)
    }
    pub(super) fn thread_id(&self) -> Result<&str, HarnessError> {
        self.thread_response
            .as_deref()
            .ok_or_else(|| protocol("thread id is not established"))
    }
    pub(super) fn turn_id(&self) -> Result<&str, HarnessError> {
        self.turn_response
            .as_deref()
            .ok_or_else(|| protocol("turn id is not established"))
    }
    fn require_phase(&self, expected: Phase, operation: &str) -> Result<(), HarnessError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(protocol(format!(
                "{operation} invalid in phase {:?}",
                self.phase
            )))
        }
    }
    pub(super) fn event(
        &mut self,
        kind: AgentEventKind,
        payload: Value,
        native_id: impl Into<String>,
    ) -> AgentEvent {
        self.event_serial += 1;
        self.normalizer.accept(
            kind,
            payload,
            &NativeMeta {
                event_id: Some(format!("{}:{}", native_id.into(), self.event_serial)),
                sequence: None,
            },
        )
    }
    pub(super) fn completed_turn(
        &mut self,
        params: &Map<String, Value>,
        id: &str,
    ) -> Result<AgentEvent, HarnessError> {
        let Some((item_id, text)) = self.final_message.clone() else {
            return self.fail("completed turn has no final agent message");
        };
        if !self.terminal_items_match(params, &item_id, &text) {
            return self.fail("terminal items differ from completed item set");
        }
        let proposal_value = match decode_strict_json(&text) {
            Ok(value) => value,
            Err(_) => return self.fail("proposal refused: malformed or duplicate-key JSON"),
        };
        let proposal = match PatchProposal::from_value(&proposal_value) {
            Ok(proposal) => proposal,
            Err(error) => return self.fail(format!("proposal refused: {}", error.reason_code())),
        };
        if proposal.gate_ids != self.admitted_gate_ids {
            return self.fail("proposal gate_ids differ from exact admitted order");
        }
        let payload = match serde_json::to_value(&proposal) {
            Ok(payload) => payload,
            Err(_) => return self.fail("proposal serialization failed"),
        };
        self.outcome = Some(AppServerOutcome::Proposal(proposal));
        self.phase = Phase::Terminal;
        Ok(self.event(
            AgentEventKind::TurnCompleted,
            json!({"proposal": payload}),
            format!("turn:{id}:completed"),
        ))
    }
    fn terminal_items_match(
        &self,
        params: &Map<String, Value>,
        expected: &str,
        text: &str,
    ) -> bool {
        let Some(items) = params
            .get("turn")
            .and_then(Value::as_object)
            .and_then(|turn| turn.get("items"))
            .and_then(Value::as_array)
        else {
            return false;
        };
        if items.len() != self.item_states.len() || items.len() > Self::MAX_ITEMS {
            return false;
        }
        let mut ids = BTreeSet::new();
        let mut agent_messages = 0;
        for item in items {
            let Some(item) = item.as_object() else {
                return false;
            };
            let (Some(id), Some(kind)) = (
                item.get("id").and_then(Value::as_str),
                item.get("type").and_then(Value::as_str),
            ) else {
                return false;
            };
            if !ids.insert(id)
                || !self
                    .item_states
                    .get(id)
                    .is_some_and(|(observed, _, completed)| observed == kind && *completed)
            {
                return false;
            }
            match kind {
                "agentMessage" => {
                    agent_messages += 1;
                    if id != expected || item.get("text").and_then(Value::as_str) != Some(text) {
                        return false;
                    }
                }
                "reasoning" | "commandExecution" => {}
                _ => return false,
            }
        }
        agent_messages == 1
    }
    pub(super) fn fail<T>(&mut self, reason: impl Into<String>) -> Result<T, HarnessError> {
        self.phase = Phase::Poisoned;
        Err(protocol(reason))
    }
}
pub(super) fn protocol(reason: impl Into<String>) -> HarnessError {
    HarnessError::Protocol {
        provider: "codex".to_string(),
        reason: reason.into(),
    }
}
pub(super) fn valid_native_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLIENT_VERSION_BYTES
        && !value.chars().any(char::is_control)
}
pub(super) fn parse_frame(line: &str) -> Result<Frame, String> {
    if line.is_empty()
        || line.len() > FRAME_BYTES_LIMIT
        || line.as_bytes().contains(&b'\0')
        || line.contains(['\n', '\r'])
    {
        return Err("malformed or oversized JSONL frame".into());
    }
    let value: Value = decode_strict_json(line).map_err(|_| "malformed or duplicate-key JSON")?;
    let object = value.as_object().ok_or("JSONL frame must be an object")?;
    if object.contains_key("jsonrpc") {
        return Err("stable App Server frames omit jsonrpc".into());
    }
    match (object.get("id"), object.get("method")) {
        (Some(id), None) => {
            let id = id
                .as_u64()
                .ok_or("response id must be an unsigned integer")?;
            match (object.get("result"), object.get("error")) {
                (Some(result), None) => Ok(Frame::Response {
                    id,
                    result: result.clone(),
                }),
                (None, Some(_)) => Err("App Server request returned an error".into()),
                _ => Err("response must contain exactly one of result or error".into()),
            }
        }
        (None, Some(method)) => {
            let method = method
                .as_str()
                .ok_or("notification method must be a string")?
                .to_string();
            let params = object
                .get("params")
                .and_then(Value::as_object)
                .ok_or("notification params must be an object")?
                .clone();
            let canonical =
                serde_json::to_string(&value).map_err(|_| "notification serialization failed")?;
            Ok(Frame::Notification {
                method,
                params,
                canonical,
            })
        }
        (Some(_), Some(_)) => Err("server requests are not admitted".into()),
        (None, None) => Err("frame is neither response nor notification".into()),
    }
}
pub(super) fn nested_str<'a>(
    object: Option<&'a Map<String, Value>>,
    parent: &str,
    field: &str,
) -> Option<&'a str> {
    object?.get(parent)?.as_object()?.get(field)?.as_str()
}
pub(super) fn turn_subject(object: Option<&Map<String, Value>>) -> Option<(&str, &str)> {
    let turn = object?.get("turn")?.as_object()?;
    turn.get("items")?.as_array()?;
    Some((turn.get("id")?.as_str()?, turn.get("status")?.as_str()?))
}
pub(super) fn valid_initialize_response(result: &Value) -> bool {
    let Some(object) = result.as_object() else {
        return false;
    };
    ["codexHome", "platformFamily", "platformOs", "userAgent"]
        .into_iter()
        .all(|field| nonempty_string(object, field))
}
pub(super) fn nonempty_string(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}
pub(super) fn valid_thread(
    thread: &Map<String, Value>,
    id: &str,
    runtime_version: &str,
    cwd: Option<&str>,
) -> bool {
    thread.get("id").and_then(Value::as_str) == Some(id)
        && thread.get("sessionId").and_then(Value::as_str) == Some(id)
        && thread.get("cliVersion").and_then(Value::as_str) == Some(runtime_version)
        && thread.get("cwd").and_then(Value::as_str) == cwd
        && thread.get("ephemeral").and_then(Value::as_bool) == Some(true)
        && nonempty_string(thread, "modelProvider")
        && thread.get("createdAt").is_some_and(Value::is_i64)
        && thread.get("updatedAt").is_some_and(Value::is_i64)
        && thread.get("preview").is_some_and(Value::is_string)
        && thread.get("source").is_some_and(Value::is_string)
        && thread.get("status").is_some_and(Value::is_object)
        && thread.get("turns").is_some_and(Value::is_array)
        && thread.contains_key("projectId")
}
