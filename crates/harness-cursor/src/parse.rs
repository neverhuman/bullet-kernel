//! Pure, bounded Cursor ACP v1 JSONL transcript state machine.
//!
//! Raw frames use the shared recursive duplicate-key-rejecting decoder. This
//! is ordinary JSON validation, not RFC 8785 canonicalization or live admission.

use crate::protocol::{
    bounded_string, exact_fields, object, protocol, valid_cwd, valid_native_id,
    valid_subject_digest, valid_token, validate_agent_info, validate_auth_methods,
    validate_capabilities,
};
use bullet_harness_core::{
    decode_strict_json, proposal::validate_gate_ids, AgentEvent, AgentEventKind, AgentSessionId,
    EventNormalizer, HarnessError, InvocationId, PatchProposal,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
const FRAME_LIMIT: usize = 1024 * 1024;
const INBOUND_LIMIT: usize = 128;
const UPDATE_LIMIT: usize = 64;
const PROMPT_LIMIT: usize = 64 * 1024;
const CHUNK_LIMIT: usize = 16 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    Initializing,
    Initialized,
    Authenticating,
    Authenticated,
    SessionStarting,
    Ready,
    Prompting,
    Terminal,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Initialize,
    Authenticate,
    SessionNew,
    Prompt,
}

/// Terminal result of one offline ACP transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorAcpOutcome {
    /// A validated writer proposal. This is never Evidence or verification.
    Proposal(PatchProposal),
}

/// Deterministic ACP v1 client for one Cursor session and prompt.
///
/// The machine performs no filesystem, process, credential, or network I/O.
/// Its `bullet.farm` `_meta` contract is an ACP extension, not a capability
/// currently documented by Cursor, so public runtime admission stays blocked.
pub struct CursorAcpTranscript {
    pub(super) phase: Phase,
    pub(super) client_version: String,
    pub(super) expected_runtime_version: String,
    pub(super) subject_digest: String,
    admitted_gate_ids: Vec<String>,
    next_id: u64,
    pending: Option<(u64, Pending)>,
    inbound_frames: usize,
    updates: usize,
    seen_responses: BTreeSet<u64>,
    seen_notifications: BTreeSet<String>,
    pub(super) normalizer: EventNormalizer,
    pub(super) event_serial: u64,
    pub(super) cwd: Option<String>,
    pub(super) native_session_id: Option<String>,
    pub(super) outcome: Option<CursorAcpOutcome>,
}

impl CursorAcpTranscript {
    /// Maximum encoded size of any inbound or outbound frame.
    pub const MAX_FRAME_BYTES: usize = FRAME_LIMIT;
    /// Maximum inbound frames accepted by one transcript.
    pub const MAX_INBOUND_FRAMES: usize = INBOUND_LIMIT;
    /// Maximum streamed updates accepted by one prompt.
    pub const MAX_UPDATES: usize = UPDATE_LIMIT;
    /// Maximum prompt size in UTF-8 bytes.
    pub const MAX_PROMPT_BYTES: usize = PROMPT_LIMIT;
    /// Maximum one streamed text chunk in UTF-8 bytes.
    pub const MAX_CHUNK_BYTES: usize = CHUNK_LIMIT;

    /// Create a machine bound to exact Kernel/runtime subjects and gates.
    pub fn new(
        session_id: AgentSessionId,
        invocation_id: InvocationId,
        client_version: impl Into<String>,
        expected_runtime_version: impl Into<String>,
        subject_digest: impl Into<String>,
        admitted_gate_ids: Vec<String>,
    ) -> Result<Self, HarnessError> {
        let client_version = client_version.into();
        let expected_runtime_version = expected_runtime_version.into();
        let subject_digest = subject_digest.into();
        if !valid_token(&client_version, 128) || !valid_token(&expected_runtime_version, 128) {
            return Err(protocol("invalid client/runtime version binding"));
        }
        if !valid_subject_digest(&subject_digest) {
            return Err(protocol("subject digest must be blake3:<64 lowercase hex>"));
        }
        validate_gate_ids(&admitted_gate_ids)?;
        let mut normalizer = EventNormalizer::new(session_id, "cursor");
        normalizer.set_invocation(invocation_id);
        Ok(Self {
            phase: Phase::New,
            client_version,
            expected_runtime_version,
            subject_digest,
            admitted_gate_ids,
            next_id: 1,
            pending: None,
            inbound_frames: 0,
            updates: 0,
            seen_responses: BTreeSet::new(),
            seen_notifications: BTreeSet::new(),
            normalizer,
            event_serial: 0,
            cwd: None,
            native_session_id: None,
            outcome: None,
        })
    }

    /// Build the ACP v1 `initialize` request with no fs/terminal authority.
    pub fn initialize_request(&mut self) -> Result<Value, HarnessError> {
        self.require_phase(Phase::New, "initialize")?;
        self.phase = Phase::Initializing;
        let version = self.client_version.clone();
        self.request(
            Pending::Initialize,
            "initialize",
            json!({
                "protocolVersion": 1,
                "clientCapabilities": {
                    "fs": {"readTextFile": false, "writeTextFile": false},
                    "terminal": false,
                    "_meta": {"bullet.farm": {"patchProposal": "v1", "readOnly": true}}
                },
                "clientInfo": {"name": "bullet-farm", "version": version}
            }),
        )
    }

    /// Build Cursor's documented protocol-driven authentication request.
    pub fn authenticate_request(&mut self) -> Result<Value, HarnessError> {
        self.require_phase(Phase::Initialized, "authenticate")?;
        self.phase = Phase::Authenticating;
        self.request(
            Pending::Authenticate,
            "authenticate",
            json!({"methodId": "cursor_login"}),
        )
    }

    /// Build `session/new`, bound to one absolute cwd and no MCP servers.
    pub fn session_new_request(&mut self, cwd: &str) -> Result<Value, HarnessError> {
        self.require_phase(Phase::Authenticated, "session/new")?;
        if !valid_cwd(cwd) {
            return self.fail("session/new cwd must be bounded and absolute");
        }
        self.cwd = Some(cwd.to_string());
        self.phase = Phase::SessionStarting;
        let meta = self.binding_meta(None);
        self.request(
            Pending::SessionNew,
            "session/new",
            json!({"cwd": cwd, "mcpServers": [], "_meta": {"bullet.farm": meta}}),
        )
    }

    /// Build one text prompt whose only authoritative output is the extension.
    pub fn prompt_request(&mut self, prompt: &str) -> Result<Value, HarnessError> {
        self.require_phase(Phase::Ready, "session/prompt")?;
        if prompt.is_empty() || prompt.len() > Self::MAX_PROMPT_BYTES {
            return self.fail("prompt must be nonempty and within byte limit");
        }
        let session_id = self.session_id()?.to_string();
        let request_id = self.next_id;
        let mut meta = self.binding_meta(Some(request_id));
        meta.insert("gateIds".into(), json!(self.admitted_gate_ids));
        meta.insert(
            "proposalSchema".into(),
            serde_json::from_str(bullet_harness_core::proposal::schema_source())
                .map_err(|error| protocol(format!("embedded proposal schema invalid: {error}")))?,
        );
        self.phase = Phase::Prompting;
        self.request(
            Pending::Prompt,
            "session/prompt",
            json!({
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": prompt}],
                "_meta": {"bullet.farm": meta}
            }),
        )
    }

    /// Refuse cancellation until a provider-specific receipt is specified.
    pub fn cancel_notification(&mut self) -> Result<Value, HarnessError> {
        self.phase = Phase::Poisoned;
        Err(HarnessError::Unsupported {
            provider: "cursor".to_string(),
            method: "session/cancel",
        })
    }

    /// Refuse timeout inference for the same under-specified cancellation path.
    pub fn timeout_notification(&mut self) -> Result<Value, HarnessError> {
        self.phase = Phase::Poisoned;
        Err(HarnessError::Unsupported {
            provider: "cursor".to_string(),
            method: "session/cancel",
        })
    }

    /// Ingest exactly one bounded JSONL frame and return normalized events.
    pub fn ingest_line(&mut self, line: &str) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase == Phase::Terminal || self.phase == Phase::Poisoned {
            return self.fail("frame received after terminal or poisoned state");
        }
        self.inbound_frames += 1;
        if line.is_empty()
            || line.len() > Self::MAX_FRAME_BYTES
            || self.inbound_frames > Self::MAX_INBOUND_FRAMES
            || line
                .bytes()
                .any(|byte| matches!(byte, b'\n' | b'\r' | b'\0'))
        {
            return self.fail("inbound frame/count or JSONL delimiter limit exceeded");
        }
        let value: Value = match decode_strict_json(line) {
            Ok(value) => value,
            Err(error) => return self.fail(format!("malformed JSON-RPC frame: {error}")),
        };
        let Some(frame) = value.as_object() else {
            return self.fail("JSON-RPC frame must be an object");
        };
        if frame.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return self.fail("JSON-RPC version must be 2.0");
        }
        let result = if frame.contains_key("method") {
            self.notification(frame, &value)
        } else {
            self.response(frame)
        };
        if result.is_err() {
            self.phase = Phase::Poisoned;
        }
        result
    }

    fn request(
        &mut self,
        pending: Pending,
        method: &str,
        params: Value,
    ) -> Result<Value, HarnessError> {
        let id = self.next_id;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let encoded = serde_json::to_vec(&frame)
            .map_err(|_| protocol("outbound request serialization failed"))?;
        if encoded.len() > Self::MAX_FRAME_BYTES {
            return self.fail("outbound request exceeds frame limit");
        }
        self.next_id += 1;
        self.pending = Some((id, pending));
        Ok(frame)
    }

    fn response(&mut self, frame: &Map<String, Value>) -> Result<Vec<AgentEvent>, HarnessError> {
        exact_fields(
            frame,
            &["jsonrpc", "id", "result", "error"],
            &["jsonrpc", "id"],
        )?;
        let Some(id) = frame.get("id").and_then(Value::as_u64) else {
            return self.fail("response id must be an unsigned integer");
        };
        if !self.seen_responses.insert(id) {
            return self.fail("duplicate response id");
        }
        let Some((expected, pending)) = self.pending.take() else {
            return self.fail("unsolicited response");
        };
        if id != expected || frame.contains_key("result") == frame.contains_key("error") {
            return self.fail("response correlation/result shape mismatch");
        }
        if let Some(error) = frame.get("error") {
            let _ = error;
            return self.fail("provider error has no admitted terminal semantics");
        }
        let result = frame.get("result").expect("shape checked");
        match pending {
            Pending::Initialize => self.initialize_response(result),
            Pending::Authenticate => self.authenticate_response(result),
            Pending::SessionNew => self.session_response(result),
            Pending::Prompt => self.prompt_response(id, result),
        }
    }

    fn initialize_response(&mut self, result: &Value) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Initializing, "initialize response")?;
        let object = object(result, "initialize result")?;
        exact_fields(
            object,
            &[
                "protocolVersion",
                "agentCapabilities",
                "agentInfo",
                "authMethods",
            ],
            &[
                "protocolVersion",
                "agentCapabilities",
                "agentInfo",
                "authMethods",
            ],
        )?;
        if object.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
            return self.fail("Cursor did not negotiate ACP v1");
        }
        validate_capabilities(object.get("agentCapabilities").expect("required"))?;
        validate_agent_info(
            object.get("agentInfo").expect("required"),
            &self.expected_runtime_version,
        )?;
        validate_auth_methods(object.get("authMethods").expect("required"))?;
        self.phase = Phase::Initialized;
        Ok(Vec::new())
    }

    fn authenticate_response(&mut self, result: &Value) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Authenticating, "authenticate response")?;
        let object = object(result, "authenticate result")?;
        exact_fields(object, &[], &[])?;
        self.phase = Phase::Authenticated;
        Ok(Vec::new())
    }

    fn session_response(&mut self, result: &Value) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::SessionStarting, "session/new response")?;
        let object = object(result, "session/new result")?;
        exact_fields(object, &["sessionId", "_meta"], &["sessionId", "_meta"])?;
        let session_id = bounded_string(object.get("sessionId"), "sessionId", 256)?;
        if !valid_native_id(session_id) {
            return self.fail("invalid native session id");
        }
        self.validate_binding_meta(object.get("_meta").expect("required"), None, None)?;
        self.native_session_id = Some(session_id.to_string());
        self.normalizer.set_native_session(session_id);
        self.phase = Phase::Ready;
        Ok(vec![self.event(
            AgentEventKind::SessionReady,
            json!({"protocol": "acp-v1", "runtime_version": self.expected_runtime_version}),
            "session-ready",
        )])
    }

    fn prompt_response(
        &mut self,
        id: u64,
        result: &Value,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Prompting, "session/prompt response")?;
        let object = object(result, "session/prompt result")?;
        exact_fields(object, &["stopReason", "_meta"], &["stopReason", "_meta"])?;
        if object.get("stopReason").and_then(Value::as_str) != Some("end_turn") {
            return self.fail("terminal stopReason is not end_turn");
        }
        let proposal_value = self.validate_binding_meta(
            object.get("_meta").expect("required"),
            Some(id),
            Some("proposal"),
        )?;
        let proposal = PatchProposal::from_value(proposal_value.expect("proposal required"))
            .map_err(|error| protocol(format!("proposal refused: {}", error.reason_code())))?;
        if proposal.gate_ids != self.admitted_gate_ids {
            return self.fail("proposal gate_ids differ from exact admitted order");
        }
        let payload = serde_json::to_value(&proposal)
            .map_err(|_| protocol("proposal serialization failed"))?;
        self.outcome = Some(CursorAcpOutcome::Proposal(proposal));
        self.phase = Phase::Terminal;
        Ok(vec![self.event(
            AgentEventKind::TurnCompleted,
            json!({"proposal": payload, "verified": false}),
            "prompt-completed",
        )])
    }

    fn notification(
        &mut self,
        frame: &Map<String, Value>,
        value: &Value,
    ) -> Result<Vec<AgentEvent>, HarnessError> {
        self.require_phase(Phase::Prompting, "notification")?;
        exact_fields(
            frame,
            &["jsonrpc", "method", "params"],
            &["jsonrpc", "method", "params"],
        )?;
        if frame.get("method").and_then(Value::as_str) != Some("session/update") {
            return self.fail("unknown or authority-seeking ACP notification");
        }
        let canonical = serde_json::to_string(value)
            .map_err(|_| protocol("notification serialization failed"))?;
        if !self.seen_notifications.insert(canonical) {
            return self.fail("duplicate notification");
        }
        self.updates += 1;
        if self.updates > Self::MAX_UPDATES {
            return self.fail("session update count limit exceeded");
        }
        let params = object(
            frame.get("params").expect("required"),
            "session/update params",
        )?;
        exact_fields(params, &["sessionId", "update"], &["sessionId", "update"])?;
        if params.get("sessionId").and_then(Value::as_str) != self.native_session_id.as_deref() {
            return self.fail("session/update subject mismatch");
        }
        let update = object(params.get("update").expect("required"), "session update")?;
        exact_fields(
            update,
            &["sessionUpdate", "content"],
            &["sessionUpdate", "content"],
        )?;
        if update.get("sessionUpdate").and_then(Value::as_str) != Some("agent_message_chunk") {
            return self.fail("only untrusted text chunks are admitted; tool updates are refused");
        }
        let content = object(update.get("content").expect("required"), "chunk content")?;
        exact_fields(content, &["type", "text"], &["type", "text"])?;
        if content.get("type").and_then(Value::as_str) != Some("text") {
            return self.fail("only text ACP content is admitted");
        }
        let text = bounded_string(content.get("text"), "text chunk", Self::MAX_CHUNK_BYTES)?;
        Ok(vec![self.event(
            AgentEventKind::TurnDelta,
            json!({"text": text, "authoritative": false}),
            "agent-message-chunk",
        )])
    }
}
