//! Pure, frozen Claude bidirectional stream-JSON protocol boundary.

use bullet_harness_core::{
    live::dispatch::MAX_INTERACTIVE_LINES, proposal::validate_gate_ids, unsupported, AgentEvent,
    AgentEventKind, AgentSessionId, EventNormalizer, HarnessError, InvocationId, NativeMeta,
    PatchProposal,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Exact installed build whose embedded schema source was observed offline.
///
/// This is not a live conformance or executable-admission claim.
pub const OBSERVED_CLAUDE_SCHEMA_VERSION: &str = "2.1.243";
/// Maximum bytes in one admitted stream-JSON frame.
pub const MAX_STREAM_JSON_FRAME_BYTES: usize = 1024 * 1024;
/// Maximum frames consumed by one transcript, including control and terminal frames.
pub const MAX_STREAM_JSON_FRAMES: u64 = 34;
/// Maximum assistant messages consumed by one transcript.
pub const MAX_ASSISTANT_MESSAGES: u64 = 32;
/// Maximum structured content items in one assistant message.
pub const MAX_ASSISTANT_CONTENT_ITEMS: usize = 32;
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_ID_BYTES: usize = 128;

/// Frames admitted by one dogfood read-only turn.
///
/// A real read-only turn interleaves `assistant`/`user` tool frames, so the
/// frozen conformance bound of [`MAX_STREAM_JSON_FRAMES`] (sized for a single
/// PONG exchange) cannot express it. This bound is still a hard refusal.
pub const DOGFOOD_MAX_STREAM_JSON_FRAMES: u64 = MAX_INTERACTIVE_LINES as u64;
/// Assistant messages admitted by one dogfood read-only turn.
pub const DOGFOOD_MAX_ASSISTANT_MESSAGES: u64 = 512;
/// The only tools a read-only provider turn may advertise, in any order.
///
/// Membership is checked as a set: a `system/init` advertising anything outside
/// this list (`Bash`, `Write`, `Edit`, …) poisons the transcript under every
/// profile. ADR 0001 makes providers proposers; this is where that is enforced
/// on the wire.
pub const READ_ONLY_TOOL_ALLOWLIST: [&str; 3] = ["Read", "Glob", "Grep"];

/// Which transcript contract one turn is parsed under.
///
/// The two profiles are not interchangeable and a transcript never changes
/// profile after construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptProfile {
    /// The frozen V1 conformance subject: one PONG exchange, no tool use, and
    /// the exact runtime build recorded in [`OBSERVED_CLAUDE_SCHEMA_VERSION`].
    /// Its admission is unchanged by the existence of any other profile.
    ConformanceV1,
    /// One read-only dogfood coding turn (ADR 0015). It admits read-only tool
    /// use and the operator-enrolled runtime build, and it relaxes nothing that
    /// bounds provider authority: the tool allowlist, `permissionMode: "plan"`,
    /// empty mcp/agents/skills/plugins, the terminal `PatchProposal` and its
    /// exact `gate_ids`, frame/message ceilings, duplicate-frame and
    /// duplicate-uuid refusal, and native-session binding all still apply.
    DogfoodReadOnlyV0,
}

impl TranscriptProfile {
    /// Maximum inbound frames admitted under this profile.
    #[must_use]
    pub const fn max_stream_json_frames(self) -> u64 {
        match self {
            Self::ConformanceV1 => MAX_STREAM_JSON_FRAMES,
            Self::DogfoodReadOnlyV0 => DOGFOOD_MAX_STREAM_JSON_FRAMES,
        }
    }

    /// Maximum assistant messages admitted under this profile.
    #[must_use]
    pub const fn max_assistant_messages(self) -> u64 {
        match self {
            Self::ConformanceV1 => MAX_ASSISTANT_MESSAGES,
            Self::DogfoodReadOnlyV0 => DOGFOOD_MAX_ASSISTANT_MESSAGES,
        }
    }

    /// Whether this profile admits read-only tool use and its `user` frames.
    #[must_use]
    pub const fn admits_tool_use(self) -> bool {
        matches!(self, Self::DogfoodReadOnlyV0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    AwaitSessionInit,
    Active,
    Terminal,
    Poisoned,
}

/// Terminal result of one exact offline Claude stream transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaudeStreamOutcome {
    /// A schema-valid proposal naming exactly the admitted gates.
    Proposal(PatchProposal),
    /// Claude emitted a valid non-cancellation failure result.
    Failed(String),
}

/// Deterministic state machine for one Claude bidirectional stream-JSON turn.
///
/// It performs no filesystem, environment, process, credential, clock, or
/// network I/O. A separate signed runtime admission is required before any
/// request returned here may be transported to Claude.
pub struct ClaudeStreamTranscript {
    pub(super) profile: TranscriptProfile,
    pub(super) phase: Phase,
    pub(super) invocation_id: String,
    pub(super) expected_cwd: String,
    pub(super) expected_runtime_version: String,
    pub(super) admitted_gate_ids: Vec<String>,
    pub(super) native_session_id: Option<String>,
    pub(super) model: Option<String>,
    pub(super) seen_frames: BTreeSet<String>,
    pub(super) seen_event_ids: BTreeSet<String>,
    pub(super) seen_message_ids: BTreeSet<String>,
    pub(super) seen_tool_use_ids: BTreeSet<String>,
    pub(super) outstanding_tool_use_ids: BTreeSet<String>,
    pub(super) inbound_frames: u64,
    pub(super) assistant_messages: u64,
    pub(super) normalizer: EventNormalizer,
    pub(super) outcome: Option<ClaudeStreamOutcome>,
}

impl ClaudeStreamTranscript {
    /// Bind one Kernel session/invocation, frozen runtime, cwd, and ordered gates.
    ///
    /// # Errors
    ///
    /// Refuses malformed identifiers, cwd, or gate admission.
    pub fn new(
        session_id: AgentSessionId,
        invocation_id: InvocationId,
        expected_cwd: impl Into<String>,
        expected_runtime_version: impl Into<String>,
        admitted_gate_ids: Vec<String>,
    ) -> Result<Self, HarnessError> {
        Self::new_with_profile(
            session_id,
            invocation_id,
            expected_cwd,
            expected_runtime_version,
            admitted_gate_ids,
            TranscriptProfile::ConformanceV1,
        )
    }

    /// Bind one turn under an explicit [`TranscriptProfile`].
    ///
    /// Under [`TranscriptProfile::ConformanceV1`] the runtime version must be
    /// exactly [`OBSERVED_CLAUDE_SCHEMA_VERSION`], as before. Under
    /// [`TranscriptProfile::DogfoodReadOnlyV0`] it must be a well-formed
    /// version string, which the caller takes from the operator's enrollment
    /// record: that record — not a constant in this crate — is the pin, and it
    /// binds the executable digest the bytes were observed from. `system/init`
    /// must still match the bound version exactly, so a runtime that differs
    /// from the enrolled one poisons the transcript.
    ///
    /// # Errors
    ///
    /// Refuses malformed identifiers, cwd, runtime version, or gate admission.
    pub fn new_with_profile(
        session_id: AgentSessionId,
        invocation_id: InvocationId,
        expected_cwd: impl Into<String>,
        expected_runtime_version: impl Into<String>,
        admitted_gate_ids: Vec<String>,
        profile: TranscriptProfile,
    ) -> Result<Self, HarnessError> {
        let kernel_session_id = session_id.as_str();
        let invocation = invocation_id.as_str().to_string();
        let expected_cwd = expected_cwd.into();
        let expected_runtime_version = expected_runtime_version.into();
        if !valid_kernel_id(kernel_session_id) || !valid_kernel_id(&invocation) {
            return Err(protocol("invalid Kernel session or invocation id"));
        }
        if !valid_cwd(&expected_cwd) {
            return Err(protocol("invalid read-only cwd binding"));
        }
        match profile {
            TranscriptProfile::ConformanceV1 => {
                if expected_runtime_version != OBSERVED_CLAUDE_SCHEMA_VERSION {
                    return Err(protocol(format!(
                        "runtime version {expected_runtime_version:?} has no frozen transcript contract"
                    )));
                }
            }
            TranscriptProfile::DogfoodReadOnlyV0 => {
                if !valid_runtime_version(&expected_runtime_version) {
                    return Err(protocol(format!(
                        "enrolled runtime version {expected_runtime_version:?} is malformed"
                    )));
                }
            }
        }
        validate_gate_ids(&admitted_gate_ids)?;
        let mut normalizer = EventNormalizer::new(session_id, "claude");
        normalizer.set_invocation(invocation_id);
        Ok(Self {
            profile,
            phase: Phase::New,
            invocation_id: invocation,
            expected_cwd,
            expected_runtime_version,
            admitted_gate_ids,
            native_session_id: None,
            model: None,
            seen_frames: BTreeSet::new(),
            seen_event_ids: BTreeSet::new(),
            seen_message_ids: BTreeSet::new(),
            seen_tool_use_ids: BTreeSet::new(),
            outstanding_tool_use_ids: BTreeSet::new(),
            inbound_frames: 0,
            assistant_messages: 0,
            normalizer,
            outcome: None,
        })
    }

    /// Build one exact user message; Claude emits system/init in response.
    pub fn user_message(&mut self, prompt: &str) -> Result<Value, HarnessError> {
        self.require_phase(Phase::New, "user message")?;
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains('\0') {
            return self.fail("invalid user prompt");
        }
        let frame = json!({
            "type": "user",
            "uuid": self.invocation_id,
            "session_id": "",
            "message": {"role": "user", "content": [{"type": "text", "text": prompt}]},
            "parent_tool_use_id": null,
        });
        let encoded_bytes = match serde_json::to_vec(&frame) {
            Ok(encoded) => encoded.len(),
            Err(error) => return self.fail(format!("user frame encoding failed: {error}")),
        };
        if encoded_bytes > MAX_STREAM_JSON_FRAME_BYTES {
            return self.fail("encoded user frame exceeds stream-JSON frame limit");
        }
        self.phase = Phase::AwaitSessionInit;
        Ok(frame)
    }

    /// Refuse interruption because no exact terminal agreement is admitted.
    pub fn interrupt_request(&mut self) -> Result<Value, HarnessError> {
        self.unsupported_cancellation("offline_interrupt")
    }

    /// Refuse timeout cancellation because no exact terminal agreement is admitted.
    pub fn timeout_request(&mut self) -> Result<Value, HarnessError> {
        self.unsupported_cancellation("offline_timeout")
    }

    /// Read the outcome only after a complete, mutually consistent terminal.
    pub fn outcome(&self) -> Result<&ClaudeStreamOutcome, HarnessError> {
        if self.phase != Phase::Terminal {
            return Err(protocol("turn has no complete terminal outcome"));
        }
        self.outcome
            .as_ref()
            .ok_or_else(|| protocol("terminal outcome missing"))
    }

    fn unsupported_cancellation(&mut self, operation: &'static str) -> Result<Value, HarnessError> {
        self.phase = Phase::Poisoned;
        self.outcome = None;
        Err(unsupported("claude", operation))
    }

    pub(super) fn require_phase(
        &mut self,
        expected: Phase,
        operation: &str,
    ) -> Result<(), HarnessError> {
        if self.phase != expected {
            return self.fail(format!("{operation} is invalid in phase {:?}", self.phase));
        }
        Ok(())
    }

    pub(super) fn event(
        &mut self,
        kind: AgentEventKind,
        payload: Value,
        native_event_id: &str,
    ) -> AgentEvent {
        self.normalizer.accept(
            kind,
            payload,
            &NativeMeta {
                event_id: Some(native_event_id.to_string()),
                sequence: None,
            },
        )
    }

    pub(super) fn fail<T>(&mut self, reason: impl Into<String>) -> Result<T, HarnessError> {
        self.phase = Phase::Poisoned;
        self.outcome = None;
        Err(protocol(reason))
    }
}

/// A syntactically admissible provider runtime version.
///
/// Deliberately narrow: dotted digits with optional short alphanumeric or
/// `-`/`+` build parts, bounded length. It authenticates nothing — the
/// operator's enrollment record binds the executable digest.
fn valid_runtime_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        && value.contains('.')
}

pub(super) fn protocol(reason: impl Into<String>) -> HarnessError {
    HarnessError::Protocol {
        provider: "claude".to_string(),
        reason: reason.into(),
    }
}

pub(super) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}

pub(super) fn valid_native_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_kernel_id(value: &str) -> bool {
    valid_native_id(value)
}

fn valid_cwd(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 4096 && !value.contains('\0') && !value.contains("//")
}

pub(super) fn exact_fields(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> bool {
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

pub(super) fn basic_event_subject(object: &Map<String, Value>) -> Option<(&str, &str)> {
    Some((
        object.get("uuid")?.as_str()?,
        object.get("session_id")?.as_str()?,
    ))
}

pub(super) fn event_subject(object: &Map<String, Value>) -> Option<(&str, &str, &str)> {
    let (uuid, session_id) = basic_event_subject(object)?;
    let model = object.get("model")?.as_str()?;
    if !valid_uuid(uuid) || !valid_uuid(session_id) || !valid_native_id(model) {
        return None;
    }
    Some((uuid, session_id, model))
}

pub(super) fn unique_string_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Option<Vec<&'a str>> {
    let strings: Vec<_> = object
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    (strings.iter().copied().collect::<BTreeSet<_>>().len() == strings.len()).then_some(strings)
}

pub(super) fn empty_array(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

pub(super) fn empty_optional_array(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
}

pub(super) fn valid_result_common(object: &Map<String, Value>) -> bool {
    let required = [
        "type",
        "subtype",
        "uuid",
        "session_id",
        "duration_ms",
        "duration_api_ms",
        "is_error",
        "num_turns",
        "stop_reason",
        "total_cost_usd",
        "usage",
        "modelUsage",
        "permission_denials",
    ];
    let optional = [
        "result",
        "structured_output",
        "errors",
        "api_error_status",
        "ttft_ms",
        "deferred_tool_use",
        "fast_mode_state",
        "fast_mode_disabled_reason",
        "terminal_reason",
    ];
    exact_fields(object, &required, &optional)
        && object.get("duration_ms").and_then(Value::as_u64).is_some()
        && object
            .get("duration_api_ms")
            .and_then(Value::as_u64)
            .is_some()
        && object
            .get("num_turns")
            .and_then(Value::as_u64)
            .is_some_and(|turns| turns > 0)
        && object
            .get("total_cost_usd")
            .and_then(Value::as_f64)
            .is_some_and(|cost| cost.is_finite() && cost >= 0.0)
        && object.get("usage").is_some_and(Value::is_object)
        && object.get("modelUsage").is_some_and(Value::is_object)
        && object
            .get("permission_denials")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && object
            .get("terminal_reason")
            .is_none_or(|reason| reason.is_null() || reason.is_string())
}
