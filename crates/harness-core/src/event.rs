//! `AgentEvent` envelope and stream normalizer (spec s18.3). Malformed,
//! duplicate, stale, and out-of-order provider events become typed
//! `protocol.error` envelopes instead of corrupting the sequence.

use crate::ids::{synthetic_uuid, AgentSessionId, EventId, InvocationId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Path to a stored raw provider transcript (JSONL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef(String);

impl ArtifactRef {
    /// Wrap an artifact path.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Borrow the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Free-form event payload. Provider output is untrusted data.
pub type AgentEventPayload = Value;

/// The 26 event kinds of spec s18.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentEventKind {
    #[serde(rename = "session.started")]
    SessionStarted,
    #[serde(rename = "session.ready")]
    SessionReady,
    #[serde(rename = "session.identity")]
    SessionIdentity,
    #[serde(rename = "turn.started")]
    TurnStarted,
    #[serde(rename = "turn.delta")]
    TurnDelta,
    #[serde(rename = "turn.completed")]
    TurnCompleted,
    #[serde(rename = "turn.failed")]
    TurnFailed,
    #[serde(rename = "thinking.delta")]
    ThinkingDelta,
    #[serde(rename = "tool.requested")]
    ToolRequested,
    #[serde(rename = "tool.started")]
    ToolStarted,
    #[serde(rename = "tool.completed")]
    ToolCompleted,
    #[serde(rename = "tool.failed")]
    ToolFailed,
    #[serde(rename = "permission.requested")]
    PermissionRequested,
    #[serde(rename = "plan.proposed")]
    PlanProposed,
    #[serde(rename = "plan.waiting")]
    PlanWaiting,
    #[serde(rename = "usage.reported")]
    UsageReported,
    #[serde(rename = "quota.reported")]
    QuotaReported,
    #[serde(rename = "context.reported")]
    ContextReported,
    #[serde(rename = "auth.required")]
    AuthRequired,
    #[serde(rename = "rate_limited")]
    RateLimited,
    #[serde(rename = "steering.acknowledged")]
    SteeringAcknowledged,
    #[serde(rename = "interrupt.acknowledged")]
    InterruptAcknowledged,
    #[serde(rename = "checkpoint.completed")]
    CheckpointCompleted,
    #[serde(rename = "session.compacted")]
    SessionCompacted,
    #[serde(rename = "session.terminated")]
    SessionTerminated,
    #[serde(rename = "protocol.error")]
    ProtocolError,
}

impl AgentEventKind {
    /// All 26 kinds in spec order.
    pub const ALL: [AgentEventKind; 26] = [
        AgentEventKind::SessionStarted,
        AgentEventKind::SessionReady,
        AgentEventKind::SessionIdentity,
        AgentEventKind::TurnStarted,
        AgentEventKind::TurnDelta,
        AgentEventKind::TurnCompleted,
        AgentEventKind::TurnFailed,
        AgentEventKind::ThinkingDelta,
        AgentEventKind::ToolRequested,
        AgentEventKind::ToolStarted,
        AgentEventKind::ToolCompleted,
        AgentEventKind::ToolFailed,
        AgentEventKind::PermissionRequested,
        AgentEventKind::PlanProposed,
        AgentEventKind::PlanWaiting,
        AgentEventKind::UsageReported,
        AgentEventKind::QuotaReported,
        AgentEventKind::ContextReported,
        AgentEventKind::AuthRequired,
        AgentEventKind::RateLimited,
        AgentEventKind::SteeringAcknowledged,
        AgentEventKind::InterruptAcknowledged,
        AgentEventKind::CheckpointCompleted,
        AgentEventKind::SessionCompacted,
        AgentEventKind::SessionTerminated,
        AgentEventKind::ProtocolError,
    ];

    /// Stable wire name (dotted, per spec s18.3).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionStarted => "session.started",
            Self::SessionReady => "session.ready",
            Self::SessionIdentity => "session.identity",
            Self::TurnStarted => "turn.started",
            Self::TurnDelta => "turn.delta",
            Self::TurnCompleted => "turn.completed",
            Self::TurnFailed => "turn.failed",
            Self::ThinkingDelta => "thinking.delta",
            Self::ToolRequested => "tool.requested",
            Self::ToolStarted => "tool.started",
            Self::ToolCompleted => "tool.completed",
            Self::ToolFailed => "tool.failed",
            Self::PermissionRequested => "permission.requested",
            Self::PlanProposed => "plan.proposed",
            Self::PlanWaiting => "plan.waiting",
            Self::UsageReported => "usage.reported",
            Self::QuotaReported => "quota.reported",
            Self::ContextReported => "context.reported",
            Self::AuthRequired => "auth.required",
            Self::RateLimited => "rate_limited",
            Self::SteeringAcknowledged => "steering.acknowledged",
            Self::InterruptAcknowledged => "interrupt.acknowledged",
            Self::CheckpointCompleted => "checkpoint.completed",
            Self::SessionCompacted => "session.compacted",
            Self::SessionTerminated => "session.terminated",
            Self::ProtocolError => "protocol.error",
        }
    }
}

/// Structured event envelope (spec s18.3 fields verbatim; provider and model
/// are strings because the domain crate defines no provider/model ids).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// Envelope id.
    pub event_id: EventId,
    /// Kernel session id.
    pub session_id: AgentSessionId,
    /// Invocation this event belongs to.
    pub invocation_id: Option<InvocationId>,
    /// Provider-native session id.
    pub native_session_id: Option<String>,
    /// Provider name.
    pub provider: String,
    /// Model when known.
    pub model: Option<String>,
    /// Event kind.
    pub kind: AgentEventKind,
    /// Envelope timestamp.
    pub timestamp: DateTime<Utc>,
    /// Monotonic per-session sequence.
    pub sequence: u64,
    /// Causing envelope when known.
    pub causation_id: Option<EventId>,
    /// Untrusted provider payload.
    pub payload: AgentEventPayload,
    /// Raw transcript path.
    pub raw_artifact: Option<ArtifactRef>,
}

/// Native-stream metadata used for duplicate/order detection.
#[derive(Clone, Debug, Default)]
pub struct NativeMeta {
    /// Provider-native event id when present.
    pub event_id: Option<String>,
    /// Provider-native sequence when present.
    pub sequence: Option<u64>,
}

impl NativeMeta {
    /// No native metadata.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// Normalizes one provider stream into monotonic envelopes.
#[derive(Debug)]
pub struct EventNormalizer {
    session_id: AgentSessionId,
    provider: String,
    invocation_id: Option<InvocationId>,
    native_session_id: Option<String>,
    model: Option<String>,
    raw_artifact: Option<ArtifactRef>,
    next_sequence: u64,
    seen_native: BTreeSet<String>,
    last_native_sequence: Option<u64>,
    turn_closed: bool,
}

impl EventNormalizer {
    /// New normalizer for one session.
    #[must_use]
    pub fn new(session_id: AgentSessionId, provider: impl Into<String>) -> Self {
        Self {
            session_id,
            provider: provider.into(),
            invocation_id: None,
            native_session_id: None,
            model: None,
            raw_artifact: None,
            next_sequence: 0,
            seen_native: BTreeSet::new(),
            last_native_sequence: None,
            turn_closed: false,
        }
    }

    /// Bind the current invocation.
    pub fn set_invocation(&mut self, invocation: InvocationId) {
        self.invocation_id = Some(invocation);
    }

    /// Record the provider-native session id.
    pub fn set_native_session(&mut self, native: impl Into<String>) {
        self.native_session_id = Some(native.into());
    }

    /// Record the model in effect.
    pub fn set_model(&mut self, model: impl Into<String>) {
        self.model = Some(model.into());
    }

    /// Record the raw transcript path stamped on every envelope.
    pub fn set_raw_artifact(&mut self, artifact: ArtifactRef) {
        self.raw_artifact = Some(artifact);
    }

    fn envelope(&mut self, kind: AgentEventKind, payload: Value) -> AgentEvent {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        AgentEvent {
            event_id: EventId::new(synthetic_uuid("event")),
            session_id: self.session_id.clone(),
            invocation_id: self.invocation_id.clone(),
            native_session_id: self.native_session_id.clone(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            kind,
            timestamp: Utc::now(),
            sequence,
            causation_id: None,
            payload,
            raw_artifact: self.raw_artifact.clone(),
        }
    }

    /// Accept one provider event. Duplicates, out-of-order native sequences,
    /// and events after turn close become `protocol.error` anomalies.
    pub fn accept(
        &mut self,
        kind: AgentEventKind,
        payload: Value,
        native: &NativeMeta,
    ) -> AgentEvent {
        if let Some(native_id) = &native.event_id {
            if !self.seen_native.insert(native_id.clone()) {
                return self.anomaly("DUPLICATE_EVENT", json!({ "native_event_id": native_id }));
            }
        }
        if let Some(native_seq) = native.sequence {
            if self
                .last_native_sequence
                .is_some_and(|last| native_seq <= last)
            {
                return self.anomaly(
                    "OUT_OF_ORDER_EVENT",
                    json!({ "native_sequence": native_seq, "dropped_kind": kind.as_str() }),
                );
            }
            self.last_native_sequence = Some(native_seq);
        }
        if kind == AgentEventKind::TurnStarted {
            self.turn_closed = false;
        } else if self.turn_closed
            && matches!(
                kind,
                AgentEventKind::TurnDelta | AgentEventKind::ThinkingDelta
            )
        {
            return self.anomaly("STALE_EVENT", json!({ "dropped_kind": kind.as_str() }));
        }
        if matches!(
            kind,
            AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed
        ) {
            self.turn_closed = true;
        }
        self.envelope(kind, payload)
    }

    /// A raw line that was not valid provider JSON.
    pub fn malformed(&mut self, raw_line: &str) -> AgentEvent {
        self.anomaly("MALFORMED_EVENT", json!({ "raw": raw_line }))
    }

    /// A typed protocol anomaly envelope.
    pub fn anomaly(&mut self, reason_code: &str, detail: Value) -> AgentEvent {
        self.envelope(
            AgentEventKind::ProtocolError,
            json!({ "reason_code": reason_code, "detail": detail }),
        )
    }
}
