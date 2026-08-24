//! Internal helpers for the simulator: stream ingestion, raw artifact
//! writing, the long-turn loop, and the declared capability matrix.

use crate::scenario;
use crate::SimAdapter;
use bullet_harness_core::{
    Ack, AgentEventKind, Capability, CapabilityMatrix, CapabilityState, EventNormalizer,
    HarnessError, HarnessResult, InvocationId, NativeMeta, TurnHandle,
};
use serde_json::{json, Value};
use std::io::Write;
use std::time::Duration;

impl SimAdapter {
    pub(crate) fn with_normalizer<R>(
        &self,
        session_id: &str,
        f: impl FnOnce(&mut EventNormalizer) -> R,
    ) -> HarnessResult<R> {
        let mut map = self.normalizers.lock().map_err(|_| HarnessError::Io {
            context: "normalizer lock".into(),
            reason: "poisoned".into(),
        })?;
        map.get_mut(session_id)
            .map(f)
            .ok_or_else(|| HarnessError::SessionUnknown {
                session: session_id.to_string(),
            })
    }

    pub(crate) fn append_raw(&self, session_id: &str, lines: &[String]) -> HarnessResult<()> {
        let path = self
            .store
            .with_entry(session_id, |e| e.artifact_path.clone())?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| HarnessError::Io {
                context: format!("raw artifact {}", path.display()),
                reason: err.to_string(),
            })?;
        for line in lines {
            let _ = writeln!(file, "{line}");
        }
        Ok(())
    }

    pub(crate) fn parse_raw(line: &str) -> Option<(AgentEventKind, Value, NativeMeta)> {
        let value: Value = serde_json::from_str(line).ok()?;
        let kind: AgentEventKind = serde_json::from_value(value.get("kind")?.clone()).ok()?;
        let payload = value.get("payload").cloned().unwrap_or(Value::Null);
        let meta = NativeMeta {
            event_id: value
                .get("native_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            sequence: value.get("native_seq").and_then(Value::as_u64),
        };
        Some((kind, payload, meta))
    }

    pub(crate) fn ingest(&self, session_id: &str, lines: &[String]) -> HarnessResult<()> {
        self.append_raw(session_id, lines)?;
        let events = self.with_normalizer(session_id, |n| {
            lines
                .iter()
                .map(|line| match Self::parse_raw(line) {
                    Some((kind, payload, meta)) => n.accept(kind, payload, &meta),
                    None => n.malformed(line),
                })
                .collect::<Vec<_>>()
        })?;
        self.store.push_events(session_id, events)
    }

    pub(crate) fn emit(
        &self,
        session_id: &str,
        kind: AgentEventKind,
        payload: Value,
    ) -> HarnessResult<()> {
        let event =
            self.with_normalizer(session_id, |n| n.accept(kind, payload, &NativeMeta::none()))?;
        self.store.push_events(session_id, vec![event])
    }

    pub(crate) async fn run_long_turn(
        &self,
        session_id: &str,
        invocation_id: InvocationId,
    ) -> HarnessResult<TurnHandle> {
        self.emit(session_id, AgentEventKind::TurnStarted, json!({}))?;
        for tick in 0..200u32 {
            if self.store.with_entry(session_id, |e| e.interrupted)? {
                self.emit(
                    session_id,
                    AgentEventKind::SessionTerminated,
                    json!({ "reason": "interrupted", "tick": tick }),
                )?;
                return Ok(TurnHandle {
                    invocation_id,
                    exit_code: None,
                    timed_out: false,
                });
            }
            self.emit(
                session_id,
                AgentEventKind::TurnDelta,
                json!({ "text": ".", "tick": tick }),
            )?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.emit(
            session_id,
            AgentEventKind::TurnCompleted,
            json!({ "proposal": scenario::sample_proposal(), "text": "long turn done" }),
        )?;
        Ok(TurnHandle {
            invocation_id,
            exit_code: Some(0),
            timed_out: false,
        })
    }

    pub(crate) fn close_waiting_turn(
        &self,
        session_id: &str,
        approved: bool,
    ) -> HarnessResult<Ack> {
        if approved {
            self.emit(
                session_id,
                AgentEventKind::UsageReported,
                json!({ "input_tokens": 90, "output_tokens": 30, "cost_usd": 0.001 }),
            )?;
            self.emit(
                session_id,
                AgentEventKind::TurnCompleted,
                json!({ "proposal": scenario::sample_proposal(), "text": "approved" }),
            )?;
        } else {
            self.emit(
                session_id,
                AgentEventKind::TurnFailed,
                json!({ "reason": "rejected by decision" }),
            )?;
        }
        Ok(Ack { acknowledged: true })
    }
}

pub(crate) fn capabilities() -> CapabilityMatrix {
    let supported = [
        Capability::StructuredEvents,
        Capability::StructuredOutputSchema,
        Capability::NativeResume,
        Capability::TurnInterrupt,
        Capability::MidTurnSteering,
        Capability::ToolApprovals,
        Capability::PlanModeControl,
        Capability::UsageEvents,
        Capability::QuotaSource,
        Capability::ModelSelection,
        Capability::ContextUsage,
        Capability::NativeCompaction,
        Capability::SessionExport,
        Capability::HeadlessMode,
        Capability::MultilinePrompt,
    ];
    let mut matrix = CapabilityMatrix::new();
    for capability in supported {
        matrix.set(capability, CapabilityState::Supported);
    }
    matrix
}
