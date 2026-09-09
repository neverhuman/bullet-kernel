//! Guarded live dispatch for the Codex App Server. Drives the frozen
//! bidirectional JSONL contract (`initialize` -> `initialized` ->
//! `thread/start` -> `turn/start`) through the caller-supplied (egress)
//! command factory and the reactive stdio runner in `bullet-harness-core`.
//! It never spawns `codex` itself. This path is exercised only under an
//! operator-ratified live-admission policy; under v1alpha1 the orchestrator
//! refuses long before it is reached.

use crate::protocol::CodexAppServerTranscript;
use bullet_harness_core::live::dispatch::artifact_digest;
use bullet_harness_core::{
    run_interactive, scan_events, AgentEvent, AgentEventKind, ArgvBuilder, CommandFactory,
    EvaluatedAdmission, HarnessError, InteractiveReaction, LiveTurnOutcome, LiveTurnRequest,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Client version advertised in `initialize`.
pub const CODEX_CLIENT_VERSION: &str = "bullet-farm-conformance";
/// Runtime version the frozen App Server thread subject is checked against.
pub const CODEX_OBSERVED_RUNTIME_VERSION: &str = "0.0.0";

/// Dispatch one read-only Codex App Server turn against a cleared admission.
///
/// # Errors
///
/// `PROVIDER_ADMISSION_BLOCKED` when a blocker remains, `SPAWN_FAILED` /
/// `IO_FAILED` on process failure, `SECRET_CANARY_EXPOSURE` on a leaked
/// canary, or `PROTOCOL_ERROR` when the exchange is not conformant.
pub fn dispatch_live_turn(
    admission: &EvaluatedAdmission,
    factory: &CommandFactory<'_>,
    request: &LiveTurnRequest,
) -> Result<LiveTurnOutcome, HarnessError> {
    let cwd = request.workdir.to_string_lossy().into_owned();
    let prepared = ArgvBuilder::new(admission.executable().to_string_lossy().into_owned(), &cwd)
        .arg("app-server")
        .timeout(request.wall_timeout)
        .build_with_admission(admission)?;

    let transcript = Rc::new(RefCell::new(CodexAppServerTranscript::new(
        request.session_id.clone(),
        request.invocation_id.clone(),
        CODEX_CLIENT_VERSION,
        CODEX_OBSERVED_RUNTIME_VERSION,
        request.gate_ids.clone(),
    )?));
    let events: Rc<RefCell<Vec<AgentEvent>>> = Rc::new(RefCell::new(Vec::new()));

    let initial = vec![to_line(&transcript.borrow_mut().initialize_request()?)?];
    let cwd_frame = cwd.clone();
    let prompt = request.prompt.clone();
    let driver_transcript = Rc::clone(&transcript);
    let driver_events = Rc::clone(&events);
    let mut on_line = move |line: &str| -> Result<InteractiveReaction, HarnessError> {
        let mut transcript = driver_transcript.borrow_mut();
        let new_events = transcript.ingest_line(line)?;
        let mut send = Vec::new();
        let mut done = false;
        for event in &new_events {
            match event.kind {
                AgentEventKind::SessionStarted => {
                    send.push(to_line(&transcript.initialized_notification()?)?);
                    send.push(to_line(&transcript.thread_start_request(&cwd_frame)?)?);
                }
                AgentEventKind::SessionReady => {
                    send.push(to_line(
                        &transcript.turn_start_request(&prompt, &cwd_frame)?,
                    )?);
                }
                AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed => done = true,
                _ => {}
            }
        }
        driver_events.borrow_mut().extend(new_events);
        Ok(InteractiveReaction { send, done })
    };

    let capture = run_interactive(factory, &prepared, &request.canaries, initial, &mut on_line)?;
    drop(on_line);

    transcript.borrow().outcome()?;
    let events = Rc::try_unwrap(events)
        .map(RefCell::into_inner)
        .unwrap_or_default();
    let events_blake3 = scan_events(&events, &request.canaries)?;
    let response_text = extract_response(&events);
    let native_session_id = events
        .iter()
        .find_map(|event| event.native_session_id.clone());

    Ok(LiveTurnOutcome {
        response_text,
        native_session_id,
        total_cost_micro_usd: None,
        exit_code: capture.exit_code,
        wall_ms: capture.wall_ms,
        timed_out: capture.timed_out,
        stdout_blake3: artifact_digest(b"stdout", capture.stdout().as_bytes()),
        stderr_blake3: artifact_digest(b"stderr", capture.stderr.as_bytes()),
        events_blake3,
        events,
    })
}

fn to_line(frame: &serde_json::Value) -> Result<String, HarnessError> {
    serde_json::to_string(frame).map_err(|error| HarnessError::Protocol {
        provider: crate::PROVIDER.to_string(),
        reason: format!("outbound frame serialization failed: {error}"),
    })
}

fn extract_response(events: &[AgentEvent]) -> String {
    if let Some(text) = events.iter().find_map(|event| {
        (event.kind == AgentEventKind::TurnDelta
            && event
                .payload
                .get("final")
                .and_then(serde_json::Value::as_bool)
                == Some(true))
        .then(|| event.payload.get("text").and_then(|value| value.as_str()))
        .flatten()
    }) {
        return text.to_string();
    }
    let mut text = String::new();
    for event in events {
        if event.kind == AgentEventKind::TurnDelta {
            if let Some(chunk) = event.payload.get("text").and_then(|value| value.as_str()) {
                text.push_str(chunk);
            }
        }
    }
    text
}
