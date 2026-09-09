//! Guarded live dispatch for Claude Code. Builds the frozen read-only argv
//! through the admission chokepoint, runs exactly one turn inside the
//! caller-supplied (egress) command factory, and parses the bidirectional
//! stream-JSON transcript with the frozen [`ClaudeStreamTranscript`] contract.
//! It never spawns `claude` itself; the factory owns the process.

use crate::protocol::{ClaudeStreamTranscript, OBSERVED_CLAUDE_SCHEMA_VERSION};
use bullet_harness_core::live::dispatch::artifact_digest;
use bullet_harness_core::{
    capture_turn, scan_events, AgentEvent, AgentEventKind, ArgvBuilder, CommandFactory,
    EvaluatedAdmission, HarnessError, LiveTurnOutcome, LiveTurnRequest,
};

/// Dispatch one read-only Claude turn against a fully-cleared admission.
///
/// # Errors
///
/// `PROVIDER_ADMISSION_BLOCKED` when the admission still carries a blocker,
/// `SPAWN_FAILED`/`IO_FAILED` on process failure, `SECRET_CANARY_EXPOSURE` on
/// a leaked canary, or `PROTOCOL_ERROR` when the transcript is not conformant.
pub fn dispatch_live_turn(
    admission: &EvaluatedAdmission,
    factory: &CommandFactory<'_>,
    request: &LiveTurnRequest,
) -> Result<LiveTurnOutcome, HarnessError> {
    let cwd = request.workdir.to_string_lossy().into_owned();
    let prepared = ArgvBuilder::new(admission.executable().to_string_lossy().into_owned(), &cwd)
        .arg("-p")
        .arg(&request.prompt)
        .arg("--output-format")
        .arg("stream-json")
        .arg("--verbose")
        .arg("--permission-mode")
        .arg("plan")
        .arg("--max-budget-usd")
        .arg(request.max_budget_usd())
        .timeout(request.wall_timeout)
        .build_with_admission(admission)?;

    let capture = capture_turn(factory, &prepared, &request.canaries)?;

    let mut transcript = ClaudeStreamTranscript::new(
        request.session_id.clone(),
        request.invocation_id.clone(),
        &cwd,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        request.gate_ids.clone(),
    )?;
    // The prompt travels via argv (`-p`), so the user frame is discarded; the
    // call only advances the transcript to await the system/init frame.
    let _ = transcript.user_message(&request.prompt)?;

    let mut events: Vec<AgentEvent> = Vec::new();
    for line in &capture.stdout_lines {
        if line.is_empty() {
            continue;
        }
        events.extend(transcript.ingest_line(line)?);
    }
    // A conforming turn must reach a terminal outcome.
    let _ = transcript.outcome()?;

    let events_blake3 = scan_events(&events, &request.canaries)?;
    let response_text = extract_response(&events);
    let native_session_id = events
        .iter()
        .find_map(|event| event.native_session_id.clone());
    let total_cost_micro_usd = extract_cost_micro_usd(&events);

    Ok(LiveTurnOutcome {
        response_text,
        native_session_id,
        total_cost_micro_usd,
        exit_code: capture.exit_code,
        wall_ms: capture.wall_ms,
        timed_out: capture.timed_out,
        stdout_blake3: artifact_digest(b"stdout", capture.stdout().as_bytes()),
        stderr_blake3: artifact_digest(b"stderr", capture.stderr.as_bytes()),
        events_blake3,
        events,
    })
}

fn extract_response(events: &[AgentEvent]) -> String {
    let mut text = String::new();
    for event in events {
        if event.kind != AgentEventKind::TurnDelta {
            continue;
        }
        if let Some(chunk) = event.payload.get("text").and_then(|value| value.as_str()) {
            text.push_str(chunk);
        }
    }
    text
}

fn extract_cost_micro_usd(events: &[AgentEvent]) -> Option<u64> {
    for event in events {
        if event.kind != AgentEventKind::UsageReported {
            continue;
        }
        if let Some(usd) = event
            .payload
            .get("total_cost_usd")
            .and_then(serde_json::Value::as_f64)
        {
            if usd.is_finite() && usd >= 0.0 {
                return Some((usd * 1_000_000.0).round() as u64);
            }
        }
    }
    None
}
