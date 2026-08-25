//! Guarded live dispatch for Cursor Agent. The conformance ping uses the
//! documented headless surface (`cursor-agent -p <prompt> --workspace <dir>
//! --mode plan --output-format stream-json --trust`) and reads the response
//! text; the frozen ACP `CursorAcpTranscript` governs real structured turns
//! and is deliberately not driven here. The caller-supplied (egress) factory
//! owns the process; this crate never spawns `cursor-agent` itself. This path
//! runs only under an operator-ratified live-admission policy.

use bullet_harness_core::live::dispatch::artifact_digest;
use bullet_harness_core::{
    capture_turn, scan_events, ArgvBuilder, CommandFactory, EvaluatedAdmission, HarnessError,
    LiveTurnOutcome, LiveTurnRequest,
};

/// Runtime version recorded for the frozen ACP admission subject.
pub const CURSOR_OBSERVED_RUNTIME_VERSION: &str = "0.0.0";

/// Dispatch one read-only Cursor turn against a fully-cleared admission.
///
/// # Errors
///
/// `PROVIDER_ADMISSION_BLOCKED` when a blocker remains, `SPAWN_FAILED` /
/// `IO_FAILED` on process failure, or `SECRET_CANARY_EXPOSURE` on a leaked
/// canary.
pub fn dispatch_live_turn(
    admission: &EvaluatedAdmission,
    factory: &CommandFactory<'_>,
    request: &LiveTurnRequest,
) -> Result<LiveTurnOutcome, HarnessError> {
    let cwd = request.workdir.to_string_lossy().into_owned();
    let prepared = ArgvBuilder::new(admission.executable().to_string_lossy().into_owned(), &cwd)
        .arg("-p")
        .arg(&request.prompt)
        .arg("--workspace")
        .arg(&cwd)
        .arg("--mode")
        .arg("plan")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--trust")
        .timeout(request.wall_timeout)
        .build_with_admission(admission)?;

    let capture = capture_turn(factory, &prepared, &request.canaries)?;
    let events = Vec::new();
    let events_blake3 = scan_events(&events, &request.canaries)?;

    Ok(LiveTurnOutcome {
        response_text: capture.stdout(),
        native_session_id: None,
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
