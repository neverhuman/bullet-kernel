//! Guarded live dispatch for Antigravity (`agy`). For the conformance ping the
//! installed CLI runs text-only (`--sandbox --mode plan --print-timeout 3m
//! -p=<prompt>`); the frozen structured `AgyHeadlessTranscript` is for real
//! work turns and is deliberately not used here. The caller-supplied (egress)
//! factory owns the process; this crate never spawns `agy` itself.

use bullet_harness_core::live::dispatch::artifact_digest;
use bullet_harness_core::{
    capture_turn, scan_events, ArgvBuilder, CommandFactory, EvaluatedAdmission, HarnessError,
    LiveTurnOutcome, LiveTurnRequest,
};

/// The frozen print-timeout the conformance turn uses.
pub const CONFORMANCE_PRINT_TIMEOUT: &str = "3m";

/// Dispatch one read-only Antigravity turn against a fully-cleared admission.
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
        .arg("--sandbox")
        .arg("--mode")
        .arg("plan")
        .arg("--print-timeout")
        .arg(CONFORMANCE_PRINT_TIMEOUT)
        .arg(format!("-p={}", request.prompt))
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
