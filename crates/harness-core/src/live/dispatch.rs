//! Generic guarded dispatch: run a validated invocation through a
//! caller-supplied command factory, capture bounded output, and scan every
//! captured surface for canary exposure. Provider-specific parsing stays in
//! adapters.

mod streams;
mod supervision;

pub use supervision::{
    capture_turn_supervised, run_interactive_supervised, DispatchCapture, DispatchSignal,
    DispatchStop, FallibleCommandFactory, SupervisedCommand,
};

use crate::admission::CanarySecrets;
use crate::argv::PreparedInvocation;
use crate::error::HarnessError;
use crate::event::AgentEvent;
use std::process::Command;

/// Frames to write in response to one inbound line, plus whether the exchange
/// is complete.
#[derive(Clone, Debug, Default)]
pub struct InteractiveReaction {
    /// Newline-delimited frames to write to the child's stdin.
    pub send: Vec<String>,
    /// True once the terminal frame has been observed.
    pub done: bool,
}

/// Reactive per-line handler for a bidirectional stdio protocol.
pub type LineHandler<'a> = dyn FnMut(&str) -> Result<InteractiveReaction, HarnessError> + 'a;

/// Maximum stdout frames admitted by one guarded interactive transport.
pub const MAX_INTERACTIVE_LINES: usize = 1024;

/// Backwards-compatible infallible command factory.
///
/// New containment integrations should use [`FallibleCommandFactory`] so
/// executable identity and sandbox planning can refuse before spawn.
pub type CommandFactory<'a> = dyn Fn(&str, &[&str], &[(&str, &str)]) -> Command + 'a;

/// Raw bounded capture from one dispatched process.
#[derive(Clone, Debug)]
pub struct RawCapture {
    /// Stdout lines in arrival order (partial on timeout).
    pub stdout_lines: Vec<String>,
    /// Complete captured stderr.
    pub stderr: String,
    /// Exit code when the process finished.
    pub exit_code: Option<i32>,
    /// Observed wall time in milliseconds.
    pub wall_ms: u64,
    /// True when the wall-clock bound fired.
    pub timed_out: bool,
}

impl RawCapture {
    /// The complete stdout as one string.
    #[must_use]
    pub fn stdout(&self) -> String {
        self.stdout_lines.join("\n")
    }
}

/// The normalized outcome of one dispatched provider turn.
#[derive(Clone, Debug)]
pub struct LiveTurnOutcome {
    /// Normalized envelopes for the invocation.
    pub events: Vec<AgentEvent>,
    /// The provider's response text.
    pub response_text: String,
    /// Provider-native session id, when reported.
    pub native_session_id: Option<String>,
    /// Reported spend in micro-USD, when the provider reported one.
    pub total_cost_micro_usd: Option<u64>,
    /// Process exit code, when it finished.
    pub exit_code: Option<i32>,
    /// Observed wall time in milliseconds.
    pub wall_ms: u64,
    /// True when the wall-clock bound fired.
    pub timed_out: bool,
    /// Digest of the complete captured stdout.
    pub stdout_blake3: String,
    /// Digest of the complete captured stderr.
    pub stderr_blake3: String,
    /// Digest of the normalized event log.
    pub events_blake3: String,
}

/// Run one validated invocation through a legacy infallible factory.
///
/// The child is placed into a fresh process group and the complete group is
/// killed and reaped on every terminal path.
///
/// # Errors
///
/// `SPAWN_FAILED`, `IO_FAILED`, or `SECRET_CANARY_EXPOSURE` when supervision,
/// bounded capture, or canary inspection fails.
pub fn capture_turn(
    factory: &CommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
) -> Result<RawCapture, HarnessError> {
    let fallible = |program: &str, args: &[&str], env: &[(&str, &str)]| {
        Ok(SupervisedCommand::child_process_group(factory(
            program, args, env,
        )))
    };
    complete_legacy_capture(capture_turn_supervised(
        &fallible,
        invocation,
        canaries,
        &DispatchSignal::new(),
    )?)
}

/// Run one bidirectional exchange through a legacy infallible factory.
///
/// # Errors
///
/// Supervision, bounded I/O, canary, or handler failures.
pub fn run_interactive(
    factory: &CommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
    initial: Vec<String>,
    on_line: &mut LineHandler<'_>,
) -> Result<RawCapture, HarnessError> {
    let fallible = |program: &str, args: &[&str], env: &[(&str, &str)]| {
        Ok(SupervisedCommand::child_process_group(factory(
            program, args, env,
        )))
    };
    complete_legacy_capture(run_interactive_supervised(
        &fallible,
        invocation,
        canaries,
        &DispatchSignal::new(),
        initial,
        on_line,
    )?)
}

fn complete_legacy_capture(outcome: DispatchCapture) -> Result<RawCapture, HarnessError> {
    outcome.capture.ok_or_else(|| HarnessError::Io {
        context: "dispatch supervision".to_string(),
        reason: "legacy dispatch stopped before spawn".to_string(),
    })
}

/// Domain-separated digest of one captured artifact.
#[must_use]
pub fn artifact_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bullet-live-conformance-artifact-v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// Scan already-normalized events for canary exposure.
///
/// # Errors
///
/// `SECRET_CANARY_EXPOSURE` on the `event_log` surface, or
/// `ADMISSION_REFUSED` if the events cannot be serialized.
pub fn scan_events(
    events: &[AgentEvent],
    canaries: &CanarySecrets,
) -> Result<String, HarnessError> {
    let bytes = serde_json::to_vec(events).map_err(|error| HarnessError::AdmissionRefused {
        reason: format!("event serialization failed: {error}"),
    })?;
    canaries.inspect("event_log", &bytes)?;
    Ok(artifact_digest(b"events", &bytes))
}
