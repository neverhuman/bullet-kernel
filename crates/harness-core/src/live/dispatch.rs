//! Generic guarded dispatch: run a validated invocation through a
//! caller-supplied `std::process::Command` factory (so the egress sandbox can
//! wrap it), capture bounded output under a wall-clock kill, and scan every
//! captured surface for canary exposure. No provider-specific parsing lives
//! here; adapters own that.

use crate::admission::CanarySecrets;
use crate::argv::PreparedInvocation;
use crate::error::HarnessError;
use crate::event::AgentEvent;
use crate::spawnrun::kill_process_group;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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

const MAX_INTERACTIVE_LINES: usize = 1024;

/// Factory that turns a program, argv, and environment into a ready command.
/// The egress sandbox's `PreparedSandbox::command` matches this shape; a plain
/// factory is used in the non-namespace workspace test run.
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

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Run one validated invocation through `factory`, capture bounded output
/// under the invocation's wall-clock bound (killing the process group on
/// timeout), and refuse if any captured surface exposes a canary.
///
/// # Errors
///
/// `SPAWN_FAILED` when the process cannot start, `IO_FAILED` when its stdio
/// pipes are unavailable, or `SECRET_CANARY_EXPOSURE` when stdout or stderr
/// carries a host canary.
pub fn capture_turn(
    factory: &CommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
) -> Result<RawCapture, HarnessError> {
    let args: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = invocation
        .env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut command = factory(&invocation.program, &args, &env);
    command
        .current_dir(&invocation.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| HarnessError::Spawn {
        program: invocation.program.clone(),
        reason: error.to_string(),
    })?;
    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err(pipe_missing("child stdout"));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        return Err(pipe_missing("child stderr"));
    };
    let out_handle = thread::spawn(move || read_lines(stdout));
    let err_handle = thread::spawn(move || read_all(stderr));

    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                kill_process_group(pid);
                let _ = child.wait();
                return Err(io("child wait", &error));
            }
        }
        if started.elapsed() >= invocation.timeout {
            timed_out = true;
            kill_process_group(pid);
            let _ = child.wait();
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let exit_code = child
        .try_wait()
        .ok()
        .flatten()
        .and_then(|status| status.code());
    let stdout_lines = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    for line in &stdout_lines {
        canaries.inspect("stdout", line.as_bytes())?;
    }
    canaries.inspect("stderr", stderr.as_bytes())?;

    Ok(RawCapture {
        stdout_lines,
        stderr,
        exit_code,
        wall_ms,
        timed_out,
    })
}

/// Run one validated invocation as a bidirectional stdio exchange: write the
/// `initial` frames, then for each inbound stdout line scan it for canaries,
/// hand it to `on_line`, and write the frames it returns, until the handler
/// reports completion, the child exits, or the wall-clock bound fires.
///
/// # Errors
///
/// `SPAWN_FAILED` / `IO_FAILED` on process failure, `SECRET_CANARY_EXPOSURE`
/// on a leaked canary, or any typed error the handler returns.
pub fn run_interactive(
    factory: &CommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
    initial: Vec<String>,
    on_line: &mut LineHandler<'_>,
) -> Result<RawCapture, HarnessError> {
    let args: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = invocation
        .env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut command = factory(&invocation.program, &args, &env);
    command
        .current_dir(&invocation.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| HarnessError::Spawn {
        program: invocation.program.clone(),
        reason: error.to_string(),
    })?;
    let pid = child.id();
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        kill_process_group(pid);
        let _ = child.wait();
        return Err(pipe_missing("child stdio"));
    };
    let err_handle = thread::spawn(move || read_all(stderr));

    let write_frames = |stdin: &mut std::process::ChildStdin, frames: &[String]| {
        for frame in frames {
            let _ = stdin.write_all(frame.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
        let _ = stdin.flush();
    };
    write_frames(&mut stdin, &initial);

    let mut reader = BufReader::new(stdout);
    let mut stdout_lines = Vec::new();
    let mut timed_out = false;
    let mut line = String::new();
    loop {
        if started.elapsed() >= invocation.timeout {
            timed_out = true;
            kill_process_group(pid);
            break;
        }
        if stdout_lines.len() >= MAX_INTERACTIVE_LINES {
            kill_process_group(pid);
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
        canaries.inspect("stdout", trimmed.as_bytes())?;
        stdout_lines.push(trimmed.clone());
        let reaction = on_line(&trimmed)?;
        write_frames(&mut stdin, &reaction.send);
        if reaction.done {
            break;
        }
    }
    drop(stdin);
    let exit_code = wait_bounded(&mut child, pid, started, invocation.timeout, &mut timed_out);
    let stderr = err_handle.join().unwrap_or_default();
    canaries.inspect("stderr", stderr.as_bytes())?;
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(RawCapture {
        stdout_lines,
        stderr,
        exit_code,
        wall_ms,
        timed_out,
    })
}

fn wait_bounded(
    child: &mut std::process::Child,
    pid: u32,
    started: Instant,
    timeout: Duration,
    timed_out: &mut bool,
) -> Option<i32> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => {}
            Err(_) => return None,
        }
        if started.elapsed() >= timeout {
            *timed_out = true;
            kill_process_group(pid);
            let _ = child.wait();
            return None;
        }
        thread::sleep(POLL_INTERVAL);
    }
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
/// `SECRET_CANARY_EXPOSURE` on the `event_log` surface, or `ADMISSION_REFUSED`
/// if the events cannot be serialized.
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

fn read_lines<R: Read>(reader: R) -> Vec<String> {
    let mut lines = Vec::new();
    let mut buffered = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buffered.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => lines.push(line.trim_end_matches(['\n', '\r']).to_string()),
        }
    }
    lines
}

fn read_all<R: Read>(mut reader: R) -> String {
    let mut text = String::new();
    let _ = reader.read_to_string(&mut text);
    text
}

fn pipe_missing(context: &str) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: "pipe missing".to_string(),
    }
}

fn io(context: &str, error: &std::io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}
