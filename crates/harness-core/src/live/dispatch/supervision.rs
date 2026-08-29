//! Exact process-group ownership and bounded dispatch supervision.

use super::streams::{
    io_error, pipe_missing, raw_capture, stderr_reader, stdout_reader, InteractiveReader,
    InteractiveWriter,
};
use super::{InteractiveReaction, LineHandler, RawCapture, MAX_INTERACTIVE_LINES};
use crate::admission::CanarySecrets;
use crate::argv::PreparedInvocation;
use crate::error::HarnessError;
use crate::spawnrun::{kill_process_group, kill_process_group_members};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SIGNAL_NONE: u8 = 0;
const SIGNAL_CANCELLED: u8 = 1;
const SIGNAL_HEARTBEAT_LOST: u8 = 2;

/// Why one supervised dispatch stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchStop {
    /// The process leader exited; remaining group members were killed.
    Exited,
    /// The invocation wall bound expired.
    TimedOut,
    /// The controller requested cancellation.
    Cancelled,
    /// Durable-authority heartbeat was lost.
    HeartbeatLost,
}

/// Race-safe, first-writer-wins stop signal shared with the dispatch owner.
#[derive(Clone, Debug, Default)]
pub struct DispatchSignal {
    state: Arc<AtomicU8>,
}

impl DispatchSignal {
    /// A fresh signal with no stop requested.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request controller cancellation.
    pub fn cancel(&self) {
        self.request(SIGNAL_CANCELLED);
    }

    /// Record loss of the durable-authority heartbeat.
    pub fn heartbeat_lost(&self) {
        self.request(SIGNAL_HEARTBEAT_LOST);
    }

    /// Current requested stop, if any.
    #[must_use]
    pub fn requested(&self) -> Option<DispatchStop> {
        match self.state.load(Ordering::SeqCst) {
            SIGNAL_CANCELLED => Some(DispatchStop::Cancelled),
            SIGNAL_HEARTBEAT_LOST => Some(DispatchStop::HeartbeatLost),
            _ => None,
        }
    }

    fn request(&self, state: u8) {
        let _ = self
            .state
            .compare_exchange(SIGNAL_NONE, state, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// A command plus the exact process group dispatch owns and terminates.
pub struct SupervisedCommand {
    command: Command,
    group: ProcessGroup,
}

impl SupervisedCommand {
    /// Place the spawned child in a fresh group led by its own pid.
    #[must_use]
    pub fn child_process_group(command: Command) -> Self {
        Self {
            command,
            group: ProcessGroup::Child,
        }
    }

    /// Place the child into an existing process group owned by the caller.
    ///
    /// The external owner remains responsible for reaping that group's leader;
    /// this supervisor kills the complete group and reaps its own child.
    ///
    /// # Errors
    /// `ADMISSION_REFUSED` for zero or non-platform process-group values, and
    /// on platforms without Unix process groups.
    pub fn existing_process_group(
        command: Command,
        process_group: u32,
    ) -> Result<Self, HarnessError> {
        validate_existing_group(process_group)?;
        Ok(Self {
            command,
            group: ProcessGroup::Existing(process_group),
        })
    }
}

/// Fallible pre-spawn command construction and containment revalidation.
pub type FallibleCommandFactory<'a> =
    dyn Fn(&str, &[&str], &[(&str, &str)]) -> Result<SupervisedCommand, HarnessError> + 'a;

/// Signal-aware capture; absent only when stopped before spawn.
#[derive(Clone, Debug)]
pub struct DispatchCapture {
    /// Exact terminal reason.
    pub stop: DispatchStop,
    /// Captured process facts, absent only for a pre-spawn stop.
    pub capture: Option<RawCapture>,
}

#[derive(Clone, Copy, Debug)]
enum ProcessGroup {
    Child,
    Existing(u32),
}

struct GuardedChild {
    child: Child,
    group: u32,
    reaped: bool,
}

impl GuardedChild {
    fn spawn(
        mut prepared: SupervisedCommand,
        invocation: &PreparedInvocation,
        interactive: bool,
    ) -> Result<Self, HarnessError> {
        configure_process_group(&mut prepared.command, prepared.group)?;
        prepared
            .command
            .current_dir(&invocation.cwd)
            .stdin(if interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = prepared
            .command
            .spawn()
            .map_err(|error| HarnessError::Spawn {
                program: invocation.program.clone(),
                reason: error.to_string(),
            })?;
        let group = match prepared.group {
            ProcessGroup::Child => child.id(),
            ProcessGroup::Existing(group) => group,
        };
        Ok(Self {
            child,
            group,
            reaped: false,
        })
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, HarnessError> {
        self.child
            .try_wait()
            .map_err(|error| io_error("child wait", &error))
    }

    fn finish_exited(&mut self) {
        self.reaped = true;
        kill_process_group_members(self.group);
    }

    fn terminate(&mut self) {
        if self.reaped {
            kill_process_group_members(self.group);
            return;
        }
        kill_process_group(self.group);
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }

    fn wait_until_stop(
        &mut self,
        started: Instant,
        timeout: Duration,
        signal: &DispatchSignal,
    ) -> Result<(DispatchStop, Option<i32>), HarnessError> {
        loop {
            if let Some(status) = self.try_wait()? {
                self.finish_exited();
                return Ok((DispatchStop::Exited, status.code()));
            }
            if let Some(stop) = signal.requested() {
                self.terminate();
                return Ok((stop, None));
            }
            if started.elapsed() >= timeout {
                self.terminate();
                return Ok((DispatchStop::TimedOut, None));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Fallible, signal-aware bounded capture.
///
/// # Errors
/// Factory, spawn, pipe, reader, or canary failures. Every post-spawn error
/// first kills the exact process group and reaps the direct child.
pub fn capture_turn_supervised(
    factory: &FallibleCommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
    signal: &DispatchSignal,
) -> Result<DispatchCapture, HarnessError> {
    let Some(prepared) = prepare(factory, invocation, signal)? else {
        return Ok(pre_spawn_stop(signal));
    };
    let started = Instant::now();
    let mut guarded = GuardedChild::spawn(prepared, invocation, false)?;
    let stdout = guarded
        .child
        .stdout
        .take()
        .ok_or_else(|| pipe_missing("child stdout"))?;
    let stderr = guarded
        .child
        .stderr
        .take()
        .ok_or_else(|| pipe_missing("child stderr"))?;
    let stdout = stdout_reader(stdout);
    let stderr = stderr_reader(stderr);
    let (stop, exit_code) = guarded.wait_until_stop(started, invocation.timeout, signal)?;
    let stdout_lines = stdout.finish("captured stdout")?;
    let stderr = stderr.finish("captured stderr")?;
    for line in &stdout_lines {
        canaries.inspect("stdout", line.as_bytes())?;
    }
    canaries.inspect("stderr", stderr.as_bytes())?;
    Ok(DispatchCapture {
        stop,
        capture: Some(raw_capture(
            stdout_lines,
            stderr,
            exit_code,
            started,
            stop == DispatchStop::TimedOut,
        )),
    })
}

/// Fallible, signal-aware bounded interactive exchange.
///
/// # Errors
/// Factory, spawn, pipe, reader, canary, writer, or handler failures. Every
/// post-spawn error first kills the exact process group and reaps the child.
pub fn run_interactive_supervised(
    factory: &FallibleCommandFactory<'_>,
    invocation: &PreparedInvocation,
    canaries: &CanarySecrets,
    signal: &DispatchSignal,
    initial: Vec<String>,
    on_line: &mut LineHandler<'_>,
) -> Result<DispatchCapture, HarnessError> {
    let Some(prepared) = prepare(factory, invocation, signal)? else {
        return Ok(pre_spawn_stop(signal));
    };
    let started = Instant::now();
    let mut guarded = GuardedChild::spawn(prepared, invocation, true)?;
    let stdin = guarded
        .child
        .stdin
        .take()
        .ok_or_else(|| pipe_missing("child stdin"))?;
    let stdout = guarded
        .child
        .stdout
        .take()
        .ok_or_else(|| pipe_missing("child stdout"))?;
    let stderr = guarded
        .child
        .stderr
        .take()
        .ok_or_else(|| pipe_missing("child stderr"))?;
    let reader = InteractiveReader::spawn(stdout);
    let stderr = stderr_reader(stderr);
    let mut writer = InteractiveWriter::spawn(stdin);
    let mut lines = Vec::new();
    let mut interaction_error = writer.queue_frames(&initial).err();
    let mut requested_stop = None;
    let mut observed_exit = None;
    let mut exit_drain_deadline = None;
    let mut protocol_done = false;

    while interaction_error.is_none() && requested_stop.is_none() {
        if let Err(error) = writer.check() {
            interaction_error = Some(error);
            continue;
        }
        if observed_exit.is_none() {
            if let Some(status) = guarded.try_wait()? {
                guarded.finish_exited();
                observed_exit = Some(status.code());
                exit_drain_deadline = Some(Instant::now() + EXIT_DRAIN_TIMEOUT);
                writer.close();
            }
        }
        if observed_exit.is_some() && protocol_done {
            break;
        }
        if observed_exit.is_none() {
            if let Some(stop) = signal.requested() {
                requested_stop = Some(stop);
                continue;
            }
            if started.elapsed() >= invocation.timeout {
                requested_stop = Some(DispatchStop::TimedOut);
                continue;
            }
        } else if exit_drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            interaction_error = Some(HarnessError::Io {
                context: "interactive stdout".to_string(),
                reason: "reader did not drain after process-tree teardown".to_string(),
            });
            continue;
        }
        if protocol_done {
            thread::sleep(POLL_INTERVAL);
            continue;
        }
        if lines.len() >= MAX_INTERACTIVE_LINES {
            interaction_error = Some(HarnessError::Protocol {
                provider: "interactive".to_string(),
                reason: "interactive line limit exceeded".to_string(),
            });
            continue;
        }
        match reader.lines.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(Some(line))) => {
                if let Err(error) = canaries.inspect("stdout", line.as_bytes()) {
                    interaction_error = Some(error);
                    continue;
                }
                lines.push(line.clone());
                match on_line(&line) {
                    Ok(InteractiveReaction { send, done }) => {
                        if let Err(error) = writer.queue_frames(&send) {
                            interaction_error = Some(error);
                        }
                        protocol_done = done;
                        if protocol_done {
                            writer.close();
                        }
                    }
                    Err(error) => interaction_error = Some(error),
                }
            }
            Ok(Ok(None)) => {
                protocol_done = true;
                writer.close();
            }
            Ok(Err(error)) => interaction_error = Some(io_error("interactive stdout", &error)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                interaction_error = Some(HarnessError::Io {
                    context: "interactive stdout".to_string(),
                    reason: "reader terminated without an EOF frame".to_string(),
                });
            }
        }
    }

    writer.close();
    let (stop, exit_code) = if let Some(exit_code) = observed_exit {
        (DispatchStop::Exited, exit_code)
    } else if let Some(stop) = requested_stop {
        guarded.terminate();
        (stop, None)
    } else {
        guarded.terminate();
        (DispatchStop::Exited, None)
    };
    let writer_result = writer.finish();
    let reader_result = reader.finish();
    let stderr_result = stderr.finish("interactive stderr");
    if let Some(error) = interaction_error {
        return Err(error);
    }
    if stop == DispatchStop::Exited {
        writer_result?;
    }
    reader_result?;
    let stderr = stderr_result?;
    canaries.inspect("stderr", stderr.as_bytes())?;
    Ok(DispatchCapture {
        stop,
        capture: Some(raw_capture(
            lines,
            stderr,
            exit_code,
            started,
            stop == DispatchStop::TimedOut,
        )),
    })
}

fn prepare(
    factory: &FallibleCommandFactory<'_>,
    invocation: &PreparedInvocation,
    signal: &DispatchSignal,
) -> Result<Option<SupervisedCommand>, HarnessError> {
    if signal.requested().is_some() {
        return Ok(None);
    }
    let args: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = invocation
        .env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let prepared = factory(&invocation.program, &args, &env)?;
    if signal.requested().is_some() {
        return Ok(None);
    }
    Ok(Some(prepared))
}

fn pre_spawn_stop(signal: &DispatchSignal) -> DispatchCapture {
    DispatchCapture {
        stop: signal.requested().unwrap_or(DispatchStop::Cancelled),
        capture: None,
    }
}

fn validate_existing_group(process_group: u32) -> Result<(), HarnessError> {
    if process_group == 0 || i32::try_from(process_group).is_err() {
        return Err(HarnessError::AdmissionRefused {
            reason: "process group must be a positive platform pid".to_string(),
        });
    }
    #[cfg(not(unix))]
    return Err(HarnessError::AdmissionRefused {
        reason: "existing process groups require Unix".to_string(),
    });
    #[cfg(unix)]
    Ok(())
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command, group: ProcessGroup) -> Result<(), HarnessError> {
    use std::os::unix::process::CommandExt;
    let process_group = match group {
        ProcessGroup::Child => 0,
        ProcessGroup::Existing(group) => {
            i32::try_from(group).map_err(|_| HarnessError::AdmissionRefused {
                reason: "process group exceeds platform pid range".to_string(),
            })?
        }
    };
    command.process_group(process_group);
    Ok(())
}

#[cfg(not(unix))]
fn configure_process_group(
    _command: &mut Command,
    group: ProcessGroup,
) -> Result<(), HarnessError> {
    match group {
        ProcessGroup::Child => Ok(()),
        ProcessGroup::Existing(_) => Err(HarnessError::AdmissionRefused {
            reason: "existing process groups require Unix".to_string(),
        }),
    }
}
