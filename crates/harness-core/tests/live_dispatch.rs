#![cfg(unix)]

use bullet_harness_core::live::{
    capture_turn_supervised, run_interactive_supervised, DispatchSignal, DispatchStop,
    FallibleCommandFactory, InteractiveReaction, SupervisedCommand,
};
use bullet_harness_core::{ArgvBuilder, CanarySecrets, HarnessError, PreparedInvocation};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CANARY: &str = "dispatch-supervision-canary-0123456789";
const LONG_WAIT: &str = "300";

fn canaries() -> CanarySecrets {
    CanarySecrets::new(vec![CANARY.to_string()]).unwrap()
}

fn invocation(cwd: &Path, script: &str, timeout: Duration, args: &[&str]) -> PreparedInvocation {
    ArgvBuilder::new("/bin/sh", cwd)
        .args(["-c", script, "live-dispatch-test"])
        .args(args.iter().copied())
        .timeout(timeout)
        .build()
        .unwrap()
}

fn child_group_factory(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> Result<SupervisedCommand, HarnessError> {
    let mut command = Command::new(program);
    command.args(args).env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    Ok(SupervisedCommand::child_process_group(command))
}

fn read_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "pid file was not populated");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let state = stat
        .rsplit_once(") ")
        .and_then(|(_, suffix)| suffix.chars().next());
    !matches!(state, None | Some('Z') | Some('X'))
}

fn assert_process_dead(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while process_is_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process_is_alive(pid), "process {pid} survived teardown");
}

fn descendant_script(tail: &str) -> String {
    format!(
        "sleep {LONG_WAIT} & descendant=$!; printf '%s\\n' \"$descendant\" > \"$1\"; printf 'ready\\n'; {tail}"
    )
}

#[test]
fn pre_spawn_signals_do_not_invoke_the_factory() {
    for (signal, expected) in [
        (
            {
                let signal = DispatchSignal::new();
                signal.cancel();
                signal
            },
            DispatchStop::Cancelled,
        ),
        (
            {
                let signal = DispatchSignal::new();
                signal.heartbeat_lost();
                signal
            },
            DispatchStop::HeartbeatLost,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let invocation = invocation(directory.path(), "exit 0", Duration::from_secs(1), &[]);
        let invoked = AtomicBool::new(false);
        let factory = |_program: &str, _args: &[&str], _env: &[(&str, &str)]| {
            invoked.store(true, Ordering::SeqCst);
            Err(HarnessError::AdmissionRefused {
                reason: "must not run".to_string(),
            })
        };
        let outcome = capture_turn_supervised(&factory, &invocation, &canaries(), &signal).unwrap();
        assert_eq!(outcome.stop, expected);
        assert!(outcome.capture.is_none());
        assert!(!invoked.load(Ordering::SeqCst));
    }
}

#[test]
fn fallible_factory_refuses_before_any_child_exists() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("spawned");
    let script = format!("touch {}", marker.display());
    let invocation = invocation(directory.path(), &script, Duration::from_secs(1), &[]);
    let factory = |_program: &str, _args: &[&str], _env: &[(&str, &str)]| {
        Err(HarnessError::AdmissionRefused {
            reason: "filesystem identity changed".to_string(),
        })
    };

    let error = capture_turn_supervised(&factory, &invocation, &canaries(), &DispatchSignal::new())
        .unwrap_err();
    assert_eq!(error.reason_code(), "ADMISSION_REFUSED");
    assert!(!marker.exists());
}

#[test]
fn normal_exit_kills_descendants_and_drains_copied_pipes() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("exit 0");
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_secs(5),
        &[pid_file.to_str().unwrap()],
    );
    let started = Instant::now();

    let outcome = capture_turn_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
    )
    .unwrap();
    let descendant = read_pid(&pid_file);
    assert_eq!(outcome.stop, DispatchStop::Exited);
    assert_eq!(outcome.capture.unwrap().stdout_lines, ["ready"]);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_process_dead(descendant);
}

#[test]
fn timeout_kills_the_complete_child_group() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("wait");
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_millis(150),
        &[pid_file.to_str().unwrap()],
    );

    let outcome = capture_turn_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
    )
    .unwrap();
    let descendant = read_pid(&pid_file);
    assert_eq!(outcome.stop, DispatchStop::TimedOut);
    let capture = outcome.capture.unwrap();
    assert!(capture.timed_out);
    assert_eq!(capture.exit_code, None);
    assert_process_dead(descendant);
}

fn assert_external_stop(heartbeat: bool) {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("wait");
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_secs(30),
        &[pid_file.to_str().unwrap()],
    );
    let signal = DispatchSignal::new();
    let run_signal = signal.clone();
    let handle = std::thread::spawn(move || {
        capture_turn_supervised(&child_group_factory, &invocation, &canaries(), &run_signal)
    });
    let descendant = read_pid(&pid_file);
    if heartbeat {
        signal.heartbeat_lost();
    } else {
        signal.cancel();
    }
    let outcome = handle.join().unwrap().unwrap();
    assert_eq!(
        outcome.stop,
        if heartbeat {
            DispatchStop::HeartbeatLost
        } else {
            DispatchStop::Cancelled
        }
    );
    assert!(!outcome.capture.unwrap().timed_out);
    assert_process_dead(descendant);
}

#[test]
fn cancellation_kills_the_complete_child_group() {
    assert_external_stop(false);
}

#[test]
fn heartbeat_loss_kills_the_complete_child_group() {
    assert_external_stop(true);
}

#[test]
fn canary_failure_happens_after_process_tree_teardown() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script(&format!("printf '%s\\n' '{CANARY}'; wait"));
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_millis(150),
        &[pid_file.to_str().unwrap()],
    );

    let error = capture_turn_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
    )
    .unwrap_err();
    let descendant = read_pid(&pid_file);
    assert_eq!(error.reason_code(), "SECRET_CANARY_EXPOSURE");
    assert_process_dead(descendant);
}

#[test]
fn interactive_handler_failure_tears_down_before_returning() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("wait");
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_secs(5),
        &[pid_file.to_str().unwrap()],
    );
    let mut handler = |_line: &str| {
        Err(HarnessError::Protocol {
            provider: "fake-local".to_string(),
            reason: "fixture parse refusal".to_string(),
        })
    };

    let error = run_interactive_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
        Vec::new(),
        &mut handler,
    )
    .unwrap_err();
    let descendant = read_pid(&pid_file);
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert_process_dead(descendant);
}

#[test]
fn quick_interactive_exit_drains_every_terminal_frame() {
    let directory = tempfile::tempdir().unwrap();
    let invocation = invocation(
        directory.path(),
        "printf 'one\\ntwo\\ndone\\n'; exit 0",
        Duration::from_secs(3),
        &[],
    );
    let mut seen = Vec::new();
    let mut handler = |line: &str| {
        seen.push(line.to_string());
        Ok(InteractiveReaction {
            send: Vec::new(),
            done: line == "done",
        })
    };

    let outcome = run_interactive_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
        Vec::new(),
        &mut handler,
    )
    .unwrap();
    assert_eq!(outcome.stop, DispatchStop::Exited);
    assert_eq!(seen, ["one", "two", "done"]);
    assert_eq!(
        outcome.capture.unwrap().stdout_lines,
        ["one", "two", "done"]
    );
}

fn assert_blocked_writer_stop(cancel: bool) {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("wait");
    let timeout = if cancel {
        Duration::from_secs(30)
    } else {
        Duration::from_millis(150)
    };
    let invocation = invocation(
        directory.path(),
        &script,
        timeout,
        &[pid_file.to_str().unwrap()],
    );
    let signal = DispatchSignal::new();
    let run_signal = signal.clone();
    let initial = vec!["x".repeat(1024 * 1024)];
    let started = Instant::now();
    let handle = std::thread::spawn(move || {
        let mut handler = |_line: &str| {
            Ok(InteractiveReaction {
                send: Vec::new(),
                done: false,
            })
        };
        run_interactive_supervised(
            &child_group_factory,
            &invocation,
            &canaries(),
            &run_signal,
            initial,
            &mut handler,
        )
    });
    let descendant = read_pid(&pid_file);
    if cancel {
        signal.cancel();
    }
    let outcome = handle.join().unwrap().unwrap();
    assert_eq!(
        outcome.stop,
        if cancel {
            DispatchStop::Cancelled
        } else {
            DispatchStop::TimedOut
        }
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_process_dead(descendant);
}

#[test]
fn nonreading_child_cannot_block_timeout_teardown() {
    assert_blocked_writer_stop(false);
}

#[test]
fn nonreading_child_cannot_block_cancel_teardown() {
    assert_blocked_writer_stop(true);
}

#[test]
fn oversized_handler_batch_refuses_and_kills_descendants() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = descendant_script("wait");
    let invocation = invocation(
        directory.path(),
        &script,
        Duration::from_secs(3),
        &[pid_file.to_str().unwrap()],
    );
    let mut handler = |_line: &str| {
        Ok(InteractiveReaction {
            send: vec!["frame".to_string(); 65],
            done: false,
        })
    };

    let error = run_interactive_supervised(
        &child_group_factory,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
        Vec::new(),
        &mut handler,
    )
    .unwrap_err();
    let descendant = read_pid(&pid_file);
    assert_eq!(error.reason_code(), "IO_FAILED");
    assert_process_dead(descendant);
}

#[test]
fn explicit_existing_process_group_is_the_kill_target() {
    let directory = tempfile::tempdir().unwrap();
    let mut holder = Command::new("/bin/sh")
        .args(["-c", "sleep 300"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let process_group = holder.id();
    let factory = move |program: &str, args: &[&str], env: &[(&str, &str)]| {
        let mut command = Command::new(program);
        command.args(args).env_clear();
        for (key, value) in env {
            command.env(key, value);
        }
        SupervisedCommand::existing_process_group(command, process_group)
    };
    let invocation = invocation(
        directory.path(),
        "printf 'joined\\n'",
        Duration::from_secs(3),
        &[],
    );

    let outcome = capture_turn_supervised(
        &factory as &FallibleCommandFactory<'_>,
        &invocation,
        &canaries(),
        &DispatchSignal::new(),
    )
    .unwrap();
    assert_eq!(outcome.capture.unwrap().stdout_lines, ["joined"]);
    let status = holder.wait().unwrap();
    assert!(!status.success(), "owned process group was not terminated");
}

#[test]
fn zero_existing_process_group_is_refused() {
    let error = SupervisedCommand::existing_process_group(Command::new("/bin/true"), 0)
        .err()
        .unwrap();
    assert_eq!(error.reason_code(), "ADMISSION_REFUSED");
}
