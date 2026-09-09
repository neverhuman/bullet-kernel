//! Spawn the independent verifier process on the candidate subject and
//! trust only its typed stdout record. The binary is resolved like
//! bullet-gitd: env override, then the build sibling, then cargo.
use bullet_verifier_core::{VerifierEvidence, VerifierRequest};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Environment override naming the verifier binary.
pub const VERIFIER_BIN_ENV: &str = "BULLET_VERIFIER_BIN";
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_VERIFIER_STDOUT_BYTES: usize = 64 * 1024;
const MAX_VERIFIER_STDERR_BYTES: usize = 16 * 1024;
/// Resolve the verifier binary: env override first, then the sibling of the
/// running executable (both live in `target/debug` during development).
#[must_use]
pub fn verifier_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(VERIFIER_BIN_ENV) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let sibling = std::env::current_exe()
        .ok()?
        .parent()?
        .join("bullet-verifier");
    sibling.is_file().then_some(sibling)
}

fn command_for() -> tokio::process::Command {
    let mut command = match verifier_binary() {
        Some(path) => {
            let mut cmd = tokio::process::Command::new(path);
            cmd.arg("--stdin");
            cmd
        }
        None => {
            // Inside the workspace the binary can be built and run on demand.
            let mut cmd = tokio::process::Command::new("cargo");
            cmd.args(["run", "-q", "-p", "bullet-verifier", "--", "--stdin"]);
            cmd
        }
    };
    command.process_group(0);
    command
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    limit: usize,
    stream: &str,
) -> Result<Vec<u8>, String> {
    let byte_limit = u64::try_from(limit + 1).expect("output limit fits u64");
    let mut raw = Vec::with_capacity(limit.min(8 * 1024));
    reader
        .take(byte_limit)
        .read_to_end(&mut raw)
        .await
        .map_err(|err| format!("VERIFIER_{stream}_READ: {err}"))?;
    if raw.len() > limit {
        return Err(format!(
            "VERIFIER_{stream}_OVERSIZED: exceeds {limit} bytes"
        ));
    }
    Ok(raw)
}

fn process_id(raw: u32) -> Result<rustix::process::Pid, String> {
    let raw = i32::try_from(raw).map_err(|_| "VERIFIER_CONTAINMENT: pid overflow".to_string())?;
    rustix::process::Pid::from_raw(raw).ok_or_else(|| "VERIFIER_CONTAINMENT: zero pid".to_string())
}

fn enable_child_subreaper() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let own = process_id(std::process::id())?;
        rustix::process::set_child_subreaper(Some(own))
            .map_err(|error| format!("VERIFIER_CONTAINMENT: enable subreaper: {error}"))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

fn kill_process_group_members(process_group: Option<u32>) -> Result<(), String> {
    let Some(process_group) = process_group else {
        return Ok(());
    };
    let process_group = process_id(process_group)?;
    match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
        Err(error) => Err(format!("VERIFIER_CONTAINMENT: kill process group: {error}")),
    }
}

async fn reap_process_group_members(process_group: Option<u32>) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let Some(process_group) = process_group else {
            return Ok(());
        };
        let process_group = process_id(process_group)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match rustix::process::waitpgid(process_group, rustix::process::WaitOptions::NOHANG) {
                Ok(Some(_)) => {}
                Ok(None) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(None) => {
                    return Err("VERIFIER_CONTAINMENT: process-group reap timed out".into());
                }
                Err(error) if error == rustix::io::Errno::CHILD => return Ok(()),
                Err(error) => {
                    return Err(format!("VERIFIER_CONTAINMENT: reap process group: {error}"));
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

async fn kill_and_reap(
    child: &mut tokio::process::Child,
    process_group: Option<u32>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = kill_process_group_members(process_group) {
        errors.push(error);
    }
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(error) = child.start_kill() {
                errors.push(format!("VERIFIER_CONTAINMENT: kill direct child: {error}"));
            }
            match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    errors.push(format!("VERIFIER_CONTAINMENT: wait direct child: {error}"));
                }
                Err(_) => errors.push("VERIFIER_CONTAINMENT: direct-child reap timed out".into()),
            }
        }
        Err(error) => {
            errors.push(format!(
                "VERIFIER_CONTAINMENT: inspect direct child: {error}"
            ));
            if let Err(error) = child.start_kill() {
                errors.push(format!("VERIFIER_CONTAINMENT: kill direct child: {error}"));
            }
            match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    errors.push(format!("VERIFIER_CONTAINMENT: wait direct child: {error}"));
                }
                Err(_) => errors.push("VERIFIER_CONTAINMENT: direct-child reap timed out".into()),
            }
        }
    }
    if let Err(error) = reap_process_group_members(process_group).await {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn write_request(child: &mut tokio::process::Child, payload: &[u8]) -> Result<(), String> {
    let result = async {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "VERIFIER_SPAWN: stdin pipe missing".to_string())?;
        stdin
            .write_all(payload)
            .await
            .map_err(|err| format!("VERIFIER_WRITE: {err}"))?;
        drop(stdin);
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let process_group = child.id();
        return match kill_and_reap(child, process_group).await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; {cleanup}")),
        };
    }
    Ok(())
}

async fn capture_child(
    child: &mut tokio::process::Child,
    budget: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), String> {
    let process_group = child.id();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let error = "VERIFIER_SPAWN: stdout pipe missing";
            return match kill_and_reap(child, process_group).await {
                Ok(()) => Err(error.into()),
                Err(cleanup) => Err(format!("{error}; {cleanup}")),
            };
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let error = "VERIFIER_SPAWN: stderr pipe missing";
            return match kill_and_reap(child, process_group).await {
                Ok(()) => Err(error.into()),
                Err(cleanup) => Err(format!("{error}; {cleanup}")),
            };
        }
    };
    let capture = async {
        let stdout_read = read_bounded(stdout, MAX_VERIFIER_STDOUT_BYTES, "STDOUT");
        let stderr_read = read_bounded(stderr, MAX_VERIFIER_STDERR_BYTES, "STDERR");
        tokio::pin!(stdout_read, stderr_read);
        let mut stdout = None;
        let mut stderr = None;
        let mut status = None;
        loop {
            let mut terminal_error = None;
            tokio::select! {
                result = &mut stdout_read, if stdout.is_none() => match result {
                    Ok(raw) => stdout = Some(raw),
                    Err(error) => terminal_error = Some(error),
                },
                result = &mut stderr_read, if stderr.is_none() => match result {
                    Ok(raw) => stderr = Some(raw),
                    Err(error) => terminal_error = Some(error),
                },
                result = child.wait(), if status.is_none() => match result {
                    Ok(exit) => {
                        match kill_process_group_members(process_group) {
                            Ok(()) => match reap_process_group_members(process_group).await {
                                Ok(()) => status = Some(exit),
                                Err(error) => terminal_error = Some(error),
                            },
                            Err(error) => terminal_error = Some(error),
                        }
                    }
                    Err(error) => terminal_error = Some(format!("VERIFIER_WAIT: {error}")),
                },
            }
            if let Some(error) = terminal_error {
                return match kill_and_reap(child, process_group).await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(format!("{error}; {cleanup}")),
                };
            }
            if stdout.is_some() && stderr.is_some() && status.is_some() {
                return Ok((
                    status.take().expect("status set"),
                    stdout.take().expect("stdout set"),
                    stderr.take().expect("stderr set"),
                ));
            }
        }
    };
    match tokio::time::timeout(budget, capture).await {
        Ok(result) => result,
        Err(_) => match kill_and_reap(child, process_group).await {
            Ok(()) => Err("VERIFIER_TIMEOUT: no record inside the budget".into()),
            Err(cleanup) => Err(format!(
                "VERIFIER_TIMEOUT: no record inside the budget; {cleanup}"
            )),
        },
    }
}

fn parse_record(stdout: &[u8], stderr: &[u8]) -> Result<VerifierEvidence, String> {
    if !stderr.is_empty() {
        return Err("VERIFIER_PROTOCOL: successful verifier wrote stderr".into());
    }
    if stdout.len() > MAX_VERIFIER_STDOUT_BYTES {
        return Err(format!(
            "VERIFIER_STDOUT_OVERSIZED: exceeds {MAX_VERIFIER_STDOUT_BYTES} bytes"
        ));
    }
    if stdout.last() != Some(&b'\n')
        || stdout.iter().filter(|byte| **byte == b'\n').count() != 1
        || stdout.contains(&b'\r')
        || stdout.contains(&b'\0')
    {
        return Err(
            "VERIFIER_PROTOCOL: stdout must be exactly one LF-terminated JSON frame".into(),
        );
    }
    let frame = &stdout[..stdout.len() - 1];
    let record: VerifierEvidence =
        serde_json::from_slice(frame).map_err(|err| format!("VERIFIER_RECORD_PARSE: {err}"))?;
    let value: serde_json::Value =
        serde_json::from_slice(frame).map_err(|err| format!("VERIFIER_RECORD_PARSE: {err}"))?;
    let exact =
        serde_json::to_value(&record).map_err(|err| format!("VERIFIER_RECORD_ENCODE: {err}"))?;
    if exact != value {
        return Err("VERIFIER_PROTOCOL: record contains unknown or lossy fields".into());
    }
    Ok(record)
}

/// Run one clean-room verification of the exact candidate subject.
pub async fn run_verifier(request: &VerifierRequest) -> Result<VerifierEvidence, String> {
    enable_child_subreaper()?;
    let payload =
        serde_json::to_string(request).map_err(|err| format!("encode verifier request: {err}"))?;
    let mut child = command_for()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("VERIFIER_SPAWN: {err}"))?;
    write_request(&mut child, payload.as_bytes()).await?;
    let (status, stdout, stderr) = capture_child(&mut child, VERIFIER_TIMEOUT).await?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "VERIFIER_REFUSED: exit {:?}: {}",
            status.code(),
            stderr.trim()
        ));
    }
    parse_record(&stdout, &stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_frame() -> Vec<u8> {
        let mut raw = serde_json::json!({
            "tier": "E2",
            "gate_id": bullet_domain::REPOSITORY_GATE_ID,
            "outcome": "PASS",
            "reason": null,
            "detail": null,
            "argv": ["/usr/bin/grep", "-qx", "PONG", "PONG.txt"],
            "timeout_secs": 2,
            "exit_code": 0,
            "duration_ms": 1,
            "subject": {
                "base_sha": "a".repeat(40),
                "head_sha": "b".repeat(40),
                "tree_sha": "c".repeat(40),
            },
            "environment": {},
            "produced_by": "bullet-verifier",
            "author_attempt_id": "atm_test",
        })
        .to_string()
        .into_bytes();
        raw.push(b'\n');
        raw
    }

    #[test]
    fn exact_single_frame_is_accepted() {
        let record = parse_record(&record_frame(), &[]).expect("record");
        assert_eq!(record.produced_by, "bullet-verifier");
    }

    #[test]
    fn contaminated_or_oversized_output_is_refused() {
        let frame = record_frame();
        let mut crlf = frame.clone();
        *crlf.last_mut().expect("last") = b'\r';
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&frame[..frame.len() - 1]).expect("json");
        unknown["unbound"] = serde_json::json!(true);
        let mut unknown = unknown.to_string().into_bytes();
        unknown.push(b'\n');
        let frame_text = String::from_utf8(frame.clone()).expect("utf8");
        let field = "\"produced_by\":";
        let offset = frame_text.find(field).expect("producer field");
        let duplicate = format!(
            "{}\"produced_by\":\"bullet-verifier\",{}",
            &frame_text[..offset],
            &frame_text[offset..]
        )
        .into_bytes();
        for hostile in [
            [b"noise\n".as_slice(), frame.as_slice()].concat(),
            [frame.as_slice(), b"noise".as_slice()].concat(),
            [frame.as_slice(), frame.as_slice()].concat(),
            crlf,
            unknown,
            duplicate,
            vec![b' '; MAX_VERIFIER_STDOUT_BYTES + 1],
        ] {
            assert!(parse_record(&hostile, &[]).is_err());
        }
        assert!(parse_record(&frame, b"warning\n").is_err());
    }

    #[tokio::test]
    async fn hostile_oversized_child_is_killed_and_reaped_promptly() {
        async fn assert_missing_output_pipe(stdout: Stdio, stderr: Stdio, expected: &str) {
            let mut child = tokio::process::Command::new("/usr/bin/sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .kill_on_drop(true)
                .spawn()
                .expect("spawn missing-output-pipe child");
            let error = capture_child(&mut child, Duration::from_secs(2))
                .await
                .expect_err("missing output pipe refuses");
            assert_eq!(error, expected);
            assert!(child
                .try_wait()
                .expect("reaped output-pipe child")
                .is_some());
        }
        enable_child_subreaper().expect("enable child subreaper");
        let mut child = tokio::process::Command::new("/usr/bin/yes")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn yes");
        let started = std::time::Instant::now();
        let error = capture_child(&mut child, Duration::from_secs(2))
            .await
            .expect_err("oversize");
        assert!(error.starts_with("VERIFIER_STDOUT_OVERSIZED:"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(child.try_wait().expect("reaped state").is_some());
        let mut no_stdin = tokio::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn child without a stdin pipe");
        let error = write_request(&mut no_stdin, b"request")
            .await
            .expect_err("missing pipe refuses");
        assert_eq!(error, "VERIFIER_SPAWN: stdin pipe missing");
        assert!(no_stdin
            .try_wait()
            .expect("reaped missing-pipe child")
            .is_some());
        assert_missing_output_pipe(
            Stdio::null(),
            Stdio::piped(),
            "VERIFIER_SPAWN: stdout pipe missing",
        )
        .await;
        assert_missing_output_pipe(
            Stdio::piped(),
            Stdio::null(),
            "VERIFIER_SPAWN: stderr pipe missing",
        )
        .await;
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("descendant.pid");
        let mut inherited_pipe = tokio::process::Command::new("/usr/bin/sh");
        inherited_pipe
            .arg("-c")
            .arg(format!(
                "sleep 30 & echo $! > {}; printf complete",
                pid_file.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let mut inherited_pipe = inherited_pipe.spawn().expect("spawn inherited-pipe child");
        let started = std::time::Instant::now();
        let (status, stdout, stderr) = capture_child(&mut inherited_pipe, Duration::from_secs(2))
            .await
            .expect("direct exit kills descendants holding output pipes");
        assert!(status.success());
        assert_eq!(stdout, b"complete");
        assert!(stderr.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
        let descendant = std::fs::read_to_string(&pid_file).expect("descendant pid");
        let descendant = descendant.trim().parse::<u32>().expect("numeric pid");
        assert!(
            !std::path::Path::new(&format!("/proc/{descendant}")).exists(),
            "descendant {descendant} was not reaped"
        );
    }
}
