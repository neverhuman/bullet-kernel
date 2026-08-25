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
    match verifier_binary() {
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
    }
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

async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn capture_child(
    child: &mut tokio::process::Child,
    budget: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), String> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "VERIFIER_SPAWN: stdout pipe missing".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "VERIFIER_SPAWN: stderr pipe missing".to_string())?;
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
                    Ok(exit) => status = Some(exit),
                    Err(error) => terminal_error = Some(format!("VERIFIER_WAIT: {error}")),
                },
            }
            if let Some(error) = terminal_error {
                kill_and_reap(child).await;
                return Err(error);
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
        Err(_) => {
            kill_and_reap(child).await;
            Err("VERIFIER_TIMEOUT: no record inside the budget".into())
        }
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
    let payload =
        serde_json::to_string(request).map_err(|err| format!("encode verifier request: {err}"))?;
    let mut child = command_for()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("VERIFIER_SPAWN: {err}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "VERIFIER_SPAWN: stdin pipe missing".to_string())?;
    stdin
        .write_all(payload.as_bytes())
        .await
        .map_err(|err| format!("VERIFIER_WRITE: {err}"))?;
    drop(stdin);
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
    }
}
