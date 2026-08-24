//! Spawn the independent verifier process on the candidate subject and
//! trust only its typed stdout record. The binary is resolved like
//! bullet-gitd: env override, then the build sibling, then cargo.

use bullet_verifier_core::{VerifierEvidence, VerifierRequest};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Environment override naming the verifier binary.
pub const VERIFIER_BIN_ENV: &str = "BULLET_VERIFIER_BIN";
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(300);

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
    let output = tokio::time::timeout(VERIFIER_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| "VERIFIER_TIMEOUT: no record inside the budget".to_string())?
        .map_err(|err| format!("VERIFIER_WAIT: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "VERIFIER_REFUSED: exit {:?}: {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    serde_json::from_str(line).map_err(|err| format!("VERIFIER_RECORD_PARSE: {err}: {line}"))
}
