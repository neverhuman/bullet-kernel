//! Debug-component process identity observations for cleanup diagnostics.

use super::support::fail;
use super::verifier_process::ProcessGuard;
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::process::Child;

const LEDGER_FD_ENV: &str = "BULLET_TRANSACTION_OFFLINE_PROCESS_LEDGER_FD";
const VERIFIER_DIGEST_ENV: &str = "BULLET_VERIFIER_FIXTURE_SHA256";
const RUNNER_DIGEST_ENV: &str = "BULLET_RUNNER_SHA256";

pub(super) fn observe_and_guard_verifier(
    child: Child,
    required: bool,
) -> Result<ProcessGuard, String> {
    observe_and_guard_subject(
        child,
        std::env::var_os(LEDGER_FD_ENV),
        std::env::var(VERIFIER_DIGEST_ENV).ok(),
        "sealed-verifier-fixture",
        required,
    )
}

pub(super) fn observe_and_guard_runner(
    child: Child,
    required: bool,
) -> Result<ProcessGuard, String> {
    observe_and_guard_subject(
        child,
        std::env::var_os(LEDGER_FD_ENV),
        std::env::var(RUNNER_DIGEST_ENV).ok(),
        "bullet-runner-admitted",
        required,
    )
}

fn observe_and_guard_subject(
    child: Child,
    raw_fd: Option<OsString>,
    expected_digest: Option<String>,
    subject: &str,
    required: bool,
) -> Result<ProcessGuard, String> {
    let observation = record_process_subject(
        &child,
        raw_fd,
        expected_digest.as_deref(),
        subject,
        required,
    );
    let guarded = ProcessGuard::new(child);
    observation?;
    Ok(guarded)
}

fn record_process_subject(
    child: &Child,
    raw_fd: Option<OsString>,
    expected_digest: Option<&str>,
    subject: &str,
    required: bool,
) -> Result<(), String> {
    let Some(raw_fd) = raw_fd else {
        if required {
            return Err(fail("process ledger fd is required for an injected fault"));
        }
        return Ok(());
    };
    let fd = raw_fd
        .into_string()
        .map_err(|_| fail("process ledger fd is not UTF-8"))?;
    let parsed = fd
        .parse::<i32>()
        .map_err(|_| fail("process ledger fd is not an integer"))?;
    if parsed < 3 || parsed.to_string() != fd {
        return Err(fail("process ledger fd is not canonical"));
    }
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| fail(format!("read verifier process identity: {error}")))?;
    let mut fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| fail("verifier process identity is malformed"))?
        .1
        .split_whitespace();
    let _state = fields.next();
    let parent = fields
        .next()
        .ok_or_else(|| fail("verifier parent missing"))?;
    let group = fields
        .next()
        .ok_or_else(|| fail("verifier group missing"))?;
    let start = fields
        .nth(16)
        .ok_or_else(|| fail("verifier start missing"))?;
    let exe = format!("/proc/{pid}/exe");
    let link = fs::read_link(&exe).map_err(|error| fail(format!("read verifier exe: {error}")))?;
    let bytes = fs::read(&exe).map_err(|error| fail(format!("hash verifier exe: {error}")))?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let expected_digest = expected_digest
        .ok_or_else(|| fail(format!("{subject} admitted digest is unprovisioned")))?;
    if expected_digest != digest {
        return Err(fail(format!(
            "{subject} process digest differs from its admitted subject"
        )));
    }
    let mut ledger = fs::OpenOptions::new()
        .append(true)
        .open(format!("/proc/self/fd/{parsed}"))
        .map_err(|error| fail(format!("open process ledger: {error}")))?;
    writeln!(
        ledger,
        "{pid}\t{start}\t{parent}\t{group}\t{subject}\t{digest}\t{}",
        link.display()
    )
    .map_err(|error| fail(format!("record verifier process: {error}")))
}

#[cfg(test)]
mod tests {
    use super::observe_and_guard_subject;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    #[test]
    fn observation_refusal_kills_and_reaps_the_exact_spawned_process_group() {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "trap '' HUP INT TERM; while :; do /bin/sleep 60; done",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().expect("spawn hostile verifier fixture");
        let pid = child.id();
        let start = process_start(pid).expect("read hostile verifier start time");

        let error = observe_and_guard_subject(
            child,
            Some(OsString::from("2")),
            Some("0".repeat(64)),
            "sealed-verifier-fixture",
            true,
        )
        .err()
        .expect("non-canonical ledger fd must refuse");

        assert_eq!(error, "process ledger fd is not canonical");
        match process_start(pid) {
            Ok(observed) => assert_ne!(observed, start, "same-start verifier survived refusal"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("inspect verifier after refusal: {error}"),
        }
    }

    fn process_start(pid: u32) -> std::io::Result<String> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let tail = stat
            .rsplit_once(") ")
            .ok_or_else(|| std::io::Error::other("process identity is malformed"))?
            .1;
        tail.split_whitespace()
            .nth(19)
            .map(str::to_owned)
            .ok_or_else(|| std::io::Error::other("process start time is missing"))
    }
}
