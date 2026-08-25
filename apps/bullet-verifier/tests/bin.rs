//! Binary round-trip: JSON on stdin, typed evidence record on stdout, and
//! the author-overlap refusal via the environment the kernel sets.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn sh(dir: &Path, script: &str) {
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .expect("fixture");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn fixture(dir: &Path) -> serde_json::Value {
    sh(
        dir,
        "git init -q -b main . && \
         git config user.name bullet && git config user.email bullet@test && \
         echo PONG > PONG.txt && echo base > f && git add . && git commit -qm base && \
         echo head > f && git add . && git commit -qm head",
    );
    serde_json::json!({
        "workspace_repo_path": dir.display().to_string(),
        "base_sha": git_out(dir, &["rev-parse", "HEAD~1"]),
        "head_sha": git_out(dir, &["rev-parse", "HEAD"]),
        "tree_sha": git_out(dir, &["rev-parse", "HEAD^{tree}"]),
        "gate_id": "repo.gate.v1",
        "author_attempt_id": concat!(
            "atm_",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
    })
}

fn run_binary(request: &serde_json::Value, envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bullet-verifier"));
    cmd.arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(request.to_string().as_bytes())
        .expect("write");
    child.wait_with_output().expect("wait")
}

#[test]
fn stdin_round_trip_emits_typed_e2_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let request = fixture(dir.path());
    let out = run_binary(&request, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let record: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON record");
    assert_eq!(record["tier"], "E2");
    assert_eq!(record["outcome"], "PASS");
    assert_eq!(record["produced_by"], "bullet-verifier");
    assert_eq!(record["subject"]["head_sha"], request["head_sha"]);
    assert_eq!(record["author_attempt_id"], request["author_attempt_id"]);
    assert_eq!(record["gate_id"], "repo.gate.v1");
    assert_eq!(
        record["argv"],
        serde_json::json!(["/usr/bin/grep", "-qx", "PONG", "PONG.txt"])
    );
    assert_eq!(record["timeout_secs"], 2);
}

#[test]
fn author_overlap_env_refuses_with_typed_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let request = fixture(dir.path());
    let out = run_binary(&request, &[("BULLET_VERIFIER_AUTHOR_OVERLAP", "1")]);
    assert_eq!(out.status.code(), Some(2));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).expect("stderr json");
    assert_eq!(err["reason_code"], "VERIFIER_IS_AUTHOR");
    assert!(out.stdout.is_empty(), "no evidence record on refusal");
}

#[test]
fn malformed_stdin_is_bad_input() {
    let out = run_binary(&serde_json::json!({"nope": true}), &[]);
    assert_eq!(out.status.code(), Some(2));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).expect("stderr json");
    assert_eq!(err["reason_code"], "BAD_INPUT");
}

#[test]
fn legacy_shell_timeout_and_unknown_ids_fail_without_artifacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("PWNED");
    let request = fixture(dir.path());

    let mut legacy = request.clone();
    legacy["gate_command"] = serde_json::json!(format!("touch {}", marker.display()));
    legacy["timeout_secs"] = serde_json::json!(1);
    let out = run_binary(&legacy, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!marker.exists());

    for gate_id in ["unknown.gate.v1", "repo.gate.v1;touch-PWNED"] {
        let mut hostile = request.clone();
        hostile["gate_id"] = serde_json::json!(gate_id);
        let out = run_binary(&hostile, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!marker.exists());
    }
}
