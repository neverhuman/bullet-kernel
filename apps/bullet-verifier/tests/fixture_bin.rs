//! Real process checks for the explicitly enabled component-only fixture.

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
        "gate_id": "gat_8888888888888888888888888888888888888888888888888888888888888888",
        "author_attempt_id": concat!(
            "atm_",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
    })
}

fn run_binary_raw(raw: &[u8], extra_args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bullet-verifier-fixture"));
    cmd.arg("--stdin")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(raw).expect("write");
    drop(stdin);
    child.wait_with_output().expect("wait")
}

fn run_binary(request: &serde_json::Value, envs: &[(&str, &str)]) -> std::process::Output {
    run_binary_raw(request.to_string().as_bytes(), &[], envs)
}

fn one_json_line(raw: &[u8]) -> serde_json::Value {
    assert_eq!(raw.last(), Some(&b'\n'), "frame must end with one newline");
    assert_eq!(
        raw.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "protocol stream must contain exactly one frame"
    );
    serde_json::from_slice(raw).expect("frame is json")
}

fn assert_fixture_metadata(frame: &serde_json::Value) {
    assert_eq!(frame["schema_version"], "bullet.verifier-fixture.v1");
    assert_eq!(frame["evidence_class"], "COMPONENT_PROOF");
    assert_eq!(frame["independent_evidence_eligible"], false);
    assert_eq!(frame["signing_trust"], "UNSIGNED_FIXTURE");
    assert_eq!(frame["transaction_gate_eligible"], false);
}

fn assert_bad_input(out: &std::process::Output) {
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "refusal must not emit an observation"
    );
    let err = one_json_line(&out.stderr);
    assert_fixture_metadata(&err);
    assert_eq!(err["reason_code"], "BAD_INPUT");
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
    assert!(out.stderr.is_empty(), "successful fixture run is quiet");
    let observation = one_json_line(&out.stdout);
    assert_fixture_metadata(&observation);
    assert_eq!(observation["outcome"], "PASS");
    let record = &observation["record"];
    assert_eq!(record["tier"], "E2");
    assert_eq!(record["outcome"], "PASS");
    assert_eq!(record["produced_by"], "bullet-verifier");
    assert_eq!(record["subject"]["head_sha"], request["head_sha"]);
    assert_eq!(record["author_attempt_id"], request["author_attempt_id"]);
    assert_eq!(
        record["gate_id"],
        "gat_8888888888888888888888888888888888888888888888888888888888888888"
    );
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
    let err = one_json_line(&out.stderr);
    assert_fixture_metadata(&err);
    assert_eq!(err["reason_code"], "VERIFIER_IS_AUTHOR");
    assert!(out.stdout.is_empty(), "no fixture observation on refusal");
}

#[test]
fn malformed_stdin_is_bad_input() {
    let out = run_binary(&serde_json::json!({"nope": true}), &[]);
    assert_bad_input(&out);
}

#[test]
fn stdin_size_limit_accepts_exact_boundary_and_refuses_one_byte_more() {
    const LIMIT: usize = 64 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut raw = fixture(dir.path()).to_string().into_bytes();
    assert!(raw.len() < LIMIT);
    raw.resize(LIMIT, b' ');

    let accepted = run_binary_raw(&raw, &[], &[]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_fixture_metadata(&one_json_line(&accepted.stdout));

    raw.push(b' ');
    assert_bad_input(&run_binary_raw(&raw, &[], &[]));
}

#[test]
fn multiple_trailing_and_mixed_transport_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let request = fixture(dir.path()).to_string();

    for raw in [format!("{request}{request}"), format!("{request} trailing")] {
        assert_bad_input(&run_binary_raw(raw.as_bytes(), &[], &[]));
    }

    let mixed = run_binary_raw(
        request.as_bytes(),
        &["--base-sha", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        &[],
    );
    assert_bad_input(&mixed);
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

    for gate_id in [
        "unknown.gate.v1",
        "gat_8888888888888888888888888888888888888888888888888888888888888888;touch-PWNED",
    ] {
        let mut hostile = request.clone();
        hostile["gate_id"] = serde_json::json!(gate_id);
        let out = run_binary(&hostile, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!marker.exists());
    }
}
