//! The product verifier refuses before parsing unsigned fixture inputs.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

fn run_product(raw: &[u8], extra_args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bullet-verifier"));
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
    if let Err(error) = stdin.write_all(raw) {
        assert_eq!(
            error.kind(),
            ErrorKind::BrokenPipe,
            "unexpected write error"
        );
    }
    drop(stdin);
    child.wait_with_output().expect("wait")
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

fn assert_admission_refusal(out: &std::process::Output) {
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "refusal must not emit evidence");
    let err = one_json_line(&out.stderr);
    assert_eq!(
        err["reason_code"],
        "VERIFICATION_INTENT_ADMISSION_UNAVAILABLE"
    );
    assert_eq!(err["evidence_emitted"], false);
}

#[test]
fn production_refuses_before_reading_unsigned_input() {
    assert_admission_refusal(&run_product(
        br#"{"not":"an admitted verification intent"}"#,
        &[],
        &[],
    ));
}

#[test]
fn product_refusal_is_constant_across_fixture_controls() {
    let hostile = vec![b'x'; 128 * 1024];
    let out = run_product(
        &hostile,
        &["--base-sha", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        &[("BULLET_VERIFIER_AUTHOR_OVERLAP", "1")],
    );
    assert_admission_refusal(&out);
}
