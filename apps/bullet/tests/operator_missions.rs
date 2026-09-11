//! Real CLI against synthetic authenticated HTTP; component evidence only.
#![cfg(target_os = "linux")]
#[path = "support/operator_fixture.rs"]
mod fixture;

use serde_json::Value;
use std::process::{Command, Output};
use std::sync::atomic::Ordering;

fn invoke(fixture: &fixture::Fixture, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("mission")
        .args(args)
        .arg("--state-dir")
        .arg(fixture.directory.path())
        .output()
        .unwrap()
}

fn invoke_snapshot(fixture: &fixture::Fixture, args: &[&str]) -> Output {
    let before = fixture.requests().len();
    let output = invoke(fixture, args);
    assert_eq!(
        &fixture.requests()[before..],
        &[
            fixture::ReadRequest {
                path: "/api/v1/auth/session".into(),
                expected_session: None,
            },
            fixture::ReadRequest {
                path: "/api/v1/operator-snapshot".into(),
                expected_session: Some(format!("sid_{}", "c".repeat(64))),
            },
        ],
        "each operation must discover its session then read one bound snapshot"
    );
    output
}

fn accepted(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    for prefix in ["ses_", "csrf_", "bullet_session"] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(prefix));
    }
    serde_json::from_slice(&output.stdout).unwrap()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "refusal must not look like an empty mission list"
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains(code), "unexpected refusal: {text}");
    assert!(!text.contains("ses_") && !text.contains("csrf_"));
}

#[test]
fn mission_list_and_status_use_one_authenticated_snapshot_each_without_local_ledger() {
    let fixture = fixture::Fixture::start();
    let list = accepted(&invoke_snapshot(&fixture, &["list", "--json"]));
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["id"], fixture::subject());
    assert_eq!(list["as_of_sequence"], 0);
    assert_eq!(list["source"], "bullet-kernel/sqlite-ledger");
    let status = accepted(&invoke_snapshot(
        &fixture,
        &["status", "--mission", &fixture::subject(), "--json"],
    ));
    assert_eq!(status["data"]["mission"], list["data"][0]);
    assert_eq!(status["data"]["packages"], serde_json::json!([]));
    assert_eq!(status["as_of_sequence"], list["as_of_sequence"]);
    assert_eq!(status["observed_at"], list["observed_at"]);
    assert_eq!(status["source"], list["source"]);
    assert!(!fixture.directory.path().join("ledger.sqlite").exists());
    let text = invoke_snapshot(&fixture, &["status", "--mission", &fixture::subject()]);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("Mission snapshot 0"));
    assert!(text.contains("Synthetic PTY mission") && text.contains("0 tasks observed"));
    assert!(!text.contains("ses_") && !text.contains("csrf_"));
}

#[test]
fn mission_refuses_malformed_remote_truth_and_unobserved_subjects() {
    let fixture = fixture::Fixture::start();
    let absent = format!("mis_{}", "2".repeat(64));
    refused(
        &invoke_snapshot(&fixture, &["status", "--mission", &absent]),
        "MISSION_NOT_FOUND",
    );
    fixture.malformed.store(true, Ordering::SeqCst);
    refused(
        &invoke_snapshot(&fixture, &["list", "--json"]),
        "FARMD_MODEL_INVALID",
    );
    refused(
        &invoke_snapshot(
            &fixture,
            &["status", "--mission", &fixture::subject(), "--json"],
        ),
        "FARMD_MODEL_INVALID",
    );
}

#[test]
fn mission_validates_subject_destination_and_local_mode_before_any_http_request() {
    let fixture = fixture::Fixture::start();
    let output = invoke(&fixture, &["status", "--mission", "\u{1b}]52;hostile"]);
    refused(&output, "INVALID_ID");
    assert!(
        !output.stderr.contains(&0x1b),
        "terminal escape reached stderr"
    );
    refused(
        &invoke(&fixture, &["list", "--farmd", "http://127.0.0.1:1"]),
        "AUTH_DESTINATION_MISMATCH",
    );
    let local = fixture.directory.path().join("must-not-create");
    let conflict = invoke(
        &fixture,
        &[
            "status",
            "--mission",
            &fixture::subject(),
            "--data-dir",
            local.to_str().unwrap(),
        ],
    );
    assert_eq!(conflict.status.code(), Some(2));
    assert!(!local.exists());
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert!(fixture.requests().is_empty());
}
