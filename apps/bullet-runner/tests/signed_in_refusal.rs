//! Actual Runner binary, pre-launch refusal only. No worker/provider execution credit.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn actual_runner_refuses_uncontained_provider_before_child_or_authority_access() {
    let directory = tempfile::tempdir().unwrap();
    let stub = directory.path().join("provider");
    let marker = directory.path().join("child-started");
    std::fs::write(&stub, b"#!/bin/sh\nset -C\n: > child-started\nexit 97\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
    for provider in ["codex", "cursor", "agy", "antigravity"] {
        let output = Command::new(env!("CARGO_BIN_EXE_bullet-runner"))
            .current_dir(directory.path())
            .args([
                "--provider",
                provider,
                "--model",
                "fixture",
                "--signed-in-executable",
            ])
            .arg(&stub)
            .args([
                "--runner-id",
                &format!("run_{}", "1".repeat(64)),
                "--work-package-id",
                &format!("wpk_{}", "2".repeat(64)),
                "--candidate-request-digest",
                &"3".repeat(64),
                "--candidate-verification-key",
                "/absent/candidate.key",
                "--workspace-root",
                "/absent/workspace",
                "--source-repo",
                "/absent/source",
                "--base-sha",
                &"4".repeat(40),
                "--preservation-destination",
                "/absent/preserve",
                "--objective",
                "fixture",
                "--gate-id",
                &format!("gat_{}", "5".repeat(64)),
                "--scope",
                "PONG.txt",
                "--idempotency-key",
                "uncontained-fixture",
                "--lease-recovery",
                "/absent/recovery",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("PROVIDER_ADMISSION_INCOMPLETE: SIGNED_IN_CONTAINMENT_UNAVAILABLE"),
            "{stderr}"
        );
        assert!(output.stdout.is_empty());
        assert!(!marker.exists(), "uncontained provider was launched");
    }
}
