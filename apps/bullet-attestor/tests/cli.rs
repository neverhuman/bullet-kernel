//! The packaged attestor never self-echoes a successful check receipt.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn assert_typed_refusal(output: &Output, reason_code: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "refusal must not emit a receipt");
    let refusal: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("one refusal JSON object");
    assert_eq!(refusal["reason_code"], reason_code);
    let object = refusal.as_object().expect("refusal object");
    for forbidden in [
        "sha",
        "name",
        "proof_root",
        "receipt",
        "success",
        "produced_by",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "refusal must not contain success-shaped key {forbidden}"
        );
    }
}

#[test]
fn unwired_attestor_is_typed_refusal_without_success_output() {
    let credential =
        std::env::temp_dir().join(format!("bullet-attestor-cli-{}.key", std::process::id(),));
    fs::write(&credential, "attestor-cli\n").expect("credential");
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&credential).expect("metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&credential, permissions).expect("mode");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_bullet-attestor"))
        .args([
            "attest",
            "--credential-file",
            credential.to_str().expect("utf8 temp path"),
            "--sha",
            &"a".repeat(40),
            "--name",
            "gate.v1",
            "--proof-root",
            "proof-root",
        ])
        .output()
        .expect("run attestor");
    fs::remove_file(&credential).expect("cleanup");

    assert_typed_refusal(&output, "LIVE_ADMISSION_UNAVAILABLE");

    let push = Command::new(env!("CARGO_BIN_EXE_bullet-attestor"))
        .arg("push")
        .output()
        .expect("run forbidden push");
    assert_typed_refusal(&push, "UNSUPPORTED_BY_ADAPTER");
}
