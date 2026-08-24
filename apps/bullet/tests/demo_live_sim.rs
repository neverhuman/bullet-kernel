//! CLI surface proof: the synthetic scaffold stays explicit, and demo-live
//! exists only behind the mechanical live-admission gate — without the
//! operator token it refuses with LIVE_ADMISSION_UNAVAILABLE.

use std::process::Command;

#[test]
fn synthetic_surface_and_gated_live_refusal() {
    let help = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("--help")
        .output()
        .expect("spawn bullet");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("demo-synthetic"));
    assert!(stdout.contains("demo-live"));

    let denied = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(["demo-live", "--provider", "claude"])
        .env_remove("BULLET_LIVE_ADMISSION")
        .output()
        .expect("spawn bullet");
    assert!(!denied.status.success(), "no admission must refuse");
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        stderr.contains("LIVE_ADMISSION_UNAVAILABLE"),
        "stderr: {stderr}"
    );

    let wrong = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(["demo-live", "--provider", "claude"])
        .env("BULLET_LIVE_ADMISSION", "wrong-token")
        .output()
        .expect("spawn bullet");
    assert!(!wrong.status.success(), "wrong token must refuse");
}
