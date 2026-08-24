//! CLI surface proof: the synthetic scaffold is explicit and live execution
//! is not part of the command surface.

use std::process::Command;

#[test]
fn synthetic_cli_is_explicit_and_live_command_is_absent() {
    let help = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("--help")
        .output()
        .expect("spawn bullet");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("demo-synthetic"));
    assert!(!stdout.contains("demo-live"));

    let denied = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("demo-live")
        .output()
        .expect("spawn bullet");
    assert!(!denied.status.success(), "live command must not exist");
}
