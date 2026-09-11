//! Real PTYs with private synthetic credentials; no installed/provider claim.
#![cfg(target_os = "linux")]
#[path = "support/tui_console.rs"]
mod console;
#[path = "support/operator_fixture.rs"]
mod fixture;

use console::Console;
use rustix::fs::{flock, FlockOperation};
use rustix::termios::tcgetattr;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc,
};

#[test]
fn six_clients_remain_usable_during_credential_contention_and_recover_after_release() {
    let fixture = fixture::Fixture::start();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(fixture.directory.path().join(".auth.lock"))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut consoles = (0..6)
        .map(|_| Console::start(fixture.directory.path(), None))
        .collect::<Vec<_>>();
    for (console, _) in &mut consoles {
        console.until("AUTH_BUSY");
        assert!(!console.parser.screen().contents().contains("OBSERVED"));
        console.send(b"?");
        console.until("Operator help");
        console.send(b"\x1b");
        console.until_absent("Operator help");
        console.send(b"\x0b");
        console.until("Navigate");
        console.send(b"j\r");
        console.until("┌Tasks");
    }
    assert_eq!(
        fixture.reads.load(Ordering::SeqCst),
        0,
        "busy discovery must not launch a GET"
    );
    consoles[0].0.detach();
    for (console, _) in &mut consoles[1..] {
        assert!(console.child.try_wait().unwrap().is_none());
    }
    flock(&lock, FlockOperation::Unlock).unwrap();
    for (console, _) in &mut consoles[1..] {
        console.send(b"r");
        console.until("OBSERVED");
        console.until("┌Tasks");
        console.send(b"\x0b");
        console.until("Navigate");
        console.send(b"\r");
        console.until("Synthetic PTY mission");
        console.detach();
    }
    for (console, _) in &consoles {
        let output = String::from_utf8_lossy(&console.output);
        assert!(!output.contains("ses_"));
        assert!(!output.contains("csrf_"));
    }
}

#[test]
fn missing_credentials_render_navigation_then_recover_without_restarting_the_client() {
    let fixture = fixture::Fixture::start();
    let credential_path = fixture.directory.path().join("session.json");
    let retained = fixture.directory.path().join("retained-session");
    std::fs::rename(&credential_path, &retained).unwrap();
    let mut consoles = (0..6)
        .map(|_| Console::start(fixture.directory.path(), None))
        .collect::<Vec<_>>();
    for (console, _) in &mut consoles {
        console.until("AUTH_REQUIRED");
        console.send(b"?");
        console.until("Operator help");
        console.send(b"\x1b");
        console.until_absent("Operator help");
    }
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    consoles[0].0.detach();
    fixture.malformed.store(true, Ordering::SeqCst);
    std::fs::rename(&retained, &credential_path).unwrap();
    for (console, _) in &mut consoles[1..] {
        console.send(b"r");
        console.until("FARMD_MODEL_INVALID");
        assert!(!console.parser.screen().contents().contains("OBSERVED"));
    }
    fixture.malformed.store(false, Ordering::SeqCst);
    for (console, _) in &mut consoles[1..] {
        assert!(console.child.try_wait().unwrap().is_none());
        console.send(b"r");
        console.until("Synthetic PTY mission");
        console.detach();
    }
    for (console, slave) in &consoles {
        let after = tcgetattr(slave).unwrap();
        assert!(after
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON));
        assert!(!String::from_utf8_lossy(&console.output).contains("ses_"));
        assert!(!String::from_utf8_lossy(&console.output).contains("csrf_"));
    }
}

#[test]
fn revoked_sessions_clear_displayed_owner_data_and_recover_after_reauthentication() {
    for status in [401, 403] {
        let refusal = Arc::new(AtomicU16::new(0));
        let fixture = fixture::Fixture::start_with_gate_and_refusal(
            Arc::new(AtomicBool::new(false)),
            refusal.clone(),
        );
        let (mut console, _) = Console::start(fixture.directory.path(), None);
        console.until("Synthetic PTY mission");
        console.until("OBSERVED");
        refusal.store(status, Ordering::SeqCst);
        console.send(b"r");
        console.until(&format!("FARMD_SNAPSHOT_REFUSED: HTTP {status}"));
        let screen = console.parser.screen().contents();
        assert!(!screen.contains("Synthetic PTY mission"));
        assert!(!screen.contains("OBSERVED"));
        assert!(!screen.contains("STALE"));
        console.send(b"?");
        console.until("Operator help");
        console.send(b"\x1b");
        console.until_absent("Operator help");
        refusal.store(0, Ordering::SeqCst);
        console.send(b"r");
        console.until("Synthetic PTY mission");
        console.until("OBSERVED");
        console.detach();
        assert!(!String::from_utf8_lossy(&console.output).contains("ses_"));
        assert!(!String::from_utf8_lossy(&console.output).contains("csrf_"));
    }
}

#[test]
fn default_bullet_and_bulletfarm_paint_during_contention_and_detach_independently() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let fixture = fixture::Fixture::start();
    let state_root = fixture.directory.path().join("default-state");
    let directory = state_root.join("bullet/operator");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(
        fixture.directory.path().join("session.json"),
        directory.join("session.json"),
    )
    .unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join(".auth.lock"))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let binaries = [
        env!("CARGO_BIN_EXE_bullet"),
        env!("CARGO_BIN_EXE_bulletfarm"),
    ];
    let mut consoles = (0..6)
        .map(|index| Console::start_default(&state_root, binaries[index % 2]))
        .collect::<Vec<_>>();
    for (console, _) in &mut consoles {
        console.until("AUTH_BUSY");
        console.send(b"?");
        console.until("Operator help");
        console.send(b"\x1b");
        console.until_absent("Operator help");
    }
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    consoles[0].0.detach();
    for (console, _) in &mut consoles[1..] {
        assert!(console.child.try_wait().unwrap().is_none());
    }
    flock(&lock, FlockOperation::Unlock).unwrap();
    for (console, _) in &mut consoles[1..] {
        console.send(b"r");
        console.until("Synthetic PTY mission");
        console.until("OBSERVED");
        console.detach();
    }
    for (console, slave) in &consoles {
        assert!(tcgetattr(slave)
            .unwrap()
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON));
        let output = String::from_utf8_lossy(&console.output);
        assert!(!output.contains("ses_"));
        assert!(!output.contains("csrf_"));
    }
}

#[test]
fn default_aliases_keep_noninteractive_refusals_and_explicit_help() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let binaries = [
        env!("CARGO_BIN_EXE_bullet"),
        env!("CARGO_BIN_EXE_bulletfarm"),
    ];
    for binary in binaries {
        let invoke = |args: &[&str]| {
            Command::new(binary)
                .args(args)
                .env_clear()
                .env("TERM", "dumb")
                .env("XDG_STATE_HOME", directory.path())
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        let default = invoke(&[]);
        let explicit = invoke(&["tui"]);
        assert_eq!(default.status.code(), Some(1));
        assert_eq!(default.status.code(), explicit.status.code());
        assert!(default.stdout.is_empty());
        assert_eq!(default.stdout, explicit.stdout);
        assert_eq!(default.stderr, explicit.stderr);
        assert!(String::from_utf8_lossy(&default.stderr).contains("AUTH_REQUIRED"));
        let help = invoke(&["--help"]);
        assert!(help.status.success());
        let help = String::from_utf8(help.stdout).unwrap();
        for command in ["tui", "coding", "auth"] {
            assert!(help.contains(command));
        }
    }
}
