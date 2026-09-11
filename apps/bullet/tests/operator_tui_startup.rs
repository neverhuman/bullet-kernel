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
