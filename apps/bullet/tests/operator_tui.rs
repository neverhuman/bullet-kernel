//! Actual CLI/PTY smoke with synthetic HTTP. This is never live provider evidence.
#![cfg(target_os = "linux")]
#[path = "support/operator_fixture.rs"]
mod fixture;

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::pty::{grantpt, ioctl_tiocgptpeer, openpt, unlockpt, OpenptFlags};
use rustix::termios::{tcgetattr, tcsetwinsize, Winsize};
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

struct Console {
    child: Child,
    master: File,
    output: Vec<u8>,
    parser: vt100::Parser,
}
impl Console {
    fn start(directory: &std::path::Path, subject: Option<&str>) -> (Self, File) {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = File::from(
            ioctl_tiocgptpeer(
                &master,
                OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
            )
            .unwrap(),
        );
        tcsetwinsize(
            &slave,
            Winsize {
                ws_row: 30,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
        fcntl_setfl(&master, fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK).unwrap();
        let mut command = Command::new("/usr/bin/setsid");
        command
            .arg("--ctty")
            .arg(env!("CARGO_BIN_EXE_bullet"))
            .args(["tui", "--state-dir"])
            .arg(directory);
        if let Some(subject) = subject {
            command.args(["--subject", subject]);
        }
        let child = command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .env("TERM", "xterm-256color")
            .spawn()
            .unwrap();
        (
            Self {
                child,
                master: File::from(master),
                output: Vec::new(),
                parser: vt100::Parser::new(30, 120, 0),
            },
            slave,
        )
    }
    fn drain(&mut self) {
        let mut bytes = [0; 8192];
        loop {
            match self.master.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    self.parser.process(&bytes[..n]);
                    self.output.extend_from_slice(&bytes[..n]);
                    assert!(self.output.len() <= 1_048_576);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(5) =>
                {
                    break
                }
                Err(e) => panic!("PTY read failed: {e}"),
            }
        }
    }
    fn until(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if self.parser.screen().contents().contains(text) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "CLI exited before expected display: {text}"
            );
            assert!(Instant::now() < deadline, "missing display: {text}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }
    fn until_absent(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if !self.parser.screen().contents().contains(text) {
                return;
            }
            assert!(self.child.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline, "display did not close: {text}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn detach(&mut self) {
        self.send(b"\x03");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "detach did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        self.drain();
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn actual_tui_navigates_refuses_bad_refresh_and_detaches_without_mutation() {
    let fixture = fixture::Fixture::start();
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let slave = File::from(
        ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .unwrap(),
    );
    tcsetwinsize(
        &slave,
        Winsize {
            ws_row: 30,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .unwrap();
    let before = tcgetattr(&slave).unwrap();
    fcntl_setfl(&master, fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK).unwrap();
    let child = Command::new("/usr/bin/setsid")
        .arg("--ctty")
        .arg(env!("CARGO_BIN_EXE_bullet"))
        .args(["tui", "--state-dir"])
        .arg(fixture.directory.path())
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .env("TERM", "xterm-256color")
        .spawn()
        .unwrap();
    let mut console = Console {
        child,
        master: File::from(master),
        output: Vec::new(),
        parser: vt100::Parser::new(30, 120, 0),
    };
    console.until("Synthetic PTY mission");
    console.send(b"\x0b");
    console.until("Navigate");
    console.send(b"j\r");
    console.until("┌Tasks");
    console.send(b"?");
    console.until("Operator help");
    console.send(b"\x1b");
    std::thread::sleep(Duration::from_millis(100));
    console.send(b"\x1b");
    std::thread::sleep(Duration::from_millis(100));
    fixture.malformed.store(true, Ordering::SeqCst);
    console.send(b"r");
    console.until("FARMD_MODEL_INVALID");
    console.send(b"\x03");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        console.drain();
        if let Some(status) = console.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "detach did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    console.drain();
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.contains("DETACHED: durable work continues. Reconnect: bullet tui"));
    assert!(
        output.contains(&format!("--subject '{}'", fixture::subject())),
        "stale refresh must preserve the selected subject"
    );
    assert!(!output.contains("ses_"));
    assert!(!output.contains("csrf_"));
    assert!(fixture.reads.load(Ordering::SeqCst) >= 2);
    let after = tcgetattr(&slave).unwrap();
    assert_eq!(after.local_modes, before.local_modes);
    assert_eq!(after.input_modes, before.input_modes);
    assert_eq!(after.output_modes, before.output_modes);
}

#[test]
fn six_tuis_paint_before_http_and_share_credentials_without_coupled_detach() {
    let gate = Arc::new(AtomicBool::new(true));
    let fixture = fixture::Fixture::start_with_gate(gate.clone());
    let subject = fixture::subject();
    let mut consoles = (0..6)
        .map(|_| Console::start(fixture.directory.path(), Some(&subject)))
        .collect::<Vec<_>>();
    // The server cannot return any snapshot until all six have painted.
    for (console, _) in &mut consoles {
        console.until("CONNECTING");
        assert!(!console.parser.screen().contents().contains("OBSERVED"));
        assert!(!console
            .parser
            .screen()
            .contents()
            .contains("RECONNECT_SUBJECT_ABSENT"));
        assert!(!console
            .parser
            .screen()
            .contents()
            .contains("Synthetic PTY mission"));
        console.send(b"?");
        console.until("Operator help");
        console.send(b"\x1b");
        console.until_absent("Operator help");
        console.send(b"\x0b");
        console.until("Navigate");
        console.send(b"j\r");
        console.until("┌Tasks");
    }
    gate.store(false, Ordering::SeqCst);
    for (console, _) in &mut consoles {
        console.until("Synthetic PTY mission");
        assert!(console.parser.screen().contents().contains("OBSERVED"));
    }
    assert!(fixture.reads.load(Ordering::SeqCst) >= 6);
    consoles[0].0.detach();
    for (console, _) in &mut consoles[1..] {
        assert!(console.child.try_wait().unwrap().is_none());
        console.send(b"\x0b");
        console.until("Navigate");
        console.send(b"\x1b");
        console.detach();
    }
    for (console, _) in &consoles {
        let output = String::from_utf8_lossy(&console.output);
        assert!(output.contains("DETACHED: durable work continues."));
        assert!(output.contains(&format!("--subject '{subject}'")));
        assert!(!output.contains("ses_"));
        assert!(!output.contains("csrf_"));
    }
}

#[test]
fn connecting_detach_does_not_wait_for_http_and_preserves_quoted_reconnect_subject() {
    let gate = Arc::new(AtomicBool::new(true));
    let fixture = fixture::Fixture::start_with_gate(gate);
    let subject = "unobserved'subject";
    let (mut console, _) = Console::start(fixture.directory.path(), Some(subject));
    console.until("CONNECTING");
    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.reads.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "fixture did not observe initial GET"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    console.detach();
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.contains("--subject 'unobserved'\\''subject'"));
    assert!(!output.contains("RECONNECT_SUBJECT_ABSENT"));
    assert!(!output.contains("Synthetic PTY mission"));
}

#[test]
fn connecting_status_chrome_and_palette_unknown_surfaces_stay_honest() {
    let gate = Arc::new(AtomicBool::new(true));
    let fixture = fixture::Fixture::start_with_gate(gate.clone());
    let (mut console, _) = Console::start(fixture.directory.path(), None);
    console.until("CONNECTING");
    let first = console.parser.screen().contents();
    assert!(first.contains("HOLD"));
    assert!(first.contains("LIVE 0"));
    assert!(first.contains("UNBOUND"));
    assert!(first.contains("HEAD_RUNTIME_BINDING_REQUIRED"));
    assert!(first.contains("STOP_UNIMPLEMENTED"));
    assert!(!first.contains("VERIFIED"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.reads.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "fixture did not observe initial GET"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    console.until("refresh pending");
    console.send(b"\x0b");
    console.until("no ledger subject");
    console.send(b"j".repeat(8).as_slice());
    console.send(b"\r");
    console.until("Mission Graph");
    assert!(!console
        .parser
        .screen()
        .contents()
        .contains("Synthetic PTY mission"));
    gate.store(false, Ordering::SeqCst);
    console.until("OBSERVED");
    console.until("Synthetic PTY mission");
    console.send(b"J");
    console.until("raw JSON");
    console.send(b"?");
    console.until("STOP_UNIMPLEMENTED");
    console.detach();
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.contains("DETACHED: durable work continues."));
    assert!(!output.contains("ses_"));
    assert!(!output.contains("csrf_"));
}
