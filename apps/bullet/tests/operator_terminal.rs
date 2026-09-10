//! Real CLI/PTY component regressions. No provider or production recording.
#![cfg(target_os = "linux")]

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::pty::{grantpt, ioctl_tiocgptpeer, openpt, unlockpt, OpenptFlags};
use rustix::termios::{tcgetattr, tcsetwinsize, LocalModes, Winsize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn private_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn read_available(master: &mut impl Read, output: &mut Vec<u8>) {
    let mut bytes = [0; 8192];
    loop {
        match master.read(&mut bytes) {
            Ok(0) => return,
            Ok(n) => {
                output.extend_from_slice(&bytes[..n]);
                assert!(output.len() <= 1024 * 1024);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) if e.raw_os_error() == Some(5) => return,
            Err(e) => panic!("PTY read failed: {e}"),
        }
    }
}

#[test]
fn hidden_bootstrap_cancel_never_echoes_and_restores_terminal() {
    let directory = private_temp();
    let master_fd = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
    grantpt(&master_fd).unwrap();
    unlockpt(&master_fd).unwrap();
    let slave = File::from(
        ioctl_tiocgptpeer(
            &master_fd,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .unwrap(),
    );
    let before = tcgetattr(&slave).unwrap();
    tcsetwinsize(
        &slave,
        Winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .unwrap();
    fcntl_setfl(
        &master_fd,
        fcntl_getfl(&master_fd).unwrap() | OFlags::NONBLOCK,
    )
    .unwrap();
    let mut master = File::from(master_fd);
    let mut child = OwnedChild(
        Command::new("/usr/bin/setsid")
            .arg("--ctty")
            .arg(env!("CARGO_BIN_EXE_bullet"))
            .args(["auth", "login", "--state-dir"])
            .arg(directory.path().join("operator"))
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .env("TERM", "xterm-256color")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    loop {
        read_available(&mut master, &mut output);
        if !tcgetattr(&slave)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "hidden prompt did not become ready"
        );
        assert!(child.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(10));
    }
    let token = format!("boot_{}", "a".repeat(64));
    master.write_all(token.as_bytes()).unwrap();
    master.write_all(b"\x03").unwrap();
    loop {
        read_available(&mut master, &mut output);
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(Instant::now() < deadline, "cancel did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    read_available(&mut master, &mut output);
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("AUTH_INPUT_CANCELLED"));
    assert!(!output.contains(&token));
    let after = tcgetattr(&slave).unwrap();
    assert_eq!(after.local_modes, before.local_modes);
    assert_eq!(after.input_modes, before.input_modes);
    assert_eq!(after.output_modes, before.output_modes);
    assert!(!directory.path().join("operator/session.json").exists());
}

#[test]
fn oversized_piped_bootstrap_is_refused_without_echo_or_network() {
    let directory = private_temp();
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_bullet"))
            .args(["auth", "login", "--stdin", "--state-dir"])
            .arg(directory.path().join("operator"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let input = format!("boot_{}{}private", "a".repeat(64), " ".repeat(300));
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    fcntl_setfl(&stdout, fcntl_getfl(&stdout).unwrap() | OFlags::NONBLOCK).unwrap();
    fcntl_setfl(&stderr, fcntl_getfl(&stderr).unwrap() | OFlags::NONBLOCK).unwrap();
    let mut out_bytes = Vec::new();
    let mut err_bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        read_available(&mut stdout, &mut out_bytes);
        read_available(&mut stderr, &mut err_bytes);
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "piped bootstrap did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    read_available(&mut stdout, &mut out_bytes);
    read_available(&mut stderr, &mut err_bytes);
    let stderr = String::from_utf8_lossy(&err_bytes);
    assert!(!status.success());
    assert!(stderr.contains("AUTH_INPUT_TOO_LONG"));
    for output in [&out_bytes, &err_bytes] {
        let output = String::from_utf8_lossy(output);
        assert!(!output.contains("boot_"));
        assert!(!output.contains("private"));
    }
    assert!(!directory.path().join("operator/session.json").exists());
}
