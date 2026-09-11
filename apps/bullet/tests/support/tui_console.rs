use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::pty::{grantpt, ioctl_tiocgptpeer, openpt, unlockpt, OpenptFlags};
use rustix::termios::{tcsetwinsize, Winsize};
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(super) struct Console {
    pub(super) child: Child,
    pub(super) master: File,
    pub(super) output: Vec<u8>,
    pub(super) parser: vt100::Parser,
}
impl Console {
    pub(super) fn start(directory: &std::path::Path, subject: Option<&str>) -> (Self, File) {
        Self::start_command(directory, subject, env!("CARGO_BIN_EXE_bullet"), false)
    }
    pub(super) fn start_default(state_root: &std::path::Path, executable: &str) -> (Self, File) {
        Self::start_command(state_root, None, executable, true)
    }
    fn start_command(
        directory: &std::path::Path,
        subject: Option<&str>,
        executable: &str,
        default_entry: bool,
    ) -> (Self, File) {
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
        command.arg("--ctty").arg(executable);
        if default_entry {
            command.env("XDG_STATE_HOME", directory);
        } else {
            command.args(["tui", "--state-dir"]).arg(directory);
        }
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
    pub(super) fn drain(&mut self) {
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
    pub(super) fn until(&mut self, text: &str) {
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
    pub(super) fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }
    pub(super) fn until_absent(&mut self, text: &str) {
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
    pub(super) fn detach(&mut self) {
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
