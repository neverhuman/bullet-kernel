//! Tuiwright's private Child is never signalled after our reaping it.
use anyhow::{bail, ensure, Context, Result};
use rustix::fd::{AsFd, OwnedFd};
use rustix::net::sockopt::socket_peercred;
use rustix::process::{
    getuid, pidfd_open, pidfd_send_signal, waitid, Pid, PidfdFlags, Signal, WaitId, WaitIdOptions,
};
use rustix::termios::{tcgetattr, SpecialCodeIndex as Cc, Termios};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
use tuiwright::{Key, Page, SpawnConfig};

pub static CLEANUP_FAILED: AtomicBool = AtomicBool::new(false);
static CLEANUP_EVENTS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());

pub fn record_cleanup(value: serde_json::Value) {
    let mut events = CLEANUP_EVENTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if events.len() >= 128 {
        CLEANUP_FAILED.store(true, Ordering::SeqCst);
    } else {
        events.push(value);
    }
}

pub fn take_cleanup_events() -> Vec<serde_json::Value> {
    std::mem::take(
        &mut *CLEANUP_EVENTS
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct ExitObservation {
    pub pid: u32,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub terminal_restored: bool,
    pub reaped: bool,
}

pub struct Session {
    page: Option<Page>,
    pid: Pid,
    pidfd: OwnedFd,
    slave: Option<File>,
    before: Option<Termios>,
    settled: bool,
    pub permitted_at: Instant,
}

pub fn children() -> Result<BTreeSet<i32>> {
    std::fs::read_to_string("/proc/thread-self/children")?
        .split_whitespace()
        .map(|value| value.parse().map_err(Into::into))
        .collect()
}

impl Session {
    pub fn start(binary: &Path, args: &[String], nonce_override: Option<&str>) -> Result<Self> {
        let rendezvous = tempfile::Builder::new().prefix("btw-").tempdir()?;
        let socket_path = rendezvous.path().join("launch");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let nonce = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        // Guard exists even if Tuiwright returns an error after native spawn.
        let mut pending = crate::custody::Pending::new(children()?);
        let config = SpawnConfig::new(std::env::current_exe()?.to_string_lossy())
            .args([
                "--launch".to_string(),
                socket_path.to_string_lossy().into_owned(),
                nonce_override.unwrap_or(&nonce).to_owned(),
                std::process::id().to_string(),
                binary.to_string_lossy().into_owned(),
            ])
            .args(args.iter().cloned())
            .size(120, 30)
            .scrollback(100)
            .timeout(Duration::from_secs(5));
        let spawned = Page::spawn(config);
        let spawn_error = spawned.as_ref().err().map(|error| format!("{error:#}"));
        pending.page = spawned.ok();
        // Only this thread spawns children here; even an error after native spawn
        // must retain the newly created direct child until reconciliation.
        let added = pending.added()?;
        ensure!(added.len() <= 1, "LAUNCH_CUSTODY_AMBIGUOUS");
        let Some(raw_pid) = added.first() else {
            bail!("LAUNCH_CHILD_UNOBSERVED: {spawn_error:?}");
        };
        ensure!(
            nonce_override != Some("fault-after-page"),
            "INJECTED_AFTER_PAGE_FAILURE"
        );
        let pid = Pid::from_raw(*raw_pid).context("LAUNCH_PID_INVALID")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).context("LAUNCH_PIDFD_UNAVAILABLE")?;
        let mut session = Self {
            page: pending.page.take(),
            pid,
            pidfd,
            slave: None,
            before: None,
            settled: false,
            permitted_at: Instant::now(),
        };
        pending.disarmed = true;
        ensure!(
            session.page.is_some(),
            "PAGE_SPAWN_FAILED_AFTER_CHILD: {spawn_error:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(Instant::now() < deadline, "LAUNCH_HANDSHAKE_TIMEOUT");
                    ensure!(session.running()?, "LAUNCH_EXITED_BEFORE_HANDSHAKE");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let peer = socket_peercred(&stream)?;
        ensure!(
            peer.pid == pid && peer.uid == getuid(),
            "LAUNCH_PEER_MISMATCH"
        );
        let mut line = String::new();
        BufReader::new((&stream).take(128)).read_line(&mut line)?;
        ensure!(line == format!("{nonce}\n"), "LAUNCH_NONCE_MISMATCH");
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
            .open(format!("/proc/{}/fd/0", pid.as_raw_pid()))?;
        session.before = Some(tcgetattr(&slave)?);
        session.slave = Some(slave);
        session.permitted_at = Instant::now();
        stream.write_all(b"GO\n")?;
        Ok(session)
    }

    pub fn page(&self) -> &Page {
        self.page.as_ref().expect("live session Page")
    }
    pub fn pid(&self) -> u32 {
        self.pid.as_raw_pid() as u32
    }

    pub fn running(&self) -> Result<bool> {
        Ok(waitid(
            WaitId::PidFd(self.pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
        )?
        .is_none())
    }

    pub fn wait_text(&self, text: &str) -> Result<Duration> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.page().screen().contains_text(text) {
                return Ok(self.permitted_at.elapsed());
            }
            ensure!(self.running()?, "PROCESS_EXITED_BEFORE_TEXT: {text}");
            ensure!(Instant::now() < deadline, "SCREEN_TIMEOUT: {text}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn detach(&mut self) -> Result<ExitObservation> {
        self.page().press(Key::Ctrl('c'))?;
        let observation = self.finish(false)?;
        ensure!(
            observation.code == Some(0),
            "DETACH_NONZERO: {observation:?}"
        );
        ensure!(observation.terminal_restored, "TERMINAL_NOT_RESTORED");
        Ok(observation)
    }

    pub fn finish(&mut self, terminate: bool) -> Result<ExitObservation> {
        if terminate {
            match pidfd_send_signal(&self.pidfd, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => (),
                Err(error) => return Err(error.into()),
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = waitid(
                WaitId::PidFd(self.pidfd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
            )? {
                break status;
            }
            ensure!(Instant::now() < deadline, "TERMINATION_UNOBSERVED");
            std::thread::sleep(Duration::from_millis(2));
        };
        let restoration = self
            .slave
            .as_ref()
            .zip(self.before.as_ref())
            .map(|(slave, before)| tcgetattr(slave).map(|after| terminal_equal(&after, before)))
            .transpose();
        self.slave.take();
        // Zombie is still reserved. Pinned portable-pty Drop may reap here.
        drop(self.page.take());
        match waitid(
            WaitId::PidFd(self.pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
        ) {
            Ok(Some(reaped)) => ensure!(
                reaped.exit_status() == status.exit_status()
                    && reaped.terminating_signal() == status.terminating_signal(),
                "REAP_STATUS_CHANGED"
            ),
            Err(rustix::io::Errno::CHILD) => (), // Only after our exact WNOWAIT observation and Page Drop.
            other => bail!("REAP_UNOBSERVED: {other:?}"),
        }
        self.settled = true;
        record_cleanup(
            serde_json::json!({"kind":"process_settlement","pid":self.pid(),
            "code":status.exit_status(),"signal":status.terminating_signal(),"reaped":true,
            "termination_requested":terminate,
            "terminal_restored":match &restoration { Ok(Some(value)) => *value, _ => false },
            "terminal_read_error":restoration.as_ref().err().map(ToString::to_string)}),
        );
        let restored = restoration?.unwrap_or(false);
        Ok(ExitObservation {
            pid: self.pid.as_raw_pid() as u32,
            code: status.exit_status(),
            signal: status.terminating_signal(),
            terminal_restored: restored,
            reaped: true,
        })
    }
}

fn terminal_equal(after: &Termios, before: &Termios) -> bool {
    let codes = [
        Cc::VINTR,
        Cc::VQUIT,
        Cc::VERASE,
        Cc::VKILL,
        Cc::VEOF,
        Cc::VTIME,
        Cc::VMIN,
        Cc::VSWTC,
        Cc::VSTART,
        Cc::VSTOP,
        Cc::VSUSP,
        Cc::VEOL,
        Cc::VREPRINT,
        Cc::VDISCARD,
        Cc::VWERASE,
        Cc::VLNEXT,
        Cc::VEOL2,
    ];
    after.local_modes == before.local_modes
        && after.input_modes == before.input_modes
        && after.output_modes == before.output_modes
        && after.control_modes == before.control_modes
        && after.line_discipline == before.line_discipline
        && after.input_speed() == before.input_speed()
        && after.output_speed() == before.output_speed()
        && codes
            .into_iter()
            .all(|code| after.special_codes[code] == before.special_codes[code])
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.settled {
            if let Some(page) = &self.page {
                let screen = page.screen();
                record_cleanup(serde_json::json!({"kind":"failure_screen","pid":self.pid(),
                    "text":screen.plain_text(),"cols":screen.cols,"rows":screen.rows,"screen_hash":screen.stable_hash()}));
            }
            if let Err(error) = self.finish(true) {
                CLEANUP_FAILED.store(true, Ordering::SeqCst);
                if let Some(page) = self.page.take() {
                    std::mem::forget(page);
                }
                record_cleanup(
                    serde_json::json!({"kind":"unresolved_process_custody","pid":self.pid(),"error":format!("{error:#}")}),
                );
                eprintln!(
                    "TUIWRIGHT_CUSTODY_UNRESOLVED: pid={}",
                    self.pid.as_raw_pid()
                );
            }
        }
    }
}
