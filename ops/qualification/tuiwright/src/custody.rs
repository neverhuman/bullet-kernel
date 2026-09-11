//! Real failure scenarios for the harness's direct-child custody adapter.
use crate::{
    evidence::Evidence,
    session::{children, record_cleanup, Session, CLEANUP_FAILED},
};
use anyhow::{bail, ensure, Context, Result};
use rustix::fd::{AsFd, OwnedFd};
use rustix::process::{
    pidfd_open, pidfd_send_signal, waitid, Pid, PidfdFlags, Signal, WaitId, WaitIdOptions,
    WaitIdStatus,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tuiwright::Page;

pub const IDENTITIES: [&str; 8] = [
    "custody_nonce_rejection",
    "custody_after_page_failure",
    "custody_exec_failure",
    "custody_nonzero_exit",
    "custody_detach_timeout",
    "custody_partial_terminal_restore",
    "custody_parent_death",
    "custody_normal_detach",
];

/// Source-pinned Page may exist even after a partial setup failure. No GO was
/// issued. Never reap these children before dropping its private Child handle.
pub struct Pending {
    before: BTreeSet<i32>,
    pub page: Option<Page>,
    pub disarmed: bool,
}

impl Pending {
    pub fn new(before: BTreeSet<i32>) -> Self {
        Self {
            before,
            page: None,
            disarmed: false,
        }
    }
    pub fn added(&self) -> Result<Vec<i32>> {
        Ok(children()?.difference(&self.before).copied().collect())
    }
    fn cleanup(&mut self) -> Result<()> {
        let added = self.added()?;
        ensure!(
            !added.is_empty() || self.page.is_none(),
            "PENDING_CHILD_UNOBSERVED"
        );
        let handles = added
            .iter()
            .map(|pid| {
                pidfd_open(
                    Pid::from_raw(*pid).context("PENDING_PID_INVALID")?,
                    PidfdFlags::empty(),
                )
                .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        for fd in &handles {
            match pidfd_send_signal(fd, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => (),
                Err(error) => return Err(error.into()),
            }
        }
        let statuses = handles
            .iter()
            .map(|fd| observe(fd, true))
            .collect::<Result<Vec<_>>>()?;
        drop(self.page.take());
        for fd in &handles {
            match waitid(
                WaitId::PidFd(fd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
            ) {
                Ok(Some(_)) | Err(rustix::io::Errno::CHILD) => (),
                other => bail!("PENDING_REAP_UNOBSERVED: {other:?}"),
            }
        }
        for (pid, status) in added.iter().zip(statuses) {
            record_cleanup(json!({"kind":"preconstruction_cleanup","pid":pid,
                "code":status.exit_status(),"signal":status.terminating_signal(),"reaped":true}));
        }
        Ok(())
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.disarmed {
            if let Err(error) = self.cleanup() {
                CLEANUP_FAILED.store(true, Ordering::SeqCst);
                if let Some(page) = self.page.take() {
                    std::mem::forget(page);
                }
                record_cleanup(
                    json!({"kind":"unresolved_preconstruction_custody","error":format!("{error:#}")}),
                );
                eprintln!("PENDING_CUSTODY_UNRESOLVED: {error:#}");
            }
        }
    }
}

fn observe(fd: &OwnedFd, retain: bool) -> Result<WaitIdStatus> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let options = WaitIdOptions::EXITED
        | WaitIdOptions::NOHANG
        | if retain {
            WaitIdOptions::NOWAIT
        } else {
            WaitIdOptions::empty()
        };
    loop {
        if let Some(status) = waitid(WaitId::PidFd(fd.as_fd()), options)? {
            return Ok(status);
        }
        ensure!(Instant::now() < deadline, "CUSTODY_EXIT_TIMEOUT");
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub fn run(id: &str, evidence: &mut Evidence) -> Result<()> {
    let before = children()?;
    let executable = std::env::current_exe()?;
    let probe_args = |mode: &str| vec!["--probe".to_owned(), mode.to_owned()];
    match id {
        "custody_nonce_rejection" | "custody_after_page_failure" => {
            let nonce = if id == "custody_nonce_rejection" {
                "wrong-nonce"
            } else {
                "fault-after-page"
            };
            let result = Session::start(&executable, &probe_args("detach"), Some(nonce));
            let error = match result {
                Err(error) => error,
                Ok(_) => bail!("INJECTED_FAILURE_ACCEPTED"),
            };
            let reason = if id == "custody_nonce_rejection" {
                "LAUNCH_NONCE_MISMATCH"
            } else {
                "INJECTED_AFTER_PAGE_FAILURE"
            };
            ensure!(
                format!("{error:#}").contains(reason),
                "WRONG_REFUSAL: {error:#}"
            );
            evidence.event(id, "expected_refusal", json!({"reason":reason}))?;
        }
        "custody_exec_failure" => {
            let directory = tempfile::tempdir()?;
            let mut session = Session::start(&directory.path().join("absent"), &[], None)?;
            let exit = session.finish(false)?;
            ensure!(exit.code == Some(1), "EXEC_FAILURE_NOT_OBSERVED");
            evidence.event(id, "observed_exit", serde_json::to_value(exit)?)?;
        }
        "custody_nonzero_exit" => {
            let mut session = Session::start(&executable, &probe_args("exit-19"), None)?;
            let exit = session.finish(false)?;
            ensure!(exit.code == Some(19), "NONZERO_EXIT_LOST");
            evidence.event(id, "observed_exit", serde_json::to_value(exit)?)?;
        }
        "custody_detach_timeout" => {
            let mut session = Session::start(&executable, &probe_args("idle"), None)?;
            session.wait_text("HARNESS PROCESS FIXTURE")?;
            let error = session.detach().expect_err("idle fixture must not detach");
            ensure!(
                format!("{error:#}").contains("TERMINATION_UNOBSERVED"),
                "WRONG_TIMEOUT"
            );
            let exit = session.finish(true)?;
            ensure!(
                exit.signal == Some(Signal::KILL.as_raw()),
                "FORCED_TERMINATION_NOT_OBSERVED"
            );
            evidence.event(id, "observed_forced_exit", serde_json::to_value(exit)?)?;
        }
        "custody_partial_terminal_restore" | "custody_normal_detach" => {
            let mode = if id == "custody_normal_detach" {
                "detach"
            } else {
                "partial-restore"
            };
            let mut session = Session::start(&executable, &probe_args(mode), None)?;
            session.wait_text("HARNESS PROCESS FIXTURE")?;
            if mode == "detach" {
                evidence.event(
                    id,
                    "observed_exit",
                    serde_json::to_value(session.detach()?)?,
                )?;
            } else {
                let error = session
                    .detach()
                    .expect_err("altered special code must refuse restoration");
                ensure!(
                    format!("{error:#}").contains("TERMINAL_NOT_RESTORED"),
                    "WRONG_RESTORATION_REFUSAL"
                );
                evidence.event(
                    id,
                    "expected_refusal",
                    json!({"reason":"TERMINAL_NOT_RESTORED","changed_field":"VERASE"}),
                )?;
            }
        }
        "custody_parent_death" => parent_death(evidence, id)?,
        _ => bail!("CUSTODY_CASE_UNKNOWN"),
    }
    ensure!(children()? == before, "CHILDREN_NOT_REAPED");
    ensure!(
        !CLEANUP_FAILED.load(Ordering::SeqCst),
        "CUSTODY_CLEANUP_FAILED"
    );
    evidence.event(id, "children_reaped", json!({"new_children_remaining":0}))?;
    Ok(())
}

pub fn parent_probe(path: &Path, parent: u32) -> Result<()> {
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))?;
    ensure!(
        rustix::process::getppid().map(|pid| pid.as_raw_pid() as u32) == Some(parent),
        "PARENT_PROBE_OWNER_CHANGED"
    );
    let session = Session::start(
        &std::env::current_exe()?,
        &["--probe".into(), "parent-death".into()],
        None,
    )?;
    session.wait_text("HARNESS PROCESS FIXTURE")?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", session.pid())?;
    file.sync_all()?;
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

struct Parent(Child);
impl Parent {
    fn terminate(&mut self) -> Result<std::process::ExitStatus> {
        if let Some(status) = self.0.try_wait()? {
            return Ok(status);
        }
        if let Err(error) = self.0.kill() {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            return Err(error.into());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            ensure!(Instant::now() < deadline, "PARENT_TERMINATION_UNOBSERVED");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        let status = self.terminate();
        if status.is_err() {
            CLEANUP_FAILED.store(true, Ordering::SeqCst);
        }
        let mut stderr = String::new();
        let diagnostic = (|| -> Result<()> {
            if let Some(pipe) = self.0.stderr.take() {
                rustix::fs::fcntl_setfl(
                    &pipe,
                    rustix::fs::fcntl_getfl(&pipe)? | rustix::fs::OFlags::NONBLOCK,
                )?;
                pipe.take(8192).read_to_string(&mut stderr)?;
            }
            Ok(())
        })();
        if diagnostic.is_err() {
            CLEANUP_FAILED.store(true, Ordering::SeqCst);
        }
        record_cleanup(json!({"kind":"parent_fixture_exit","pid":self.0.id(),
            "status":format!("{status:?}"),"stderr":stderr,
            "diagnostic_error":diagnostic.err().map(|error|format!("{error:#}"))}));
    }
}

fn parent_death(evidence: &mut Evidence, id: &str) -> Result<()> {
    struct Subreaper(Option<Pid>);
    impl Drop for Subreaper {
        fn drop(&mut self) {
            if rustix::process::set_child_subreaper(self.0).is_err() {
                CLEANUP_FAILED.store(true, Ordering::SeqCst);
            }
        }
    }
    let _restore = Subreaper(rustix::process::child_subreaper()?);
    rustix::process::set_child_subreaper(Pid::from_raw(1))?;
    // On any error, Parent drops first, then this guard reaps adopted children.
    let adopted = Pending::new(children()?);
    let directory = tempfile::tempdir()?;
    let pid_path = directory.path().join("child");
    let result = (|| -> Result<()> {
        let mut parent = Parent(
            Command::new(std::env::current_exe()?)
                .arg("--parent-probe")
                .arg(&pid_path)
                .arg(std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_path.exists() {
            ensure!(parent.0.try_wait()?.is_none(), "PARENT_PROBE_EARLY_EXIT");
            ensure!(Instant::now() < deadline, "PARENT_PROBE_READY_TIMEOUT");
            std::thread::sleep(Duration::from_millis(2));
        }
        let pid = Pid::from_raw(std::fs::read_to_string(&pid_path)?.trim().parse()?)
            .context("PARENT_CHILD_PID_INVALID")?;
        let fd = pidfd_open(pid, PidfdFlags::empty())?;
        let stat = std::fs::read_to_string(format!("/proc/{}/status", pid.as_raw_pid()))?;
        ensure!(
            stat.lines()
                .any(|line| line == format!("PPid:\t{}", parent.0.id())),
            "PARENT_RELATION_CHANGED"
        );
        let blocked = stat
            .lines()
            .find_map(|line| line.strip_prefix("SigBlk:\t"))
            .context("PARENT_CHILD_SIGNAL_MASK_UNOBSERVED")?;
        ensure!(
            u64::from_str_radix(blocked, 16)? & 1 == 1,
            "PARENT_CHILD_HUP_NOT_BLOCKED"
        );
        evidence.event(
            id,
            "child_hup_blocked",
            json!({"pid":pid.as_raw_pid(),"signal_mask":blocked}),
        )?;
        let parent_status = parent.terminate()?;
        let parent_signal = std::os::unix::process::ExitStatusExt::signal(&parent_status);
        evidence.event(
            id,
            "parent_killed",
            json!({"pid":parent.0.id(),"signal":parent_signal}),
        )?;
        ensure!(
            parent_signal == Some(Signal::KILL.as_raw()),
            "PARENT_KILL_NOT_OBSERVED"
        );
        let status = observe(&fd, false)?;
        evidence.event(
            id,
            "adopted_child_reaped",
            json!({"pid":pid.as_raw_pid(),"signal":status.terminating_signal(),"exit_code":status.exit_status()}),
        )?;
        ensure!(
            status.terminating_signal() == Some(Signal::KILL.as_raw()),
            "PARENT_DEATH_CHILD_SURVIVED"
        );
        Ok(())
    })();
    drop(adopted);
    result
}
