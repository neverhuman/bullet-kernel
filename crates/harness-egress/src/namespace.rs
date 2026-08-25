//! Tool discovery and the user+network namespace holder with a `slirp4netns`
//! uplink. Everything is driven through the util-linux, slirp4netns, and
//! nftables binaries (no unsafe): the holder is `unshare -Urn cat` reading a
//! pipe held by this process, so it dies with the parent even on SIGKILL;
//! commands enter the namespace via `nsenter --preserve-credentials -U -n`.

use crate::error::{EgressCode, EgressError};
use crate::tools::Tooling;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// slirp4netns gateway: the host as seen from inside the namespace.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
/// slirp4netns built-in DNS forwarder address (blocked by the ruleset).
pub const GUEST_DNS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
/// Uplink device name inside the namespace.
pub const TAP_DEVICE: &str = "tap0";
/// Uplink MTU.
pub const MTU: u32 = 65520;
/// Namespace backend recorded in receipts.
pub const BACKEND: &str = "unshare";

const HOLDER_TIMEOUT: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const TEARDOWN_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(20);

/// Captured output of one in-namespace command.
#[derive(Clone, Debug, Default)]
pub struct Captured {
    /// Exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Whether the deadline killed it.
    pub timed_out: bool,
    /// Stdout bytes.
    pub stdout: Vec<u8>,
    /// Stderr bytes.
    pub stderr: Vec<u8>,
}

/// Live namespace: holder process, uplink, and the process group they share.
pub struct Namespace {
    tools: Arc<Tooling>,
    holder: Child,
    holder_stdin: Option<ChildStdin>,
    slirp: Option<Child>,
    slirp_stdin: Option<ChildStdin>,
    pgid: u32,
}

impl Namespace {
    /// Spawn `unshare -Urn cat` in a fresh process group and wait until its
    /// network namespace differs from ours.
    ///
    /// # Errors
    ///
    /// `EGRESS_NAMESPACE_FAILED` (holder exited or never changed namespace) or
    /// `EGRESS_IO_FAILED` for spawn/pipe failures.
    pub fn create(tools: Arc<Tooling>, workdir: &Path) -> Result<Self, EgressError> {
        let stderr = File::create(workdir.join("holder.stderr"))
            .map_err(|err| EgressError::io("holder stderr", &err))?;
        let mut holder = Command::new(&tools.unshare.path)
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "--",
                tools.cat.path.as_str(),
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .map_err(|err| EgressError::io("spawn unshare holder", &err))?;
        let holder_stdin = holder.stdin.take();
        let pgid = holder.id();
        let own = fs::read_link("/proc/self/ns/net")
            .map_err(|err| EgressError::io("read own netns", &err))?;
        let deadline = Instant::now() + HOLDER_TIMEOUT;
        loop {
            if let Ok(Some(status)) = holder.try_wait() {
                let detail = fs::read_to_string(workdir.join("holder.stderr")).unwrap_or_default();
                return Err(EgressError::new(
                    EgressCode::NamespaceFailed,
                    format!("holder exited early ({status}): {}", detail.trim()),
                ));
            }
            if fs::read_link(format!("/proc/{pgid}/ns/net")).is_ok_and(|link| link != own) {
                break;
            }
            if Instant::now() > deadline {
                let _ = holder.kill();
                let _ = holder.wait();
                return Err(EgressError::new(
                    EgressCode::NamespaceFailed,
                    "holder never entered a new network namespace",
                ));
            }
            thread::sleep(POLL);
        }
        Ok(Self {
            tools,
            holder,
            holder_stdin,
            slirp: None,
            slirp_stdin: None,
            pgid,
        })
    }

    /// Attach `slirp4netns --configure` and wait for its ready byte.
    ///
    /// # Errors
    ///
    /// `EGRESS_UPLINK_FAILED` when slirp4netns exits or never signals ready.
    pub fn attach_uplink(&mut self, workdir: &Path) -> Result<(), EgressError> {
        let stderr_path = workdir.join("slirp4netns.stderr");
        let stderr = File::create(&stderr_path)
            .map_err(|err| EgressError::io("slirp4netns stderr", &err))?;
        let pid = self.pgid.to_string();
        let mut slirp = Command::new(&self.tools.slirp4netns.path)
            .args([
                "--configure",
                "--mtu",
                &MTU.to_string(),
                "--ready-fd",
                "1",
                "--exit-fd",
                "0",
            ])
            .arg(&pid)
            .arg(TAP_DEVICE)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .process_group(pgid_arg(self.pgid))
            .spawn()
            .map_err(|err| EgressError::io("spawn slirp4netns", &err))?;
        self.slirp_stdin = slirp.stdin.take();
        let Some(mut stdout) = slirp.stdout.take() else {
            return Err(EgressError::new(
                EgressCode::UplinkFailed,
                "no slirp4netns stdout",
            ));
        };
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = tx.send(stdout.read(&mut byte).map(|n| (n, byte[0])));
        });
        let ready = matches!(rx.recv_timeout(READY_TIMEOUT), Ok(Ok((1, b'1'))));
        if !ready {
            let _ = slirp.kill();
            let _ = slirp.wait();
            let detail = fs::read_to_string(&stderr_path).unwrap_or_default();
            return Err(EgressError::new(
                EgressCode::UplinkFailed,
                format!(
                    "slirp4netns not ready within {READY_TIMEOUT:?}: {}",
                    detail.trim()
                ),
            ));
        }
        self.slirp = Some(slirp);
        Ok(())
    }

    /// Holder pid (the target for `nsenter`).
    #[must_use]
    pub const fn holder_pid(&self) -> u32 {
        self.pgid
    }

    /// slirp4netns pid once attached.
    #[must_use]
    pub fn slirp_pid(&self) -> Option<u32> {
        self.slirp.as_ref().map(Child::id)
    }

    /// Process group shared by the holder, the uplink, and entered commands.
    #[must_use]
    pub const fn pgid(&self) -> u32 {
        self.pgid
    }

    /// Command that runs `program` inside the namespace, in the sandbox
    /// process group. Environment is left for the caller to set.
    pub fn enter(&self, program: &OsStr) -> Command {
        let mut cmd = Command::new(&self.tools.nsenter.path);
        cmd.args(["--preserve-credentials", "--user", "--net", "--target"])
            .arg(self.pgid.to_string())
            .arg("--")
            .arg(program)
            .process_group(pgid_arg(self.pgid));
        cmd
    }

    /// Run a tool inside the namespace with a minimal environment, feeding
    /// `stdin` and capturing output, killing it at `timeout`.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` when the process cannot be spawned or piped.
    pub fn run_captured(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Captured, EgressError> {
        let mut cmd = self.enter(OsStr::new(program));
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|err| EgressError::io(&format!("spawn {program} in namespace"), &err))?;
        if let Some(mut input) = child.stdin.take() {
            if let Some(bytes) = stdin {
                let _ = input.write_all(bytes);
            }
        }
        let stdout = reader_thread(child.stdout.take());
        let stderr = reader_thread(child.stderr.take());
        let deadline = Instant::now() + timeout;
        let mut captured = Captured::default();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    captured.code = status.code();
                    break;
                }
                Ok(None) if Instant::now() > deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    captured.timed_out = true;
                    break;
                }
                Ok(None) => thread::sleep(POLL),
                Err(err) => return Err(EgressError::io("wait in-namespace command", &err)),
            }
        }
        captured.stdout = stdout.join().unwrap_or_default();
        captured.stderr = stderr.join().unwrap_or_default();
        Ok(captured)
    }

    /// Signal the whole process group.
    fn signal_group(&self, signal: &str) {
        let _ = Command::new(&self.tools.kill.path)
            .args(["-s", signal, "--", &format!("-{}", self.pgid)])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Close the holder/uplink pipes (EOF), TERM then KILL the process group,
    /// and reap both children.
    pub fn teardown(&mut self) {
        drop(self.holder_stdin.take());
        drop(self.slirp_stdin.take());
        self.signal_group("TERM");
        let deadline = Instant::now() + TEARDOWN_GRACE;
        loop {
            let holder_done = matches!(self.holder.try_wait(), Ok(Some(_)));
            let slirp_done = self
                .slirp
                .as_mut()
                .is_none_or(|child| matches!(child.try_wait(), Ok(Some(_))));
            if (holder_done && slirp_done) || Instant::now() > deadline {
                break;
            }
            thread::sleep(POLL);
        }
        self.signal_group("KILL");
        let _ = self.holder.kill();
        let _ = self.holder.wait();
        if let Some(mut slirp) = self.slirp.take() {
            let _ = slirp.kill();
            let _ = slirp.wait();
        }
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn pgid_arg(pgid: u32) -> i32 {
    i32::try_from(pgid).unwrap_or(0)
}

fn reader_thread<R: Read + Send + 'static>(source: Option<R>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(reader) = source {
            let _ = reader.take(1024 * 1024).read_to_end(&mut buf);
        }
        buf
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgid_arg_never_panics() {
        assert_eq!(pgid_arg(42), 42);
        assert_eq!(pgid_arg(u32::MAX), 0);
    }
}
