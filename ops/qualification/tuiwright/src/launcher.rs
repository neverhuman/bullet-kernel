//! Private direct-exec launcher. It never launches providers or another daemon.
use anyhow::{bail, ensure, Context, Result};
use rustix::process::{getppid, set_parent_process_death_signal, Signal};
use rustix::termios::{tcgetattr, tcsetattr, OptionalActions, SpecialCodeIndex};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

pub fn run(args: &[String]) -> Result<()> {
    ensure!(args.len() >= 4, "LAUNCH_ARGUMENTS_INVALID");
    let parent: u32 = args[2].parse().context("LAUNCH_PARENT_INVALID")?;
    set_parent_process_death_signal(Some(Signal::KILL))?;
    ensure!(
        getppid().map(|pid| pid.as_raw_pid() as u32) == Some(parent),
        "LAUNCH_PARENT_CHANGED"
    );
    let mut socket = UnixStream::connect(&args[0]).context("LAUNCH_RENDEZVOUS_FAILED")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    writeln!(socket, "{}", args[1])?;
    let mut go = [0u8; 3];
    socket
        .read_exact(&mut go)
        .context("LAUNCH_PERMISSION_UNOBSERVED")?;
    ensure!(&go == b"GO\n", "LAUNCH_PERMISSION_INVALID");
    ensure!(
        getppid().map(|pid| pid.as_raw_pid() as u32) == Some(parent),
        "LAUNCH_PARENT_CHANGED"
    );
    drop(socket);
    let error = Command::new(&args[3])
        .args(&args[4..])
        .env_clear()
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("LC_ALL", "C.UTF-8")
        .exec();
    Err(error).context("LAUNCH_EXEC_FAILED")
}

/// Explicit harness fixture for lifecycle faults, never product evidence.
pub fn probe(args: &[String]) -> Result<()> {
    let mode = args.first().map(String::as_str).unwrap_or("detach");
    if mode == "exit-19" {
        std::process::exit(19);
    }
    if mode == "parent-death" {
        // portable-pty clears the mask before exec. Isolate this child fixture
        // here, after exec, so PTY hangup cannot satisfy parent-death SIGKILL.
        let mut blocked = nix::sys::signal::SigSet::empty();
        blocked.add(nix::sys::signal::Signal::SIGHUP);
        blocked.thread_block()?;
        ensure!(
            nix::sys::signal::SigSet::thread_get_mask()?.contains(nix::sys::signal::Signal::SIGHUP),
            "PARENT_CHILD_HUP_NOT_BLOCKED"
        );
    }
    let stdin = std::io::stdin();
    let before = tcgetattr(&stdin)?;
    let mut raw = before.clone();
    raw.make_raw();
    tcsetattr(&stdin, OptionalActions::Now, &raw)?;
    println!("HARNESS PROCESS FIXTURE");
    std::io::stdout().flush()?;
    if mode == "parent-death" {
        // Closing the parent's PTY can make terminal reads/restoration fail
        // before PDEATHSIG is delivered. This probe must remain alive until
        // the death signal itself, not exit through a competing I/O failure.
        loop {
            std::thread::park();
        }
    }
    let result = (|| -> Result<()> {
        let mut input = stdin.lock();
        let mut byte = [0];
        loop {
            input.read_exact(&mut byte)?;
            if byte[0] == 3 && !matches!(mode, "idle" | "parent-death") {
                return Ok(());
            }
            if byte[0] == b'!' {
                bail!("HARNESS_EXPLICIT_FAILURE");
            }
        }
    })();
    let mut restored = before;
    if mode == "partial-restore" {
        restored.special_codes[SpecialCodeIndex::VERASE] ^= 1;
    }
    tcsetattr(&stdin, OptionalActions::Now, &restored)?;
    result
}
