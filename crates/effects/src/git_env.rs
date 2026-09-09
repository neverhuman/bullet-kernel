//! Hardened git invocations for forge pushes and read-backs.
//!
//! Small mirror of BulletGit's `SafeGit` environment policy
//! (bullet-git/crates/bullet-git-workspace/src/safe_git.rs): the child
//! environment is cleared (stripping every inherited `GIT_*` variable) and
//! rebuilt with prompts, credentials, global/system config, and hooks all
//! disabled. The effects crate carries its own copy until a tag-pinned
//! consumption of BulletGit exists.

use crate::error::EffectsError;
use std::path::Path;
use std::process::Command;

/// Build a hardened git command, optionally rooted at `repo`.
#[must_use]
pub fn hardened_git(repo: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_SSH_COMMAND", "false")
        .env("LC_ALL", "C");
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("credential.helper=");
    if let Some(repo) = repo {
        cmd.arg("-C").arg(repo);
    }
    cmd
}

/// Run a hardened git command, returning exit code, stdout, and stderr.
///
/// # Errors
///
/// Returns `IO_FAILED` when the process cannot be spawned.
pub fn run_git(repo: Option<&Path>, args: &[&str]) -> Result<(i32, String, String), EffectsError> {
    let mut cmd = hardened_git(repo);
    cmd.args(args);
    let out = cmd
        .output()
        .map_err(|err| EffectsError::Io(format!("spawn git: {err}")))?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}
