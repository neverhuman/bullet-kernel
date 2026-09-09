//! Hardened git command builder for the clean-room clone.
//!
//! Self-contained mirror of BulletGit's `SafeGit`
//! (bullet-git/crates/bullet-git-workspace/src/safe_git.rs); the verifier
//! carries its own copy until a tag-pinned consumption of that crate
//! exists. The child environment is cleared (which strips every inherited
//! `GIT_*` variable) and rebuilt with: per-run `HOME`/`XDG_CONFIG_HOME`,
//! `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_TERMINAL_PROMPT=0`, `GIT_SSH_COMMAND=false`, and hooks disabled via
//! `-c core.hooksPath=<empty dir>`.

use crate::error::{io_err, VerifierError};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Builds git commands with a fully isolated environment.
#[derive(Debug)]
pub struct HostileGit {
    home_dir: PathBuf,
    xdg_config_dir: PathBuf,
    hooks_dir: PathBuf,
}

impl HostileGit {
    /// Prepare the isolation directories under `runtime_dir`.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` when the runtime directories cannot be created.
    pub fn new(runtime_dir: &Path) -> Result<Self, VerifierError> {
        let home_dir = runtime_dir.join("home");
        let xdg_config_dir = runtime_dir.join("xdg-config");
        let hooks_dir = runtime_dir.join("hooks-empty");
        for dir in [&home_dir, &xdg_config_dir, &hooks_dir] {
            fs::create_dir_all(dir).map_err(|err| io_err("create runtime dir", &err))?;
        }
        Ok(Self {
            home_dir,
            xdg_config_dir,
            hooks_dir,
        })
    }

    /// Build a hardened git command. `allow_local_transport` is passed only
    /// by the clone call; every other invocation denies the file transport.
    #[must_use]
    pub fn command(&self, repo: Option<&Path>, allow_local_transport: bool) -> Command {
        let mut cmd = Command::new("git");
        cmd.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("HOME", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("GIT_SSH_COMMAND", "false")
            .env("LC_ALL", "C");
        let allow = if allow_local_transport {
            "user"
        } else {
            "never"
        };
        cmd.arg("-c")
            .arg(format!("core.hooksPath={}", self.hooks_dir.display()))
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg(format!("protocol.file.allow={allow}"));
        if let Some(repo) = repo {
            cmd.arg("-C").arg(repo);
        }
        cmd
    }

    /// Run a git command that must succeed; returns trimmed stdout.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` on a nonzero exit, `IO_FAILED` when the process
    /// cannot be spawned.
    pub fn run(
        &self,
        repo: Option<&Path>,
        allow_local_transport: bool,
        args: &[&str],
    ) -> Result<String, VerifierError> {
        let mut cmd = self.command(repo, allow_local_transport);
        cmd.args(args);
        let out = cmd.output().map_err(|err| io_err("spawn git", &err))?;
        if !out.status.success() {
            return Err(VerifierError::Git {
                op: args.first().copied().unwrap_or("git").to_string(),
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Run a git probe where a nonzero exit is a legitimate answer.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` only when the process cannot be spawned.
    pub fn probe(&self, repo: Option<&Path>, args: &[&str]) -> Result<bool, VerifierError> {
        let mut cmd = self.command(repo, false);
        cmd.args(args);
        let out = cmd
            .output()
            .map_err(|err| io_err("spawn git probe", &err))?;
        Ok(out.status.success())
    }
}
