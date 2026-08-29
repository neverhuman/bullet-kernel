//! Descriptor-bound Linux gate working directories.

use crate::error::RunnerError;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
const INSPECT_OUTPUT_LIMIT: usize = 4096;

/// Open directory identity retained until the gate child has changed cwd.
pub(crate) struct GateWorkdir {
    _directory: File,
    spawn_path: PathBuf,
}

impl GateWorkdir {
    pub(super) fn open(path: &Path) -> Result<Self, RunnerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(gate_error(
                "descriptor-bound gate cwd is unsupported outside Linux",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{open, Mode, OFlags};

            let descriptor = open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| gate_error(format!("open gate cwd without symlinks: {error}")))?;
            let directory = File::from(descriptor);
            Self::from_file(directory)
        }
    }

    pub(crate) fn from_file(directory: File) -> Result<Self, RunnerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            return Err(gate_error(
                "descriptor-bound gate cwd is unsupported outside Linux",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let spawn_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            if !spawn_path.is_dir() {
                return Err(gate_error("gate cwd procfd is unavailable"));
            }
            Ok(Self {
                _directory: directory,
                spawn_path,
            })
        }
    }

    pub(super) fn spawn_path(&self) -> &Path {
        &self.spawn_path
    }

    /// Verify that this exact opened worktree equals its checkpoint Git tree.
    pub(crate) async fn verify_git_tree(&self, expected: &str) -> Result<(), RunnerError> {
        #[cfg(not(target_os = "linux"))]
        return Err(gate_error(
            "descriptor-bound Git inspection is unsupported outside Linux",
        ));
        #[cfg(target_os = "linux")]
        let git_dir = {
            use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};

            let resolve = ResolveFlags::BENEATH
                .union(ResolveFlags::NO_SYMLINKS)
                .union(ResolveFlags::NO_MAGICLINKS);
            openat2(
                &self._directory,
                ".git",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            )
            .map(File::from)
            .map_err(|error| gate_error(format!("open exact workspace Git directory: {error}")))?
        };
        let private = tempfile::Builder::new()
            .prefix("bullet-gate-index-")
            .tempdir()
            .map_err(|error| gate_error(format!("create private gate index: {error}")))?;
        let private_index = private.path().join("index");
        let expected_hex = expected
            .strip_prefix("sha1:")
            .or_else(|| expected.strip_prefix("sha256:"))
            .ok_or_else(|| gate_error("checkpoint Git tree lacks an admitted algorithm tag"))?;
        self.git_success(
            &git_dir,
            &private_index,
            &["read-tree", "--reset", expected_hex],
        )
        .await?;
        self.git_success(
            &git_dir,
            &private_index,
            &[
                "update-index",
                "--refresh",
                "--unmerged",
                "--ignore-missing",
            ],
        )
        .await?;
        self.git_success(
            &git_dir,
            &private_index,
            &[
                "diff-files",
                "--quiet",
                "--no-ext-diff",
                "--ignore-submodules=none",
                "--",
            ],
        )
        .await?;
        let untracked = self
            .git_output(&git_dir, &private_index, &["ls-files", "--others", "-z"])
            .await?;
        if !untracked.is_empty() {
            return Err(gate_error("opened workspace contains untracked bytes"));
        }
        Ok(())
    }

    async fn git_success(
        &self,
        git_dir: &File,
        private_index: &Path,
        args: &[&str],
    ) -> Result<(), RunnerError> {
        let output = self.git(git_dir, private_index, args).await?;
        if !output.status.success() {
            return Err(gate_error(format!(
                "workspace Git inspection {args:?} failed with {:?}",
                output.status.code()
            )));
        }
        Ok(())
    }

    async fn git_output(
        &self,
        git_dir: &File,
        private_index: &Path,
        args: &[&str],
    ) -> Result<String, RunnerError> {
        let output = self.git(git_dir, private_index, args).await?;
        if !output.status.success() {
            return Err(gate_error(format!(
                "workspace Git inspection {args:?} failed with {:?}",
                output.status.code()
            )));
        }
        if output.stdout.len() > INSPECT_OUTPUT_LIMIT || output.stderr.len() > INSPECT_OUTPUT_LIMIT
        {
            return Err(gate_error("workspace Git inspection output exceeded limit"));
        }
        String::from_utf8(output.stdout)
            .map_err(|error| gate_error(format!("workspace Git inspection output: {error}")))
    }

    async fn git(
        &self,
        git_dir: &File,
        private_index: &Path,
        args: &[&str],
    ) -> Result<std::process::Output, RunnerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (git_dir, private_index, args);
            return Err(gate_error(
                "descriptor-bound Git inspection is unsupported outside Linux",
            ));
        }
        #[cfg(target_os = "linux")]
        let (git_dir_path, work_tree_path) = {
            let process = std::process::id();
            (
                format!("/proc/{process}/fd/{}", git_dir.as_raw_fd()),
                format!("/proc/{process}/fd/{}", self._directory.as_raw_fd()),
            )
        };
        let child = tokio::process::Command::new("/usr/bin/git")
            .args([
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.sparseCheckout=false",
                "-c",
                "index.sparse=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "diff.external=",
                "-c",
                "diff.trustExitCode=false",
            ])
            .args(args)
            .current_dir(self.spawn_path())
            .env_clear()
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_DIR", git_dir_path)
            .env("GIT_WORK_TREE", work_tree_path)
            .env("GIT_INDEX_FILE", private_index)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| gate_error(format!("spawn workspace Git inspection: {error}")))?;
        tokio::time::timeout(INSPECT_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| gate_error("workspace Git inspection timed out"))?
            .map_err(|error| gate_error(format!("workspace Git inspection: {error}")))
    }
}

fn gate_error(reason: impl Into<String>) -> RunnerError {
    RunnerError::Gate {
        command: "gate-workdir".into(),
        reason: reason.into(),
    }
}
