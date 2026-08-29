use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const SCRATCH_ROOT: &str = "/tmp";

/// Descriptor-anchored gate scratch. The directory descriptor intentionally
/// crosses exec so gate children use the retained directory, not a mutable
/// ambient path.
#[derive(Debug)]
pub(super) struct Scratch {
    directory: File,
    _temporary: tempfile::TempDir,
    _root: File,
}

impl Scratch {
    pub(super) fn path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        return PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        unreachable!("scratch construction refuses outside Linux")
    }
}

pub(super) fn create_scratch(workdir: &Path) -> Result<Scratch, String> {
    #[cfg(not(target_os = "linux"))]
    return Err("descriptor-bound gate scratch is unsupported outside Linux".to_owned());
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{open, openat, Mode, OFlags};
        use std::os::unix::fs::PermissionsExt;

        let root = File::from(
            open(
                SCRATCH_ROOT,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| format!("open admitted gate scratch root: {error}"))?,
        );
        validate_root(&root)?;
        require_external_to(workdir, &root)?;
        let anchored_root = format!("/proc/self/fd/{}", root.as_raw_fd());
        let temporary = tempfile::Builder::new()
            .prefix("bullet-gate-output-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&anchored_root)
            .map_err(|error| format!("create private gate output directory: {error}"))?;
        let name = temporary
            .path()
            .file_name()
            .ok_or_else(|| "private gate output directory has no name".to_owned())?;
        let directory = File::from(
            openat(
                &root,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| format!("retain private gate output directory: {error}"))?,
        );
        validate_private(&directory)?;
        Ok(Scratch {
            directory,
            _temporary: temporary,
            _root: root,
        })
    }
}

#[cfg(target_os = "linux")]
fn require_external_to(workdir: &Path, scratch_root: &File) -> Result<(), String> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let workdir = File::from(
        open(
            workdir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("retain admitted gate workdir identity: {error}"))?,
    );
    let workdir_identity = directory_identity(&workdir)?;
    let mut ancestor = scratch_root
        .try_clone()
        .map_err(|error| format!("retain gate scratch ancestry: {error}"))?;
    for _ in 0..256 {
        let identity = directory_identity(&ancestor)?;
        if identity == workdir_identity {
            return Err("admitted gate workdir contains the gate scratch root".to_owned());
        }
        let parent = File::from(
            openat(
                &ancestor,
                "..",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| format!("walk gate scratch ancestry: {error}"))?,
        );
        if directory_identity(&parent)? == identity {
            return Ok(());
        }
        ancestor = parent;
    }
    Err("gate scratch ancestry exceeds its admitted depth".to_owned())
}

#[cfg(target_os = "linux")]
fn directory_identity(directory: &File) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory
        .metadata()
        .map_err(|error| format!("inspect gate directory identity: {error}"))?;
    if !metadata.is_dir() || metadata.dev() == 0 || metadata.ino() == 0 {
        return Err("gate directory identity is invalid".to_owned());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "linux")]
fn validate_root(root: &File) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = root
        .metadata()
        .map_err(|error| format!("inspect admitted gate scratch root: {error}"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o1777 {
        return Err("admitted gate scratch root is not root-owned mode 01777".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private(directory: &File) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory
        .metadata()
        .map_err(|error| format!("inspect private gate output directory: {error}"))?;
    let owner = rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(format!(
            "private gate output directory has wrong owner or mode: uid={}, expected_uid={owner}, mode={:04o}",
            metadata.uid(),
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}

pub(super) struct Captured {
    pub(super) bytes: Vec<u8>,
    pub(super) overflow: bool,
}

pub(super) struct Output {
    pub(super) exit_code: Option<i32>,
    pub(super) timed_out: bool,
    pub(super) stdout: Captured,
    pub(super) stderr: Captured,
}

pub(super) async fn run(
    command: &mut tokio::process::Command,
    deadline: Duration,
    capture_limit: usize,
) -> Result<Output, String> {
    configure_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn gate child: {error}"))?;
    let process_group = child.id();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate(&mut child, process_group).await?;
            return Err("gate child stdout pipe is missing".to_owned());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            terminate(&mut child, process_group).await?;
            return Err("gate child stderr pipe is missing".to_owned());
        }
    };
    let mut stdout_task = tokio::spawn(drain(stdout, capture_limit));
    let mut stderr_task = tokio::spawn(drain(stderr, capture_limit));

    let (exit_code, timed_out, process_error) =
        match tokio::time::timeout(deadline, child.wait()).await {
            Ok(Ok(status)) => {
                let cleanup = kill_group(process_group).err();
                (status.code(), false, cleanup)
            }
            Ok(Err(error)) => {
                let cleanup = terminate(&mut child, process_group).await;
                let reason = match cleanup {
                    Ok(()) => format!("wait for gate child: {error}"),
                    Err(cleanup) => format!("wait for gate child: {error}; cleanup: {cleanup}"),
                };
                (None, false, Some(reason))
            }
            Err(_) => {
                let cleanup = terminate(&mut child, process_group).await.err();
                (None, true, cleanup)
            }
        };
    let (stdout, stderr) = tokio::join!(
        join_drain("stdout", &mut stdout_task),
        join_drain("stderr", &mut stderr_task)
    );
    let stdout = stdout?;
    let stderr = stderr?;
    if let Some(error) = process_error {
        return Err(error);
    }
    Ok(Output {
        exit_code,
        timed_out,
        stdout,
        stderr,
    })
}

async fn drain(mut reader: impl AsyncRead + Unpin, capture_limit: usize) -> io::Result<Captured> {
    let retained_limit = capture_limit.saturating_add(4);
    let mut bytes = Vec::with_capacity(retained_limit);
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > capture_limit {
            overflow = true;
        }
        let retain = retained_limit.saturating_sub(bytes.len()).min(count);
        bytes.extend_from_slice(&buffer[..retain]);
    }
    Ok(Captured { bytes, overflow })
}

async fn join_drain(
    label: &str,
    task: &mut tokio::task::JoinHandle<io::Result<Captured>>,
) -> Result<Captured, String> {
    match tokio::time::timeout(CLEANUP_TIMEOUT, &mut *task).await {
        Ok(Ok(Ok(captured))) => Ok(captured),
        Ok(Ok(Err(error))) => Err(format!("read gate child {label}: {error}")),
        Ok(Err(error)) => Err(format!("join gate child {label} reader: {error}")),
        Err(_) => {
            task.abort();
            Err(format!("gate child {label} drain timed out"))
        }
    }
}

async fn terminate(
    child: &mut tokio::process::Child,
    process_group: Option<u32>,
) -> Result<(), String> {
    let group_result = kill_group(process_group);
    let direct_result = child
        .start_kill()
        .map_err(|error| format!("kill gate child: {error}"));
    let wait_result = tokio::time::timeout(CLEANUP_TIMEOUT, child.wait())
        .await
        .map_err(|_| "gate child reap timed out".to_owned())?
        .map(|_| ())
        .map_err(|error| format!("reap gate child: {error}"));
    group_result.and(direct_result).and(wait_result)
}

#[cfg(unix)]
fn configure_process_group(command: &mut tokio::process::Command) {
    use std::os::unix::process::CommandExt;

    command.as_std_mut().process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut tokio::process::Command) {}

#[cfg(unix)]
fn kill_group(raw: Option<u32>) -> Result<(), String> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let raw = i32::try_from(raw).map_err(|_| "gate process id exceeds i32".to_owned())?;
    let process_group =
        rustix::process::Pid::from_raw(raw).ok_or_else(|| "gate process id is zero".to_owned())?;
    match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(format!("kill gate process group: {error}")),
    }
}

#[cfg(not(unix))]
fn kill_group(_raw: Option<u32>) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn piped(command: &mut tokio::process::Command) {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    #[tokio::test]
    async fn capture_is_memory_bounded() {
        let mut command = tokio::process::Command::new("/usr/bin/head");
        command.args(["-c", "65536", "/dev/zero"]);
        piped(&mut command);
        let output = run(&mut command, Duration::from_secs(5), 4096)
            .await
            .unwrap();
        assert!(!output.timed_out);
        assert!(output.stdout.overflow);
        assert_eq!(output.stdout.bytes.len(), 4100);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_kills_descendants_before_they_can_escape() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("escaped");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "(/usr/bin/sleep 1; /usr/bin/touch \"$1\") & wait",
                "gate-test",
            ])
            .arg(&marker);
        piped(&mut command);
        let output = run(&mut command, Duration::from_millis(50), 4096)
            .await
            .unwrap();
        assert!(output.timed_out);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn scratch_ignores_ambient_tmpdir_inside_a_worktree() {
        const CHILD: &str = "BULLET_GATE_SCRATCH_CHILD";
        const OBSERVATION: &str = "BULLET_GATE_SCRATCH_OBSERVATION";
        const WORKTREE: &str = "BULLET_GATE_SCRATCH_WORKTREE";
        if std::env::var_os(CHILD).is_some() {
            let worktree = PathBuf::from(std::env::var_os(WORKTREE).unwrap());
            let scratch = create_scratch(&worktree).unwrap();
            let resolved = std::fs::canonicalize(scratch.path()).unwrap();
            std::fs::write(worktree.join(".gitignore"), "ambient-tmp/\n").unwrap();
            std::fs::write(worktree.join("PONG.txt"), "PONG\n").unwrap();
            let git = |args: &[&str]| {
                let output = std::process::Command::new("/usr/bin/git")
                    .args(args)
                    .current_dir(&worktree)
                    .env_clear()
                    .env("HOME", "/nonexistent")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .output()
                    .unwrap();
                assert!(output.status.success());
                String::from_utf8_lossy(&output.stdout).trim().to_owned()
            };
            git(&["init", "-q", "-b", "main"]);
            git(&["add", ".gitignore", "PONG.txt"]);
            let expected = format!("sha1:{}", git(&["write-tree"]));
            let bound = super::super::GateWorkdir::open(&worktree).unwrap();
            let error = bound.verify_git_tree(&expected).await.unwrap_err();
            match error {
                crate::error::RunnerError::Gate { reason, .. } => {
                    assert_eq!(reason, "opened workspace contains untracked bytes");
                }
                other => panic!("unexpected private-index refusal: {other:?}"),
            }
            std::fs::write(
                std::env::var_os(OBSERVATION).unwrap(),
                resolved.to_string_lossy().as_bytes(),
            )
            .unwrap();
            return;
        }

        let fixture = tempfile::tempdir().unwrap();
        let worktree = fixture.path().join("worktree");
        let ambient = worktree.join("ambient-tmp");
        let observation = fixture.path().join("observation");
        std::fs::create_dir_all(&ambient).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gate::process::tests::scratch_ignores_ambient_tmpdir_inside_a_worktree",
                "--nocapture",
            ])
            .env("TMPDIR", &ambient)
            .env(CHILD, "1")
            .env(OBSERVATION, &observation)
            .env(WORKTREE, &worktree)
            .status()
            .unwrap();
        assert!(status.success());
        let resolved = PathBuf::from(std::fs::read_to_string(&observation).unwrap());
        assert!(resolved.starts_with(SCRATCH_ROOT));
        assert!(!resolved.starts_with(&worktree));
        assert_eq!(std::fs::read_dir(&ambient).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_refuses_workdir_ancestors_by_descriptor_identity() {
        for workdir in [Path::new("/tmp"), Path::new("/")] {
            let error = create_scratch(workdir).unwrap_err();
            assert_eq!(
                error,
                "admitted gate workdir contains the gate scratch root"
            );

            let retained = File::open(workdir).unwrap();
            let alias = PathBuf::from(format!("/proc/self/fd/{}", retained.as_raw_fd()));
            let error = create_scratch(&alias).unwrap_err();
            assert_eq!(
                error,
                "admitted gate workdir contains the gate scratch root"
            );
        }

        let ordinary = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        create_scratch(ordinary.path()).unwrap();
    }
}
