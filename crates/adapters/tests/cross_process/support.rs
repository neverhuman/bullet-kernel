//! Bounded child-process support shared by SQLite cross-process tests.

use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

pub const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);

pub fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("test root is private regardless of host umask");
    }
    directory
}

pub fn wait_until(description: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[derive(Default)]
pub struct ChildSet {
    children: Vec<Child>,
}

impl ChildSet {
    pub fn spawn(&mut self, command: &mut Command) {
        self.children
            .push(command.spawn().expect("spawn isolated child process"));
    }

    pub fn wait_all(&mut self) -> Vec<ExitStatus> {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        let mut statuses = Vec::with_capacity(self.children.len());
        for child in &mut self.children {
            loop {
                match child.try_wait().expect("poll child process") {
                    Some(status) => {
                        statuses.push(status);
                        break;
                    }
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    None => panic!("child process exceeded the shared deadline"),
                }
            }
        }
        statuses
    }
}

impl Drop for ChildSet {
    fn drop(&mut self) {
        for child in &mut self.children {
            if matches!(child.try_wait(), Ok(None) | Err(_)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
