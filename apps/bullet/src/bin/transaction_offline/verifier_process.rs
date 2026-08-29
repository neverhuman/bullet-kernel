use super::support::stop_child;
use std::process::Child;
use std::time::Duration;

pub(super) struct ProcessGuard {
    child: Option<Child>,
    process_group: u32,
}

impl ProcessGuard {
    pub(super) fn new(child: Child) -> Self {
        let process_group = child.id();
        Self {
            child: Some(child),
            process_group,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("verifier child is owned")
    }

    pub(super) fn write_request(&mut self, payload: &[u8]) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind, Write as _};

        let mut stdin = self
            .child_mut()
            .stdin
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stdin pipe missing"))?;
        stdin.write_all(payload)
    }

    fn kill_process_group_members(&self) -> std::io::Result<()> {
        match self.signal_process_group(rustix::process::Signal::KILL) {
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
                Ok(())
            }
            result => result,
        }
    }

    pub(super) fn signal_process_group(
        &self,
        signal: rustix::process::Signal,
    ) -> std::io::Result<()> {
        let process_group = process_id(self.process_group)?;
        rustix::process::kill_process_group(process_group, signal).map_err(std::io::Error::from)
    }

    fn reap_process_group_members(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let process_group = process_id(self.process_group)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match rustix::process::waitpgid(process_group, rustix::process::WaitOptions::NOHANG)
                {
                    Ok(Some(_)) => {}
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "verifier process-group reap timed out",
                        ));
                    }
                    Err(error) if error == rustix::io::Errno::CHILD => return Ok(()),
                    Err(error) => return Err(std::io::Error::from(error)),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        Ok(())
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = self.kill_process_group_members() {
            errors.push(format!("signal verifier process group: {error}"));
        }
        if let Some(child) = self.child.take() {
            if let Err(error) = stop_child(child) {
                errors.push(error);
            }
        }
        if let Err(error) = self.reap_process_group_members() {
            errors.push(format!("reap verifier process group: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }

    pub(super) fn wait_with_output(self) -> std::io::Result<std::process::Output> {
        self.wait_with_output_for(Duration::from_secs(30))
    }

    pub(super) fn wait_with_output_for(
        mut self,
        timeout: Duration,
    ) -> std::io::Result<std::process::Output> {
        use std::io::{Error, ErrorKind, Read as _};
        use std::sync::mpsc;

        const OUTPUT_LIMIT: u64 = 64 * 1024;
        const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

        let stdout = self
            .child_mut()
            .stdout
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stdout pipe missing"))?;
        let stderr = self
            .child_mut()
            .stderr
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stderr pipe missing"))?;
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = stdout_tx.send(result);
        });
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stderr
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = stderr_tx.send(result);
        });
        let deadline = std::time::Instant::now() + timeout;
        let status = loop {
            match self.child_mut().try_wait() {
                Ok(Some(status)) => {
                    let group_result = self.kill_process_group_members();
                    self.child.take();
                    let reap_result = self.reap_process_group_members();
                    break group_result.and(reap_result).map(|()| status);
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    break match self.terminate() {
                        Ok(()) => Err(Error::new(
                            ErrorKind::TimedOut,
                            "verifier process timed out",
                        )),
                        Err(error) => Err(error),
                    };
                }
                Err(error) => {
                    break match self.terminate() {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(Error::other(format!(
                            "verifier wait failed: {error}; containment cleanup failed: {cleanup}"
                        ))),
                    };
                }
            }
        };
        let drain_deadline = std::time::Instant::now() + PIPE_DRAIN_TIMEOUT;
        let stdout = stdout_rx
            .recv_timeout(drain_deadline.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| Error::new(ErrorKind::TimedOut, "verifier stdout drain timed out"))??;
        let stderr = stderr_rx
            .recv_timeout(drain_deadline.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| Error::new(ErrorKind::TimedOut, "verifier stderr drain timed out"))??;
        if stdout.len() > OUTPUT_LIMIT as usize || stderr.len() > OUTPUT_LIMIT as usize {
            return Err(Error::other("verifier output exceeded 64 KiB"));
        }
        Ok(std::process::Output {
            status: status?,
            stdout,
            stderr,
        })
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate();
        }
    }
}

fn process_id(raw: u32) -> std::io::Result<rustix::process::Pid> {
    let raw = i32::try_from(raw)
        .map_err(|_| std::io::Error::other("process id exceeds the platform range"))?;
    rustix::process::Pid::from_raw(raw)
        .ok_or_else(|| std::io::Error::other("process id must be non-zero"))
}

pub(super) fn enable_child_subreaper() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let own = process_id(std::process::id())?;
        rustix::process::set_child_subreaper(Some(own)).map_err(std::io::Error::from)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}
