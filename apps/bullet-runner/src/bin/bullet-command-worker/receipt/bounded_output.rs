//! Kernel-enforced bounded stdout custody for admitted child processes.

use super::invalid;
use crate::error::WorkerError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::Stdio;

/// A pre-sized memfd that cannot grow or shrink after child admission.
pub(super) struct BoundedOutput {
    file: File,
    limit: u64,
}

impl BoundedOutput {
    pub(super) fn new(name: &str, limit: u64) -> Result<Self, WorkerError> {
        let capacity = limit
            .checked_add(1)
            .ok_or_else(|| invalid("bounded child output capacity overflow"))?;
        let descriptor = rustix::fs::memfd_create(
            name,
            rustix::fs::MemfdFlags::ALLOW_SEALING | rustix::fs::MemfdFlags::CLOEXEC,
        )
        .map_err(invalid)?;
        let mut file = File::from(descriptor);
        file.set_len(capacity).map_err(invalid)?;
        rustix::fs::fcntl_add_seals(
            &file,
            rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::SEAL,
        )
        .map_err(invalid)?;
        file.seek(SeekFrom::Start(0)).map_err(invalid)?;
        Ok(Self { file, limit })
    }

    pub(super) fn child_stdout(&self) -> Result<Stdio, WorkerError> {
        self.file.try_clone().map(Stdio::from).map_err(invalid)
    }

    /// Read exactly the bytes written through the shared file description.
    /// The one-byte sentinel identifies overflow when a write reaches it;
    /// otherwise the child's failed status still identifies the sealed cap.
    pub(super) fn finish(mut self, overflow: &str) -> Result<Vec<u8>, WorkerError> {
        let written = self.file.stream_position().map_err(invalid)?;
        if written > self.limit {
            return Err(invalid(overflow));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(invalid)?;
        let mut bytes = Vec::with_capacity(usize::try_from(written).map_err(invalid)?);
        (&mut self.file)
            .take(written)
            .read_to_end(&mut bytes)
            .map_err(invalid)?;
        if bytes.len() as u64 != written {
            return Err(invalid("bounded child output read-back was truncated"));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    fn backing_len(&self) -> u64 {
        self.file.metadata().expect("metadata").len()
    }

    #[cfg(test)]
    fn written_len(&mut self) -> u64 {
        self.file.stream_position().expect("stream position")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    #[test]
    fn unbounded_child_cannot_grow_past_overflow_sentinel() {
        let mut output = BoundedOutput::new("bullet-bounded-output-hostile", 4_096).unwrap();
        let mut child = Command::new("/usr/bin/yes")
            .stdin(Stdio::null())
            .stdout(output.child_stdout().unwrap())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();

        assert!(!status.success());
        assert_eq!(output.backing_len(), 4_097);
        let written = output.written_len();
        assert!(written > 0 && written <= 4_097);
        match output.finish("hostile child exceeded output bound") {
            Ok(bytes) => assert!(bytes.len() <= 4_096),
            Err(error) => {
                assert_eq!(written, 4_097);
                assert_eq!(error.code(), "COMMAND_RECEIPT_INVALID");
                assert!(error.to_string().contains("exceeded output bound"));
            }
        }
    }
}
