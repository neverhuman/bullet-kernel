//! Bounded provider pipe readers. Completion waits are bounded independently
//! from the provider deadline, so a hostile descendant retaining a copied pipe
//! descriptor cannot hang dispatch teardown.

use crate::error::HarnessError;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{ChildStderr, ChildStdout};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use super::{RawCapture, MAX_INTERACTIVE_LINES};

pub(super) const MAX_INTERACTIVE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 1024 * 1024;
const READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_QUEUE_DEPTH: usize = 4;
const MAX_WRITE_BATCH_FRAMES: usize = 64;
const MAX_WRITE_BATCH_BYTES: usize = 2 * 1024 * 1024;

/// One detached reader with a bounded result wait. Dropping the receiver never
/// waits for the thread; the process supervisor has already killed its exact
/// process group before [`ReaderTask::finish`] is called.
pub(super) struct ReaderTask<T> {
    result: Receiver<io::Result<T>>,
}

impl<T: Send + 'static> ReaderTask<T> {
    pub(super) fn spawn(read: impl FnOnce() -> io::Result<T> + Send + 'static) -> ReaderTask<T> {
        let (tx, result) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(read());
        });
        Self { result }
    }

    pub(super) fn finish(self, context: &str) -> Result<T, HarnessError> {
        match self.result.recv_timeout(READER_DRAIN_TIMEOUT) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(io_error(context, &error)),
            Err(RecvTimeoutError::Timeout) => Err(HarnessError::Io {
                context: context.to_string(),
                reason: "reader did not drain after process-tree teardown".to_string(),
            }),
            Err(RecvTimeoutError::Disconnected) => Err(HarnessError::Io {
                context: context.to_string(),
                reason: "reader terminated without a result".to_string(),
            }),
        }
    }
}

pub(super) struct InteractiveReader {
    pub(super) lines: Receiver<io::Result<Option<String>>>,
    completion: ReaderTask<()>,
}

/// Child stdin is owned exclusively by a writer task. Queueing never blocks
/// the supervisor loop, and the fixed-depth queue plus bounded batches puts a
/// hard ceiling on resident pending input.
pub(super) struct InteractiveWriter {
    requests: Option<SyncSender<Vec<u8>>>,
    failures: Receiver<io::Error>,
    completion: ReaderTask<()>,
}

impl InteractiveWriter {
    pub(super) fn spawn(mut stdin: std::process::ChildStdin) -> Self {
        let (requests, request_rx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_DEPTH);
        let (failure_tx, failures) = mpsc::channel();
        let completion = ReaderTask::spawn(move || {
            while let Ok(bytes) = request_rx.recv() {
                if let Err(error) = stdin.write_all(&bytes).and_then(|()| stdin.flush()) {
                    let failure = io::Error::new(error.kind(), error.to_string());
                    let _ = failure_tx.send(failure);
                    return Err(error);
                }
            }
            Ok(())
        });
        Self {
            requests: Some(requests),
            failures,
            completion,
        }
    }

    pub(super) fn queue_frames(&mut self, frames: &[String]) -> Result<(), HarnessError> {
        self.check()?;
        let bytes = encode_frames(frames)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(requests) = &self.requests else {
            return Err(writer_closed());
        };
        match requests.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(HarnessError::Io {
                context: "interactive stdin".to_string(),
                reason: "bounded writer queue is full".to_string(),
            }),
            Err(TrySendError::Disconnected(_)) => {
                self.check()?;
                Err(writer_closed())
            }
        }
    }

    pub(super) fn check(&mut self) -> Result<(), HarnessError> {
        match self.failures.try_recv() {
            Ok(error) => Err(io_error("interactive stdin", &error)),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(()),
        }
    }

    pub(super) fn close(&mut self) {
        drop(self.requests.take());
    }

    pub(super) fn finish(mut self) -> Result<(), HarnessError> {
        self.close();
        self.completion.finish("interactive stdin")
    }
}

impl InteractiveReader {
    pub(super) fn spawn(stdout: ChildStdout) -> Self {
        let (line_tx, lines) = mpsc::sync_channel(1);
        let completion = ReaderTask::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let next = read_bounded_line(&mut reader);
                let terminal = matches!(&next, Ok(None) | Err(_));
                if line_tx.send(next).is_err() || terminal {
                    return Ok(());
                }
            }
        });
        Self { lines, completion }
    }

    pub(super) fn finish(self) -> Result<(), HarnessError> {
        drop(self.lines);
        self.completion.finish("interactive stdout")
    }
}

pub(super) fn stdout_reader(stdout: ChildStdout) -> ReaderTask<Vec<String>> {
    ReaderTask::spawn(move || read_lines(stdout))
}

pub(super) fn stderr_reader(stderr: ChildStderr) -> ReaderTask<String> {
    ReaderTask::spawn(move || read_all(stderr))
}

pub(super) fn raw_capture(
    stdout_lines: Vec<String>,
    stderr: String,
    exit_code: Option<i32>,
    started: Instant,
    timed_out: bool,
) -> RawCapture {
    RawCapture {
        stdout_lines,
        stderr,
        exit_code,
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        timed_out,
    }
}

fn encode_frames(frames: &[String]) -> Result<Vec<u8>, HarnessError> {
    if frames.len() > MAX_WRITE_BATCH_FRAMES {
        return Err(HarnessError::Io {
            context: "interactive stdin".to_string(),
            reason: "interactive frame batch exceeds count limit".to_string(),
        });
    }
    let mut total = 0usize;
    for frame in frames {
        if frame.len() > MAX_INTERACTIVE_FRAME_BYTES {
            return Err(HarnessError::Io {
                context: "interactive stdin".to_string(),
                reason: "interactive frame exceeds byte limit".to_string(),
            });
        }
        total = total
            .checked_add(frame.len().saturating_add(1))
            .ok_or_else(batch_too_large)?;
        if total > MAX_WRITE_BATCH_BYTES {
            return Err(batch_too_large());
        }
    }
    let mut bytes = Vec::with_capacity(total);
    for frame in frames {
        bytes.extend_from_slice(frame.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn batch_too_large() -> HarnessError {
    HarnessError::Io {
        context: "interactive stdin".to_string(),
        reason: "interactive frame batch exceeds byte limit".to_string(),
    }
}

fn writer_closed() -> HarnessError {
    HarnessError::Io {
        context: "interactive stdin".to_string(),
        reason: "writer terminated before dispatch completed".to_string(),
    }
}

pub(super) fn pipe_missing(context: &str) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: "pipe missing".to_string(),
    }
}

pub(super) fn io_error(context: &str, error: &io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}

fn read_lines<R: Read>(reader: R) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut buffered = BufReader::new(reader);
    let mut total_bytes = 0usize;
    while let Some(line) = read_bounded_line(&mut buffered)? {
        total_bytes = total_bytes.saturating_add(line.len());
        if lines.len() >= MAX_INTERACTIVE_LINES || total_bytes > MAX_CAPTURE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured stdout exceeds aggregate limit",
            ));
        }
        lines.push(line);
    }
    Ok(lines)
}

pub(super) fn read_bounded_line<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if bytes.len().saturating_add(newline) > MAX_INTERACTIVE_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "interactive frame exceeds byte limit",
                ));
            }
            bytes.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            break;
        }
        if bytes.len().saturating_add(available.len()) > MAX_INTERACTIVE_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "interactive frame exceeds byte limit",
            ));
        }
        let consumed = available.len();
        bytes.extend_from_slice(available);
        reader.consume(consumed);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "interactive frame is not valid UTF-8",
        )
    })
}

fn read_all<R: Read>(reader: R) -> io::Result<String> {
    let limit = u64::try_from(MAX_STDERR_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(MAX_STDERR_BYTES.min(8 * 1024));
    reader.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STDERR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "captured stderr exceeds byte limit",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "captured stderr is not valid UTF-8",
        )
    })
}
