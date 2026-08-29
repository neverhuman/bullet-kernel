//! Resource bounds for the lease-transport socket: frame size, per-frame and
//! per-session deadlines, and the accept bound.
//!
//! Every refusal carries a stable reason code and closes the connection. A
//! bound firing never applies anything: a frame is parsed and dispatched only
//! after it arrived whole and in time, and dispatch itself has no await point
//! between reading the ledger lock and releasing it.

use std::fmt;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::unix::{ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// Fixed per-session read window; never grows, never exceeds the frame cap.
const READ_WINDOW: usize = 8_192;

/// One buffered reader for the whole session, so bytes the peer sends between
/// the hello and its first request are never lost between frames.
pub(super) type FrameReader<'a> = BufReader<ReadHalf<'a>>;

/// Split an accepted stream into the session reader and its writer.
///
/// The read window is `min(8 KiB, max_line_bytes + 1)`, so the reader never
/// holds more of an oversized frame than the frame cap itself allows.
pub(super) fn session_halves(
    stream: &mut UnixStream,
    bounds: TransportBounds,
) -> (FrameReader<'_>, WriteHalf<'_>) {
    let (read, write) = stream.split();
    let window = bounds.max_line_bytes.saturating_add(1).min(READ_WINDOW);
    (BufReader::with_capacity(window, read), write)
}

/// A frame exceeded [`TransportBounds::max_line_bytes`].
pub const LEASE_TRANSPORT_FRAME_TOO_LARGE: &str = "LEASE_TRANSPORT_FRAME_TOO_LARGE";
/// One whole frame did not arrive within [`TransportBounds::read_deadline`].
pub const LEASE_TRANSPORT_READ_DEADLINE: &str = "LEASE_TRANSPORT_READ_DEADLINE";
/// The session outlived [`TransportBounds::session_deadline`].
pub const LEASE_TRANSPORT_SESSION_DEADLINE: &str = "LEASE_TRANSPORT_SESSION_DEADLINE";
/// [`TransportBounds::max_in_flight_sessions`] sessions were already open.
pub const LEASE_TRANSPORT_OVERLOADED: &str = "LEASE_TRANSPORT_OVERLOADED";
/// A bound was zero, so it could never admit anything.
pub const LEASE_TRANSPORT_BOUNDS_INVALID: &str = "LEASE_TRANSPORT_BOUNDS_INVALID";

/// Policy for one listening socket, fixed at bind time.
///
/// The Runner client opens one connection per call (hello, one request, one
/// response), so a session is expected to last milliseconds; the defaults leave
/// generous room for a loaded host while still cutting a stalled peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportBounds {
    /// Longest wait for one whole frame (hello or request), newline included.
    /// A trickle of bytes does not extend it: it bounds the frame, not a byte.
    pub read_deadline: Duration,
    /// Longest life of one accepted session, from accept to close.
    pub session_deadline: Duration,
    /// Largest request frame in bytes, newline excluded. The hello frame is
    /// further capped by the caller. Reading stops at the first excess byte.
    pub max_line_bytes: usize,
    /// Sessions admitted at once; the next peer is refused, never queued.
    pub max_in_flight_sessions: usize,
}

impl TransportBounds {
    /// Default [`Self::read_deadline`].
    pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(5);
    /// Default [`Self::session_deadline`].
    pub const DEFAULT_SESSION_DEADLINE: Duration = Duration::from_secs(30);
    /// Default [`Self::max_line_bytes`] (64 KiB).
    pub const DEFAULT_MAX_LINE_BYTES: usize = 65_536;
    /// Default [`Self::max_in_flight_sessions`].
    pub const DEFAULT_MAX_IN_FLIGHT_SESSIONS: usize = 64;

    /// The documented defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            read_deadline: Self::DEFAULT_READ_DEADLINE,
            session_deadline: Self::DEFAULT_SESSION_DEADLINE,
            max_line_bytes: Self::DEFAULT_MAX_LINE_BYTES,
            max_in_flight_sessions: Self::DEFAULT_MAX_IN_FLIGHT_SESSIONS,
        }
    }

    /// Refuse a policy that could never admit a session.
    ///
    /// # Errors
    ///
    /// [`TransportRefusal::BoundsInvalid`] naming the zero field.
    pub fn admitted(self) -> Result<Self, TransportRefusal> {
        let zero = if self.read_deadline.is_zero() {
            "read_deadline"
        } else if self.session_deadline.is_zero() {
            "session_deadline"
        } else if self.max_line_bytes == 0 {
            "max_line_bytes"
        } else if self.max_in_flight_sessions == 0 {
            "max_in_flight_sessions"
        } else {
            return Ok(self);
        };
        Err(TransportRefusal::BoundsInvalid { field: zero })
    }
}

impl Default for TransportBounds {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Why the transport closed a connection (or refused to bind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportRefusal {
    /// A frame exceeded the byte limit.
    FrameTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// One frame did not arrive whole within the deadline.
    ReadDeadline(Duration),
    /// The session outlived its deadline.
    SessionDeadline(Duration),
    /// Every session slot was taken.
    Overloaded {
        /// The slots that were all busy.
        limit: usize,
    },
    /// A zero bound.
    BoundsInvalid {
        /// The field that was zero.
        field: &'static str,
    },
}

impl TransportRefusal {
    /// Stable reason code carried on the wire and in logs.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::FrameTooLarge { .. } => LEASE_TRANSPORT_FRAME_TOO_LARGE,
            Self::ReadDeadline(_) => LEASE_TRANSPORT_READ_DEADLINE,
            Self::SessionDeadline(_) => LEASE_TRANSPORT_SESSION_DEADLINE,
            Self::Overloaded { .. } => LEASE_TRANSPORT_OVERLOADED,
            Self::BoundsInvalid { .. } => LEASE_TRANSPORT_BOUNDS_INVALID,
        }
    }

    /// Recover the typed refusal from an I/O error that wrapped it.
    #[must_use]
    pub fn from_io(error: &Error) -> Option<&Self> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
    }

    const fn io_kind(&self) -> ErrorKind {
        match self {
            Self::FrameTooLarge { .. } | Self::BoundsInvalid { .. } => ErrorKind::InvalidInput,
            Self::ReadDeadline(_) | Self::SessionDeadline(_) => ErrorKind::TimedOut,
            Self::Overloaded { .. } => ErrorKind::WouldBlock,
        }
    }
}

impl fmt::Display for TransportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { limit } => write!(f, "frame exceeds {limit} bytes"),
            Self::ReadDeadline(limit) => {
                write!(f, "no whole frame within {} ms", limit.as_millis())
            }
            Self::SessionDeadline(limit) => {
                write!(f, "session exceeded {} ms", limit.as_millis())
            }
            Self::Overloaded { limit } => write!(f, "{limit} sessions already in flight"),
            Self::BoundsInvalid { field } => write!(f, "transport bound {field} is zero"),
        }
    }
}

impl std::error::Error for TransportRefusal {}

impl From<TransportRefusal> for Error {
    fn from(refusal: TransportRefusal) -> Self {
        Error::new(refusal.io_kind(), refusal)
    }
}

/// The accept bound: a fixed number of session slots, never a queue.
#[derive(Debug)]
pub(super) struct SessionSlots {
    slots: Arc<Semaphore>,
    limit: usize,
}

impl SessionSlots {
    pub(super) fn new(bounds: TransportBounds) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(bounds.max_in_flight_sessions)),
            limit: bounds.max_in_flight_sessions,
        }
    }

    /// Take a slot now or refuse; the permit is released when dropped.
    pub(super) fn try_admit(&self) -> Result<OwnedSemaphorePermit, TransportRefusal> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| TransportRefusal::Overloaded { limit: self.limit })
    }
}

/// Read one newline-terminated frame within `bounds.read_deadline`, refusing
/// it as soon as `max` content bytes (newline excluded) are exceeded.
///
/// The frame is read in chunks through the session reader, never one syscall
/// per byte. The read is capped at `max + 1` bytes (content plus newline), so
/// the frame buffer never holds more than that even for a hostile sender.
///
/// # Errors
///
/// [`TransportRefusal::FrameTooLarge`] or [`TransportRefusal::ReadDeadline`]
/// wrapped in an I/O error, `UnexpectedEof` on a clean close, or the socket
/// error.
pub(super) async fn read_frame(
    reader: &mut FrameReader<'_>,
    bounds: TransportBounds,
    max: usize,
) -> Result<Vec<u8>, Error> {
    match timeout(bounds.read_deadline, read_frame_unbounded(reader, max)).await {
        Ok(frame) => frame,
        Err(_) => Err(TransportRefusal::ReadDeadline(bounds.read_deadline).into()),
    }
}

async fn read_frame_unbounded(reader: &mut FrameReader<'_>, max: usize) -> Result<Vec<u8>, Error> {
    let cap = max.saturating_add(1);
    let mut buf = Vec::new();
    let mut capped = reader.take(cap as u64);
    let n = capped.read_until(b'\n', &mut buf).await?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(buf);
    }
    if n >= cap {
        return Err(TransportRefusal::FrameTooLarge { limit: max }.into());
    }
    Err(Error::new(ErrorKind::UnexpectedEof, "lease-transport eof"))
}

/// Run one session under `bounds.session_deadline`.
///
/// # Errors
///
/// The session's own error, or [`TransportRefusal::SessionDeadline`] wrapped
/// in an I/O error once the deadline passes.
pub(super) async fn bounded_session<F>(bounds: TransportBounds, session: F) -> Result<(), Error>
where
    F: std::future::Future<Output = Result<(), Error>>,
{
    match timeout(bounds.session_deadline, session).await {
        Ok(result) => result,
        Err(_) => Err(TransportRefusal::SessionDeadline(bounds.session_deadline).into()),
    }
}

/// Tell the peer why its connection is closing when the reason is a typed
/// refusal, without waiting on a peer that does not drain its socket.
///
/// The write is bounded by `bounds.read_deadline`; a peer that never reads
/// simply loses the frame. Returns the reason code that was logged.
pub(super) async fn close_with_reason(
    writer: &mut WriteHalf<'_>,
    bounds: TransportBounds,
    error: &Error,
) -> Option<&'static str> {
    let refusal = TransportRefusal::from_io(error)?;
    let code = refusal.reason_code();
    let message = refusal.to_string();
    let frame = super::write_err(writer, None, code, &message);
    match timeout(bounds.read_deadline, frame).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::debug!("lease-transport {code} frame not delivered: {err}"),
        Err(_) => tracing::debug!("lease-transport {code} frame write timed out"),
    }
    Some(code)
}

/// Refuse a connection that found no free session slot with one typed frame,
/// then close it.
///
/// The socket leaves the reactor first, so the frame goes out as one direct
/// non-blocking `write(2)`: a fresh connection's send buffer is empty, so it is
/// delivered whole or dropped. The accept loop never waits and nothing is
/// spawned for the refused peer.
pub(super) fn refuse_overloaded(stream: UnixStream, refusal: &TransportRefusal) {
    use std::io::Write;
    let code = refusal.reason_code();
    tracing::warn!("lease-transport peer refused: {code}: {refusal}");
    let delivered = super::encode_err(None, code, &refusal.to_string())
        .and_then(|bytes| stream.into_std().map(|std| (std, bytes)))
        .and_then(|(mut std, bytes)| {
            let n = std.write(&bytes)?;
            (n == bytes.len())
                .then_some(())
                .ok_or_else(|| Error::new(ErrorKind::WriteZero, "short refusal frame"))
        });
    if let Err(err) = delivered {
        tracing::debug!("lease-transport {code} frame not delivered: {err}");
    }
}
