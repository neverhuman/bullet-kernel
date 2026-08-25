//! Bounded newline framing in front of the official MCP stdio transport.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// Maximum accepted MCP request frame, excluding its newline delimiter.
pub const MAX_MCP_FRAME_BYTES: usize = 1024 * 1024;

/// Async reader that closes on a line longer than its configured byte limit.
pub struct BoundedLines<R> {
    inner: R,
    current_line_bytes: usize,
    maximum_line_bytes: usize,
}

impl<R> BoundedLines<R> {
    /// Wrap a reader with the production MCP frame ceiling.
    pub fn mcp(inner: R) -> Self {
        Self {
            inner,
            current_line_bytes: 0,
            maximum_line_bytes: MAX_MCP_FRAME_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limit(inner: R, maximum_line_bytes: usize) -> Self {
        assert!(maximum_line_bytes > 0);
        Self {
            inner,
            current_line_bytes: 0,
            maximum_line_bytes,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedLines<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining_in_line = self
            .maximum_line_bytes
            .saturating_sub(self.current_line_bytes);
        let allowance = output.remaining().min(remaining_in_line.saturating_add(1));
        let target = output.initialize_unfilled_to(allowance);
        let mut limited = ReadBuf::new(target);
        match Pin::new(&mut self.inner).poll_read(context, &mut limited) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let bytes = limited.filled();
                let mut next_count = self.current_line_bytes;
                for byte in bytes {
                    if *byte == b'\n' {
                        next_count = 0;
                    } else {
                        next_count = next_count.saturating_add(1);
                        if next_count > self.maximum_line_bytes {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "MCP request frame exceeds the fixed byte limit",
                            )));
                        }
                    }
                }
                let count = bytes.len();
                self.current_line_bytes = next_count;
                output.advance(count);
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn accepts_exact_limit_and_resets_at_newline() {
        let input = b"1234\n5678\n".as_slice();
        let mut reader = BoundedLines::with_limit(input, 4);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn refuses_one_byte_over_limit() {
        let mut reader = BoundedLines::with_limit(b"12345\n".as_slice(), 4);
        let mut output = Vec::new();
        let error = reader.read_to_end(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(output.len() <= 4);
    }
}
