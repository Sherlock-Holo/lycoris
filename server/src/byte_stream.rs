use std::io;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{ready, AsyncRead, Stream, StreamExt};

pub struct ByteStream<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> ByteStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Default::default(),
        }
    }
}

impl<B: Deref<Target = [u8]>, S: Stream<Item = io::Result<B>> + Unpin> AsyncRead for ByteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !self.buf.is_empty() {
            let copy_size = buf.len().min(self.buf.len());

            self.buf.copy_to_slice(&mut buf[..copy_size]);

            return Poll::Ready(Ok(copy_size));
        }

        if let Some(result) = ready!(self.stream.poll_next_unpin(cx)) {
            let data = result?;

            self.buf.put_slice(data.deref());

            self.poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::{stream, AsyncReadExt};

    use super::*;

    #[tokio::test]
    async fn byte_stream() {
        let s = stream::iter([vec![1], vec![2, 3], vec![3, 4, 5]]).map(Ok::<_, io::Error>);
        let mut byte_stream = ByteStream::new(s);
        let mut buf = vec![0; 2];

        let mut n = byte_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], &[1]);

        n = byte_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], &[2, 3]);

        n = byte_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], &[3, 4]);

        n = byte_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], &[5]);

        assert_eq!(byte_stream.read(&mut buf).await.unwrap(), 0);
    }
}
