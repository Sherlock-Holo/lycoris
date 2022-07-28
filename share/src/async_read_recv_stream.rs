use std::io;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{ready, AsyncRead, Stream, StreamExt};
use h2::RecvStream;

use crate::helper::h2_err_to_io_err;

pub trait LimitedRecvStream: Stream {
    fn release_capacity(&mut self, size: usize) -> io::Result<()>;
}

impl LimitedRecvStream for RecvStream {
    #[inline]
    fn release_capacity(&mut self, size: usize) -> io::Result<()> {
        self.flow_control()
            .release_capacity(size)
            .map_err(h2_err_to_io_err)
    }
}

pub struct AsyncReadRecvStream<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> AsyncReadRecvStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Default::default(),
        }
    }
}

impl<B, S> AsyncRead for AsyncReadRecvStream<S>
where
    B: Deref<Target = [u8]>,
    S: Stream<Item = Result<B, h2::Error>> + Unpin + LimitedRecvStream,
{
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
            let data = result.map_err(h2_err_to_io_err)?;

            self.stream.release_capacity(data.len())?;
            self.buf.put_slice(data.deref());

            self.poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::{stream, AsyncReadExt};

    use super::*;

    struct WrapperStream<S>(S);

    impl<S: Stream + Unpin> Stream for WrapperStream<S> {
        type Item = S::Item;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.0.poll_next_unpin(cx)
        }
    }

    impl<S: Stream + Unpin> LimitedRecvStream for WrapperStream<S> {
        fn release_capacity(&mut self, _size: usize) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn byte_stream() {
        let s = stream::iter([
            Bytes::from_static(&[1]),
            Bytes::from_static(&[2, 3]),
            Bytes::from_static(&[3, 4, 5]),
        ])
        .map(Ok::<_, h2::Error>);
        let mut recv_stream = AsyncReadRecvStream::new(WrapperStream(s));
        let mut buf = vec![0; 2];

        let mut n = recv_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], &[1]);

        n = recv_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], &[2, 3]);

        n = recv_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], &[3, 4]);

        n = recv_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], &[5]);

        assert_eq!(recv_stream.read(&mut buf).await.unwrap(), 0);
    }
}
