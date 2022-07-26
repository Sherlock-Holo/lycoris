use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_util::{ready, AsyncWrite};
use h2::{Reason, SendStream};
use http::HeaderMap;

use crate::err::h2_err_to_io_err;

pub trait LimitedSendStream<B: Buf> {
    fn reserve_capacity(&mut self, capacity: usize);

    fn capacity(&self) -> usize;

    fn poll_capacity(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<usize, h2::Error>>>;

    fn send_data(&mut self, data: B, end_of_stream: bool) -> Result<(), h2::Error>;

    fn send_reset(&mut self, reason: Reason);

    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reason, h2::Error>>;

    fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), h2::Error>;
}

impl<B: Buf> LimitedSendStream<B> for SendStream<B> {
    #[inline]
    fn reserve_capacity(&mut self, capacity: usize) {
        SendStream::reserve_capacity(self, capacity)
    }

    #[inline]
    fn capacity(&self) -> usize {
        SendStream::capacity(self)
    }

    #[inline]
    fn poll_capacity(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<usize, h2::Error>>> {
        SendStream::poll_capacity(self, cx)
    }

    #[inline]
    fn send_data(&mut self, data: B, end_of_stream: bool) -> Result<(), h2::Error> {
        SendStream::send_data(self, data, end_of_stream)
    }

    #[inline]
    fn send_reset(&mut self, reason: Reason) {
        SendStream::send_reset(self, reason)
    }

    #[inline]
    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reason, h2::Error>> {
        SendStream::poll_reset(self, cx)
    }

    #[inline]
    fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), h2::Error> {
        SendStream::send_trailers(self, trailers)
    }
}

#[derive(Debug)]
pub struct AsyncWriteSendStream<S>(S);

impl<S> AsyncWriteSendStream<S> {
    pub fn new(send_stream: S) -> Self {
        Self(send_stream)
    }
}

impl<S: LimitedSendStream<Bytes>> AsyncWriteSendStream<S> {
    fn send_data(&mut self, data: &[u8], capacity: usize) -> io::Result<usize> {
        let write_size = capacity.min(data.len());

        if let Err(err) = self
            .0
            .send_data(Bytes::copy_from_slice(&data[..write_size]), false)
        {
            Err(h2_err_to_io_err(err))
        } else {
            Ok(write_size)
        }
    }

    fn check_reset(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.0.poll_reset(cx) {
            Poll::Ready(Err(err)) => Err(h2_err_to_io_err(err)),
            Poll::Ready(Ok(reason)) => {
                let err = match reason {
                    Reason::NO_ERROR | Reason::CONNECT_ERROR => {
                        io::Error::from(ErrorKind::BrokenPipe)
                    }
                    Reason::PROTOCOL_ERROR
                    | Reason::COMPRESSION_ERROR
                    | Reason::FRAME_SIZE_ERROR => io::Error::from(ErrorKind::InvalidData),

                    reason => io::Error::new(ErrorKind::Other, reason.description()),
                };

                Err(err)
            }

            Poll::Pending => Ok(()),
        }
    }
}

impl<S: LimitedSendStream<Bytes> + Unpin> AsyncWrite for AsyncWriteSendStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        // check peer close or not
        this.check_reset(cx)?;

        if this.0.capacity() > 0 {
            let n = this.send_data(buf, this.0.capacity())?;

            return Poll::Ready(Ok(n));
        }

        this.0.reserve_capacity(buf.len());

        let increased_capacity = match ready!(this.0.poll_capacity(cx)) {
            None => return Poll::Ready(Err(io::Error::from(ErrorKind::UnexpectedEof))),
            Some(Err(err)) => return Poll::Ready(Err(h2_err_to_io_err(err))),
            Some(Ok(capacity)) => capacity,
        };

        let n = this.send_data(buf, increased_capacity)?;

        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // check peer close or not
        self.check_reset(cx)?;

        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .send_trailers(HeaderMap::new())
            .map_err(h2_err_to_io_err)?;

        // should we need to call check_reset?
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use futures_util::AsyncWriteExt;
    use h2::Error;

    use super::*;

    #[derive(Debug, Default)]
    pub struct WatchSendStream {
        buf: BytesMut,
        is_closed: bool,
    }

    impl LimitedSendStream<Bytes> for WatchSendStream {
        fn reserve_capacity(&mut self, capacity: usize) {
            if self.buf.capacity() < capacity {
                self.buf.reserve(capacity - self.buf.capacity())
            }
        }

        fn capacity(&self) -> usize {
            self.buf.capacity()
        }

        fn poll_capacity(&mut self, _cx: &mut Context<'_>) -> Poll<Option<Result<usize, Error>>> {
            if self.is_closed {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok(self.buf.capacity())))
            }
        }

        fn send_data(&mut self, data: Bytes, _end_of_stream: bool) -> Result<(), Error> {
            if self.is_closed {
                return Err(Error::from(Reason::NO_ERROR));
            }

            self.buf.put(data);

            Ok(())
        }

        fn send_reset(&mut self, _reason: Reason) {
            self.is_closed = true;
        }

        fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reason, Error>> {
            if self.is_closed {
                Poll::Ready(Ok(Reason::NO_ERROR))
            } else {
                cx.waker().wake_by_ref();

                Poll::Pending
            }
        }

        fn send_trailers(&mut self, _trailers: HeaderMap) -> Result<(), Error> {
            self.is_closed = true;

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_async_write_send_stream() {
        let watch_send_stream = WatchSendStream::default();

        let mut async_write_send_stream = AsyncWriteSendStream::new(watch_send_stream);

        async_write_send_stream.write_all(b"test").await.unwrap();
        assert_eq!(
            async_write_send_stream.0.buf.copy_to_bytes(4).as_ref(),
            b"test"
        );

        async_write_send_stream.write_all(b"123").await.unwrap();
        assert_eq!(
            async_write_send_stream.0.buf.copy_to_bytes(3).as_ref(),
            b"123"
        );

        async_write_send_stream.close().await.unwrap();

        assert_eq!(
            async_write_send_stream
                .write_all(b"test")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    }
}
