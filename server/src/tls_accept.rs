use std::io::Error;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use hyper::rt::{Read, ReadBufCursor, Write};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

pub struct TlsAcceptor {
    tcp_listener: TcpListener,
    tls_listener: tokio_rustls::TlsAcceptor,
}

impl TlsAcceptor {
    pub fn new(tcp_listener: TcpListener, tls_listener: tokio_rustls::TlsAcceptor) -> Self {
        Self {
            tcp_listener,
            tls_listener,
        }
    }

    pub async fn accept(&self) -> Result<HyperTlsStream, Error> {
        let stream = self.tcp_listener.accept().await?.0;
        self.tls_listener.accept(stream).await.map(HyperTlsStream)
    }
}

pub struct HyperTlsStream(TlsStream<TcpStream>);

impl Read for HyperTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), Error>> {
        let stream = Pin::new(&mut self.0);

        // safety: we won't read it
        let mut io_buf = ReadBuf::uninit(unsafe { buf.as_mut() });
        ready!(stream.poll_read(cx, &mut io_buf))?;
        let filled = io_buf.filled().len();

        // safety: we have written it
        unsafe {
            buf.advance(filled);
        }

        Poll::Ready(Ok(()))
    }
}

impl Write for HyperTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
