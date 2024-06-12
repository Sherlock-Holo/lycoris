use std::io;
use std::io::{Error, IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{AsyncRead, AsyncWrite, Stream};
use hyper_util::client::legacy::connect::{Connected, Connection};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

pub struct TokioTcp(Compat<TcpStream>);

impl From<TcpStream> for TokioTcp {
    fn from(value: TcpStream) -> Self {
        Self(value.compat())
    }
}

impl Connection for TokioTcp {
    fn connected(&self) -> Connected {
        self.0.get_ref().connected()
    }
}

impl AsyncRead for TokioTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for TokioTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

#[derive(Debug)]
pub struct TcpListenerAddrStream {
    listener: TcpListener,
}

impl From<TcpListener> for TcpListenerAddrStream {
    fn from(listener: TcpListener) -> Self {
        Self { listener }
    }
}

impl Stream for TcpListenerAddrStream {
    type Item = Result<(TcpStream, SocketAddr), Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let listener = Pin::new(&mut self.listener);

        listener.poll_accept(cx).map(Some)
    }
}
