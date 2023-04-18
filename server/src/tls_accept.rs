use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::stream::FuturesUnordered;
use futures_util::{ready, StreamExt};
use hyper::server::accept::Accept;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

pub struct TlsAcceptor {
    tcp_listener: TcpListener,
    tls_listener: tokio_rustls::TlsAcceptor,
    accepting_stream: FuturesUnordered<tokio_rustls::Accept<TcpStream>>,
}

impl TlsAcceptor {
    pub fn new(tcp_listener: TcpListener, tls_listener: tokio_rustls::TlsAcceptor) -> Self {
        Self {
            tcp_listener,
            tls_listener,
            accepting_stream: Default::default(),
        }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream<TcpStream>;
    type Error = Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        loop {
            if let Poll::Ready(Some(stream)) = self.accepting_stream.poll_next_unpin(cx)? {
                return Poll::Ready(Some(Ok(stream)));
            }

            let (stream, _) = ready!(self.tcp_listener.poll_accept(cx))?;

            let fut = self.tls_listener.accept(stream);
            self.accepting_stream.push(fut);
        }
    }
}
