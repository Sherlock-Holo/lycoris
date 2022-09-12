use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::net::{TcpListener, TcpStream};

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
