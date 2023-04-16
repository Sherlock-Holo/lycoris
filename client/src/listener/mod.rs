use async_trait::async_trait;
use hyper::upgrade::Upgraded;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, BufStream, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::Error;

pub mod bpf;
pub mod http;
pub mod socks;

#[async_trait]
pub trait Listener {
    type Stream: Split;

    async fn accept(&mut self) -> Result<(Self::Stream, DomainOrSocketAddr), Error>;
}

pub trait Split {
    type Read: AsyncRead + Send + Unpin;
    type Write: AsyncWrite + Send + Unpin;

    fn into_split(self) -> (Self::Read, Self::Write);
}

impl Split for TcpStream {
    type Read = OwnedReadHalf;
    type Write = OwnedWriteHalf;

    fn into_split(self) -> (Self::Read, Self::Write) {
        self.into_split()
    }
}

impl Split for BufStream<TcpStream> {
    type Read = ReadHalf<Self>;
    type Write = WriteHalf<Self>;

    fn into_split(self) -> (Self::Read, Self::Write) {
        io::split(self)
    }
}

impl Split for Upgraded {
    type Read = ReadHalf<Self>;
    type Write = WriteHalf<Self>;

    fn into_split(self) -> (Self::Read, Self::Write) {
        io::split(self)
    }
}
