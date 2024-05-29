use protocol::DomainOrSocketAddr;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, BufStream, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub mod bpf;

#[trait_variant::make(Send)]
pub trait Listener {
    type Stream: Split;

    async fn accept(&mut self) -> anyhow::Result<(Self::Stream, DomainOrSocketAddr)>;
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
