use protocol::DomainOrSocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod hyper;

#[trait_make::make(Send)]
pub trait Connect {
    type Read: AsyncRead + Unpin + Send + 'static;
    type Write: AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, addr: DomainOrSocketAddr) -> anyhow::Result<(Self::Read, Self::Write)>;
}
