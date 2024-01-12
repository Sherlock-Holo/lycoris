use tokio::io::{AsyncRead, AsyncWrite};

use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;

pub mod hyper;

#[trait_variant::make(Connect: Send)]
pub trait LocalConnect {
    type Read: AsyncRead + Unpin + Send + 'static;
    type Write: AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, addr: DomainOrSocketAddr) -> anyhow::Result<(Self::Read, Self::Write)>;
}
