use tokio::io::{AsyncRead, AsyncWrite};

use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::err::Error;

pub mod hyper;

#[async_trait::async_trait]
pub trait Connect {
    type Read: AsyncRead + Unpin + Send + 'static;
    type Write: AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, addr: DomainOrSocketAddr) -> Result<(Self::Read, Self::Write), Error>;
}
