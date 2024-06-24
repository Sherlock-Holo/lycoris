use std::io;
use std::net::SocketAddr;

use futures_util::Stream;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use protocol::auth::Auth;
use protocol::connect::TcpConnector;
use protocol::{DomainOrSocketAddr, HyperConnectorConfig};
use share::dns::HickoryDnsResolver;
use share::tcp_wrapper::TokioTcp;
use tokio::net::TcpStream;

use super::Connect;
use crate::mptcp::MptcpExt;

#[derive(Debug, Default, Clone)]
struct TokioConnector;

impl TcpConnector for TokioConnector {
    type ConnectedTcpStream = TokioTcp;

    async fn connect<S: Stream<Item = io::Result<SocketAddr>> + Send>(
        &mut self,
        addrs: S,
    ) -> io::Result<Self::ConnectedTcpStream> {
        TcpStream::connect_mptcp(addrs).await.map(Into::into)
    }
}

#[derive(Clone)]
pub struct HyperConnector {
    protocol_connector: protocol::HyperConnector<TokioConnector, HickoryDnsResolver>,
}

impl HyperConnector {
    pub fn new(
        tls_client_config: protocol::connect::ClientConfig,
        remote_domain: String,
        remote_port: u16,
        token_header: String,
        auth: Auth,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            protocol_connector: protocol::HyperConnector::new(HyperConnectorConfig {
                tls_client_config,
                remote_domain,
                remote_port,
                auth,
                token_header,
                dns_resolver: HickoryDnsResolver::new()?,
                tcp_connector: TokioConnector,
                executor: TokioExecutor::new(),
                timer: TokioTimer::new(),
            })?,
        })
    }
}

impl Connect for HyperConnector {
    type Read = impl tokio::io::AsyncRead + Unpin + Send + 'static;
    type Write = impl tokio::io::AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, addr: DomainOrSocketAddr) -> anyhow::Result<(Self::Read, Self::Write)> {
        let rw = self.protocol_connector.connect(addr).await?;

        Ok(rw)
    }
}
