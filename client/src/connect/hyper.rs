use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{AsyncRead, AsyncWrite};
use hickory_resolver::name_server::{GenericConnector, TokioRuntimeProvider};
use hickory_resolver::AsyncResolver;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use protocol::auth::Auth;
use protocol::connect::TcpConnector;
use protocol::{DnsResolver, DomainOrSocketAddr, HyperConnectorConfig};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use super::Connect;

#[derive(Clone)]
struct HickoryDnsResolver {
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl HickoryDnsResolver {
    fn new() -> io::Result<Self> {
        let resolver = AsyncResolver::tokio_from_system_conf()?;

        Ok(Self { resolver })
    }
}

impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&mut self, name: &str) -> io::Result<impl IntoIterator<Item = IpAddr>> {
        let lookup_ip = self.resolver.lookup_ip(name).await?;

        Ok(lookup_ip)
    }
}

struct TokioTcp(Compat<TcpStream>);

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

#[derive(Debug, Default, Clone)]
struct TokioConnector;

impl TcpConnector for TokioConnector {
    type ConnectedTcpStream = TokioTcp;

    async fn connect(&mut self, addr: SocketAddr) -> io::Result<Self::ConnectedTcpStream> {
        let tcp_stream = TcpStream::connect(addr).await?;

        Ok(TokioTcp(tcp_stream.compat()))
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
        self.protocol_connector.connect(addr).await
    }
}
