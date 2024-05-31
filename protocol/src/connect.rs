use std::convert::Infallible;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_channel::mpsc;
use futures_rustls::pki_types::{DnsName, ServerName};
pub use futures_rustls::rustls::ClientConfig;
use futures_rustls::TlsConnector;
use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{AsyncRead, AsyncWrite, StreamExt};
use http::{Request, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper::rt::Timer;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::client::legacy::Client;
use tokio_util::io::{SinkWriter, StreamReader};
use tower_service::Service;
use tracing::{error, info, instrument};

use crate::auth::Auth;
use crate::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use crate::hyper_body::BodyStream;
use crate::{DnsResolver, DomainOrSocketAddr, GenericTlsStream, Reader, Writer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Http(#[from] http::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper_util::client::legacy::Error),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Debug)]
pub struct HyperConnectorConfig<TC, DR, E, T> {
    pub tls_client_config: ClientConfig,
    pub remote_domain: String,
    pub remote_port: u16,
    pub auth: Auth,
    pub token_header: String,
    pub dns_resolver: DR,
    pub tcp_connector: TC,
    pub executor: E,
    pub timer: T,
}

#[derive(Debug, Clone)]
pub struct HyperConnector<TC, DR> {
    inner: Arc<HyperConnectorInner<TC, DR>>,
}

#[derive(Debug)]
struct HyperConnectorInner<TC, DR> {
    client: Client<GenericHttpsConnector<TC, DR>, BoxBody<Bytes, Infallible>>,
    remote_addr: Uri,
    token_generator: Auth,
    token_header: String,
}

impl<DR: DnsResolver + Sync + 'static, TC: TcpConnector + Sync + 'static> HyperConnector<TC, DR> {
    pub fn new<E, T>(config: HyperConnectorConfig<TC, DR, E, T>) -> Result<Self, Error>
    where
        E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>>
            + Send
            + Sync
            + Clone
            + 'static,
        T: Timer + Send + Sync + 'static,
    {
        let https_connector = GenericHttpsConnector {
            dns_resolver: config.dns_resolver,
            tcp_connector: config.tcp_connector,
            tls_connector: TlsConnector::from(Arc::new(config.tls_client_config)),
        };

        let client = Client::builder(config.executor)
            .timer(config.timer)
            .http2_only(true)
            .http2_initial_connection_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(PING_TIMEOUT)
            .http2_keep_alive_interval(PING_INTERVAL)
            .build(https_connector);

        Ok(Self {
            inner: Arc::new(HyperConnectorInner {
                client,
                remote_addr: Uri::try_from(format!(
                    "https://{}:{}",
                    config.remote_domain, config.remote_port
                ))
                .map_err(|err| Error::Other(err.into()))?,
                token_generator: config.auth,
                token_header: config.token_header,
            }),
        })
    }

    #[instrument(skip(self), err(Debug))]
    pub async fn connect(
        &self,
        remote_addr: DomainOrSocketAddr,
    ) -> Result<(Reader, Writer), Error> {
        let token = self.inner.token_generator.generate_token();
        let remote_addr_data = super::encode_addr(remote_addr);

        let (req_body_tx, req_body_rx) = mpsc::unbounded();
        req_body_tx
            .unbounded_send(Ok(Frame::data(remote_addr_data)))
            .expect("unbounded_send should not fail");

        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri(self.inner.remote_addr.clone())
            .header(&self.inner.token_header, token)
            .body(BoxBody::new(StreamBody::new(req_body_rx)))?;

        let response = self.inner.client.request(request).await?;

        info!("receive h2 response done");

        if response.status() != StatusCode::OK {
            let status_code = response.status();
            error!(%status_code, "status code is not 200");

            return Err(Error::Other(
                format!("status {status_code} is not 200").into(),
            ));
        }

        info!("get h2 stream done");

        let reader = StreamReader::new(BodyStream::from(response.into_body()));

        Ok((reader, SinkWriter::new(req_body_tx.into())))
    }
}

#[trait_make::make(Send)]
pub trait TcpConnector: Clone {
    type ConnectedTcpStream: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static;

    async fn connect(&mut self, addr: SocketAddr) -> io::Result<Self::ConnectedTcpStream>;
}

#[derive(Clone)]
struct GenericHttpsConnector<TC, DR> {
    dns_resolver: DR,
    tcp_connector: TC,
    tls_connector: TlsConnector,
}

impl<TC: TcpConnector + Sync + 'static, DR: DnsResolver + 'static> Service<Uri>
    for GenericHttpsConnector<TC, DR>
{
    type Response = GenericTlsStream<TC::ConnectedTcpStream>;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let mut this = self.clone();

        Box::pin(async move {
            let host = req
                .host()
                .ok_or_else(|| io::Error::new(ErrorKind::Other, "miss host"))?
                .trim_start_matches('[')
                .trim_end_matches(']');

            let port = req.port_u16().unwrap_or(443);

            let server_name =
                ServerName::try_from(host).map_err(|err| io::Error::new(ErrorKind::Other, err))?;
            let server_name = server_name.to_owned();

            let tcp_stream = match &server_name {
                &ServerName::IpAddress(ip) => {
                    this.tcp_connector
                        .connect(SocketAddr::new(ip.into(), port))
                        .await?
                }

                ServerName::DnsName(dns_name) => this.connect_dns_name(dns_name, port).await?,

                _ => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        format!("unknown server name {server_name:?}"),
                    ));
                }
            };

            let tls_stream = this.tls_connector.connect(server_name, tcp_stream).await?;

            Ok(GenericTlsStream {
                tls_stream: tls_stream.into(),
            })
        })
    }
}

impl<TC: TcpConnector, DR: DnsResolver> GenericHttpsConnector<TC, DR> {
    async fn connect_dns_name(
        &mut self,
        dns_name: &DnsName<'_>,
        port: u16,
    ) -> io::Result<TC::ConnectedTcpStream> {
        let ip = self.dns_resolver.resolve(dns_name.as_ref()).await?;
        let mut futs = FuturesUnordered::new();
        for ip in ip.into_iter() {
            let mut tcp_connector = self.tcp_connector.clone();
            futs.push(async move { tcp_connector.connect(SocketAddr::new(ip, port)).await });
        }

        assert!(
            !futs.is_empty(),
            "dns name {dns_name:?} resolve ip list empty"
        );

        let mut last_err = None;
        while let Some(res) = futs.next().await {
            match res {
                Err(err) => {
                    last_err = Some(err);
                }

                Ok(tcp_stream) => return Ok(tcp_stream),
            }
        }

        Err(last_err.unwrap())
    }
}
