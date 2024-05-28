use core::slice;
use std::convert::Infallible;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::{error, io};

use anyhow::Context as _;
use bytes::Bytes;
use futures_channel::mpsc;
use futures_rustls::client::TlsStream;
use futures_rustls::pki_types::ServerName;
use futures_rustls::TlsConnector;
use futures_util::{AsyncRead, AsyncWrite};
use http::{Request, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper::rt::{ReadBufCursor, Timer};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use tokio_rustls::rustls::ClientConfig;
use tokio_util::io::{SinkWriter, StreamReader};
use tower_service::Service;
use tracing::{error, info, instrument};

use super::DomainOrSocketAddr;
use crate::auth::Auth;
use crate::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use crate::hyper_body::{BodyStream, SinkBodySender};

pub type ReadWrite = (
    StreamReader<BodyStream, Bytes>,
    SinkWriter<SinkBodySender<Infallible>>,
);

#[derive(Debug)]
pub struct HyperConnectorConfig<HC, E, T> {
    pub tls_client_config: ClientConfig,
    pub remote_domain: String,
    pub remote_port: u16,
    pub auth: Auth,
    pub token_header: String,
    pub http_connector: HC,
    pub executor: E,
    pub timer: T,
}

#[derive(Debug, Clone)]
pub struct HyperConnector<HC> {
    inner: Arc<HyperConnectorInner<HC>>,
}

#[derive(Debug)]
struct HyperConnectorInner<HC> {
    client: Client<HttpsConnector<HC>, BoxBody<Bytes, Infallible>>,
    remote_addr: Uri,
    token_generator: Auth,
    token_header: String,
}

impl<HC> HyperConnector<HC>
where
    HC: Service<Uri> + Clone + Send + Sync + 'static,
    HC::Response: Connection + hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    HC::Future: Send + 'static,
    HC::Error: Into<Box<dyn error::Error + Send + Sync>>,
{
    pub fn new<E, T>(config: HyperConnectorConfig<HC, E, T>) -> anyhow::Result<Self>
    where
        E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>>
            + Send
            + Sync
            + Clone
            + 'static,
        T: Timer + Send + Sync + 'static,
    {
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(config.tls_client_config)
            .https_only()
            .with_server_name(config.remote_domain.clone())
            .enable_http2()
            .wrap_connector(config.http_connector);

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
                ))?,
                token_generator: config.auth,
                token_header: config.token_header,
            }),
        })
    }

    #[instrument(skip(self), err(Debug))]
    pub async fn connect(&self, remote_addr: DomainOrSocketAddr) -> anyhow::Result<ReadWrite> {
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
            .body(BoxBody::new(StreamBody::new(req_body_rx)))
            .with_context(|| "build h2 request failed")?;

        let response = self
            .inner
            .client
            .request(request)
            .await
            .with_context(|| "send h2 request failed")?;

        info!("receive h2 response done");

        if response.status() != StatusCode::OK {
            let status_code = response.status();
            error!(%status_code, "status code is not 200");

            return Err(anyhow::anyhow!("status {status_code} is not 200"));
        }

        info!("get h2 stream done");

        let reader = StreamReader::new(BodyStream::from(response.into_body()));

        Ok((reader, SinkWriter::new(req_body_tx.into())))
    }
}

#[trait_make::make(Send)]
pub trait TcpConnector: Clone {
    type ConnectedTcpStream: AsyncRead + AsyncWrite + Unpin;

    async fn connect(&mut self, addr: SocketAddr) -> io::Result<Self::ConnectedTcpStream>;
}

#[trait_make::make(Send)]
pub trait DnsResolver: Clone {
    async fn resolve(&mut self, name: &str) -> io::Result<IpAddr>;
}

struct GenericHttpsConnector<TC, DR> {
    dns_resolver: DR,
    tcp_connector: TC,
    tls_connector: TlsConnector,
}

impl<TC: TcpConnector, DR: DnsResolver> Service<Uri> for GenericHttpsConnector<TC, DR> {
    type Response = GenericTlsStream<TC::ConnectedTcpStream>;
    type Error = io::Error;
    type Future = impl Future<Output = Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let mut dns_resolver = self.dns_resolver.clone();
        let mut tcp_connector = self.tcp_connector.clone();
        let tls_connector = self.tls_connector.clone();

        async move {
            let host = req
                .host()
                .ok_or_else(|| io::Error::new(ErrorKind::Other, "miss host"))?;
            let port = req.port_u16().unwrap_or(443);

            let server_name =
                ServerName::try_from(host).map_err(|err| io::Error::new(ErrorKind::Other, err))?;
            let server_name = server_name.to_owned();

            let tcp_stream = match &server_name {
                &ServerName::IpAddress(ip) => {
                    tcp_connector
                        .connect(SocketAddr::new(ip.into(), port))
                        .await?
                }

                ServerName::DnsName(dns_name) => {
                    let ip = dns_resolver.resolve(dns_name.as_ref()).await?;

                    tcp_connector.connect(SocketAddr::new(ip, port)).await?
                }

                _ => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        format!("unknown server name {server_name:?}"),
                    ));
                }
            };

            let tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

            Ok(GenericTlsStream { tls_stream })
        }
    }
}

struct GenericTlsStream<IO> {
    tls_stream: TlsStream<IO>,
}

impl<IO: Connection> Connection for GenericTlsStream<IO> {
    fn connected(&self) -> Connected {
        self.tls_stream.get_ref().0.connected()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Read for GenericTlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Safety: we won't read it, unless IO implement is stupid:(
        let buf_mut = unsafe {
            let buf_mut = buf.as_mut();
            slice::from_raw_parts_mut(buf_mut.as_mut_ptr().cast(), buf_mut.len())
        };

        let n = ready!(Pin::new(&mut self.tls_stream).poll_read(cx, buf_mut))?;

        // Safety: n is written
        unsafe {
            buf.advance(n);
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Write for GenericTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tls_stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_close(cx)
    }
}
