use std::convert::Infallible;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{io, mem};

use bytes::{Buf, Bytes};
use futures_channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
pub use futures_rustls::rustls::ServerConfig;
use futures_util::future::BoxFuture;
use futures_util::{AsyncRead, AsyncWrite, Stream, TryStreamExt};
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::rt::{Executor as HyperExecutor, Timer};
use hyper::service::service_fn;
use hyper_util::server::conn::auto::Builder;
use thiserror::Error;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, error, info, instrument};

use crate::auth::Auth;
use crate::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use crate::hyper_body::{BodyStream, SinkBodySender};
use crate::{DnsResolver, GenericTlsStream, Reader, Writer};

#[must_use]
pub struct ListenTask {
    fut: BoxFuture<'static, ()>,
}

impl Future for ListenTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.fut).poll(cx)
    }
}

pub struct HyperListener<A, E, D> {
    tls_acceptor: TlsAcceptor<A>,
    executor: E,
    builder: Builder<ExecutorWrapper<E>>,
    token_header: String,
    auth: Auth,
    dns_resolver: D,
}

impl<A, E: Clone, D> HyperListener<A, E, D> {
    pub fn new<T: Timer + Send + Sync + 'static>(
        tcp_acceptor: A,
        executor: E,
        server_tls_config: ServerConfig,
        token_header: String,
        auth: Auth,
        dns_resolver: D,
        timer: T,
    ) -> Self {
        let mut builder = Builder::new(ExecutorWrapper(executor.clone()));
        builder
            .http2()
            .timer(timer)
            .initial_stream_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .keep_alive_timeout(PING_TIMEOUT)
            .keep_alive_interval(PING_INTERVAL);

        Self {
            tls_acceptor: TlsAcceptor::new(tcp_acceptor, server_tls_config),
            executor,
            builder,
            token_header,
            auth,
            dns_resolver,
        }
    }
}

pub trait Executor {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static;
}

#[derive(Clone)]
struct ExecutorWrapper<E>(E);

impl<Fut, E: Executor> HyperExecutor<Fut> for ExecutorWrapper<E>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        self.0.execute(fut)
    }
}

impl<IO, A, E, D> HyperListener<A, E, D>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: Stream<Item = io::Result<IO>> + Unpin + Send + 'static,
    E: Executor + Clone + Send + Sync + 'static,
    D: DnsResolver + Clone + 'static,
{
    pub fn listen(self) -> (ListenTask, HyperAcceptor) {
        let Self {
            mut tls_acceptor,
            executor,
            builder,
            token_header,
            auth,
            dns_resolver,
        } = self;

        let (acceptor_tx, acceptor_rx) = mpsc::unbounded();
        let builder = Arc::new(builder);
        let handler = Arc::new(HyperServerHandler { token_header, auth });

        let fut = Box::pin(async move {
            loop {
                let stream = match tls_acceptor.accept().await {
                    Err(err) => {
                        error!( % err, "accept tls failed");

                        continue;
                    }

                    Ok(stream) => stream,
                };

                let handler = handler.clone();
                let builder = builder.clone();
                let acceptor_tx = acceptor_tx.clone();
                let dns_resolver = dns_resolver.clone();

                executor.execute(Box::pin(async move {
                    let connection = builder.serve_connection(
                        stream,
                        service_fn(move |req| {
                            let handler = handler.clone();
                            let acceptor_tx = acceptor_tx.clone();
                            let dns_resolver = dns_resolver.clone();

                            async move { handler.handle(req, acceptor_tx, dns_resolver).await }
                        }),
                    );

                    connection.await.map_err(Error::Other)?;

                    Ok::<_, Error>(())
                }));
            }
        });

        (
            ListenTask { fut },
            HyperAcceptor {
                receiver: acceptor_rx,
            },
        )
    }
}

pub type AcceptorResult = (Vec<SocketAddr>, Writer, Reader);

#[derive(Debug)]
pub struct HyperAcceptor {
    receiver: UnboundedReceiver<AcceptorResult>,
}

impl Stream for HyperAcceptor {
    type Item = AcceptorResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

#[derive(Debug)]
struct HyperServerHandler {
    token_header: String,
    auth: Auth,
}

impl HyperServerHandler {
    #[instrument(skip(dns_resolver))]
    async fn handle<D: DnsResolver>(
        &self,
        request: Request<Incoming>,
        result_tx: UnboundedSender<AcceptorResult>,
        dns_resolver: D,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Error> {
        if request.version() != Version::HTTP_2 {
            error!("reject not http2 request");

            let mut response = Response::new(Empty::new().boxed());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return Ok(response);
        }

        if !self.auth_token(&request) {
            let mut response = Response::new(Empty::new().boxed());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return Ok(response);
        }

        info!("http2 token auth done");

        let mut body = request.into_body();
        let addrs = match Self::get_remote_addrs(&mut body, dns_resolver).await {
            Err(Error::AddrNotEnough) => {
                let mut response = Response::new(Empty::new().boxed());
                *response.status_mut() = StatusCode::BAD_REQUEST;

                return Ok(response);
            }

            Err(err) => return Err(err),

            Ok(addrs) => addrs,
        };

        info!(?addrs, "get remote addrs done");

        let (body_tx, body_rx) = mpsc::channel(1);
        let response = Response::new(StreamBody::new(body_rx).boxed());
        let stream_reader = StreamReader::new(BodyStream::from(body));
        let sink_body_sender = SinkBodySender::from(body_tx);

        result_tx
            .unbounded_send((
                addrs,
                Writer(SinkWriter::new(sink_body_sender)),
                Reader(stream_reader),
            ))
            .map_err(|err| Error::Other(err.into()))?;

        Ok(response)
    }

    #[instrument(skip(dns_resolver), err(Debug))]
    async fn get_remote_addrs<D: DnsResolver>(
        body: &mut Incoming,
        dns_resolver: D,
    ) -> Result<Vec<SocketAddr>, Error> {
        let frame = match body.frame().await {
            None => return Err(Error::AddrNotEnough),
            Some(Err(err)) => return Err(err.into()),
            Some(Ok(frame)) => frame,
        };

        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_) => return Err(Error::AddrNotEnough),
        };

        debug!("get remote addrs data done");

        parse_addr(&data, dns_resolver).await
    }

    #[instrument(ret)]
    fn auth_token(&self, request: &Request<Incoming>) -> bool {
        let token = match request.headers().get(&self.token_header) {
            None => {
                error!("the h2 request doesn't have token header, reject it");

                return false;
            }

            Some(token) => match token.to_str() {
                Err(err) => {
                    error!(%err,"token is not valid utf8 string");

                    return false;
                }

                Ok(token) => token,
            },
        };

        self.auth.auth(token)
    }
}

#[derive(Clone)]
struct TlsAcceptor<A> {
    tcp_acceptor: A,
    tls_acceptor: futures_rustls::TlsAcceptor,
}

impl<A> TlsAcceptor<A> {
    fn new(tcp_acceptor: A, server_tls_config: ServerConfig) -> Self {
        Self {
            tcp_acceptor,
            tls_acceptor: futures_rustls::TlsAcceptor::from(Arc::new(server_tls_config)),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin, A: Stream<Item = io::Result<IO>> + Unpin> TlsAcceptor<A> {
    async fn accept(&mut self) -> io::Result<GenericTlsStream<IO>> {
        let stream = self
            .tcp_acceptor
            .try_next()
            .await?
            .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "TCP acceptor closed"))?;
        self.tls_acceptor
            .accept(stream)
            .await
            .map(|tls_stream| GenericTlsStream {
                tls_stream: tls_stream.into(),
            })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("http error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("address data is not enough")]
    AddrNotEnough,

    #[error("address type {0} is invalid, valid is `4` and `6`")]
    AddrTypeInvalid(u8),

    #[error("address domain invalid")]
    AddrDomainInvalid,

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Parse addr from data
/// the data format is \[addr_type:1,addr:variant,port:2\]
async fn parse_addr<D: DnsResolver>(
    mut data: &[u8],
    mut dns_resolver: D,
) -> Result<Vec<SocketAddr>, Error> {
    if data.is_empty() {
        return Err(Error::AddrNotEnough);
    }

    let addrs = match data[0] {
        1 => {
            data.advance(1);

            if data.len() < 2 {
                return Err(Error::AddrNotEnough);
            }

            let domain_len = data.get_u16() as usize;
            if data.len() < domain_len {
                return Err(Error::AddrNotEnough);
            }

            let domain = data.get(0..domain_len).unwrap();
            let domain = match String::from_utf8(domain.to_vec()) {
                Err(_) => {
                    return Err(Error::AddrDomainInvalid);
                }

                Ok(domain) => domain,
            };

            let addrs = dns_resolver.resolve(&domain).await?;

            data.advance(domain_len);
            if data.len() < 2 {
                return Err(Error::AddrNotEnough);
            }

            let port = data.get_u16();

            addrs
                .map_ok(|ip| SocketAddr::new(ip, port))
                .try_collect()
                .await?
        }

        4 => {
            data.advance(1);

            if data.len() != 4 + 2 {
                return Err(Error::AddrNotEnough);
            }

            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                u16::from_be_bytes(data[4..6].try_into().unwrap()),
            )]
        }

        6 => {
            data.advance(1);

            // 128 is ipv6 bits
            if data.len() != mem::size_of::<u128>() + 2 {
                return Err(Error::AddrNotEnough);
            }

            vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    data[..16].try_into().unwrap(),
                ))),
                u16::from_be_bytes(data[16..18].try_into().unwrap()),
            )]
        }

        n => return Err(Error::AddrTypeInvalid(n)),
    };

    Ok(addrs)
}
