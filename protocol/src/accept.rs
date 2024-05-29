use std::convert::Infallible;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::{io, mem, slice};

use bytes::{Buf, Bytes};
use futures_channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures_rustls::rustls::ServerConfig;
use futures_rustls::server::TlsStream;
use futures_util::{AsyncRead, AsyncWrite, Stream, TryFutureExt, TryStreamExt};
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::rt::{Executor, Read, ReadBufCursor, Timer, Write};
use hyper::service::service_fn;
use hyper_util::server::conn::auto::Builder;
use thiserror::Error;
use tokio_util::io::StreamReader;
use tracing::{debug, error, info, instrument};

use crate::abort::{AbortHandle, Aborted, FutureAbortExt};
use crate::auth::Auth;
use crate::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use crate::hyper_body::{BodyStream, SinkBodySender};
use crate::DnsResolver;

pub struct ListenTask {
    abort: AbortHandle,
}

impl ListenTask {
    pub fn stop(&self) {
        self.abort.abort();
    }
}

pub struct HyperListener<A, E, D> {
    tls_acceptor: TlsAcceptor<A>,
    executor: E,
    builder: Builder<E>,
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
        let mut builder = Builder::new(executor.clone());
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

impl<IO, A, E, D> HyperListener<A, E, D>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    A: Stream<Item = io::Result<IO>> + Unpin,
    E: Clone,
    for<Fut> E: Executor<Fut>,
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
        let abort = AbortHandle::default();
        let (acceptor_tx, acceptor_rx) = mpsc::unbounded();
        let builder = Arc::new(builder);
        let handler = Arc::new(HyperServerHandler { token_header, auth });
        let abort_clone = abort.clone();
        executor.clone().execute(Box::pin(
            async move {
                loop {
                    let stream = match tls_acceptor.accept().await {
                        Err(err) => {
                            error ! ( % err, "accept tls failed");

                            continue;
                        }

                        Ok(stream) => stream,
                    };

                    let handler = handler.clone();
                    let builder = builder.clone();
                    let acceptor_tx = acceptor_tx.clone();
                    let dns_resolver = dns_resolver.clone();

                    executor.execute(Box::pin(
                        async move {
                            let connection =
                                builder.serve_connection(
                                    stream,
                                    service_fn(move |req| {
                                        let handler = handler.clone();
                                        let acceptor_tx = acceptor_tx.clone();
                                        let dns_resolver = dns_resolver.clone();

                                        async move {
                                            handler.handle(req, acceptor_tx, dns_resolver).await
                                        }
                                    }),
                                );

                            connection.await.map_err(Error::Other)?;

                            Ok::<_, Error>(())
                        }
                        .abortable(&abort_clone)
                        .map_err(Error::Aborted),
                    ));
                }
            }
            .abortable(&abort)
            .map_err(Error::Aborted),
        ));

        (
            ListenTask { abort },
            HyperAcceptor {
                receiver: acceptor_rx,
            },
        )
    }
}

pub type AcceptorResult = (
    Vec<SocketAddr>,
    SinkBodySender<Infallible>,
    StreamReader<BodyStream, Bytes>,
);

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

        let (body_tx, body_rx) = mpsc::unbounded();
        let response = Response::new(StreamBody::new(body_rx).boxed());
        let stream_reader = StreamReader::new(BodyStream::from(body));
        let sink_body_sender = SinkBodySender::from(body_tx);

        result_tx
            .unbounded_send((addrs, sink_body_sender, stream_reader))
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
    pub fn new(tcp_acceptor: A, server_tls_config: ServerConfig) -> Self {
        Self {
            tcp_acceptor,
            tls_acceptor: futures_rustls::TlsAcceptor::from(Arc::new(server_tls_config)),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin, A: Stream<Item = io::Result<IO>> + Unpin> TlsAcceptor<A> {
    async fn accept(&mut self) -> io::Result<HyperTlsStream<IO>> {
        let stream = self
            .tcp_acceptor
            .try_next()
            .await?
            .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "TCP acceptor closed"))?;
        self.tls_acceptor.accept(stream).await.map(HyperTlsStream)
    }
}

pub struct HyperTlsStream<IO>(TlsStream<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Read for HyperTlsStream<IO> {
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

        let n = ready!(Pin::new(&mut self.0).poll_read(cx, buf_mut))?;

        // Safety: n is written
        unsafe {
            buf.advance(n);
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Write for HyperTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
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

    #[error("auth failed")]
    AuthFailed,

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("build auth failed: {0:?}")]
    Auth(totp_rs::TotpUrlError),

    #[error(transparent)]
    Aborted(#[from] Aborted),
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
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
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
