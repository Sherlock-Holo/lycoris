use std::convert::Infallible;
use std::future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use http::{Request, Response, StatusCode, Version};
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Server};
use share::async_read_recv_stream::AsyncReadRecvStream;
use share::async_write_send_stream::AsyncWriteSendStream;
use share::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use share::hyper_body::{BodyStream, SinkBodySender};
use share::proxy;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{error, info, instrument};

use crate::auth::Auth;
use crate::h2_connection::Connection;
use crate::tls_accept::TlsAcceptor;
use crate::{addr, Error};

pub struct HyperServer {
    inner: Arc<HyperServerInner>,
    builder: Option<Builder<TlsAcceptor>>,
}

#[derive(Debug)]
struct HyperServerInner {
    token_header: String,
    auth: Auth,
}

impl HyperServerInner {
    #[instrument]
    async fn handle(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
        if request.version() != Version::HTTP_2 {
            error!("reject not http2 request");

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return Ok(response);
        }

        if !self.auth_token(&request) {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return Ok(response);
        }

        info!("http2 token auth done");

        let mut body = request.into_body();
        let addrs = match Self::get_remote_addrs(&mut body).await {
            Err(Error::AddrNotEnough) => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::BAD_REQUEST;

                return Ok(response);
            }

            Err(err) => return Err(err),

            Ok(addrs) => addrs,
        };

        info!(?addrs, "get remote addrs done");

        let tcp_stream = TcpStream::connect(addrs.as_slice())
            .await
            .tap_err(|err| error!(?addrs, %err, "connect to target failed"))?;

        info!(?addrs, "connect to remote done");

        let (body_sender, response_body) = Body::channel();
        let response = Response::new(response_body);

        tokio::spawn(async move {
            let (remote_in_tcp, remote_out_tcp) = tcp_stream.into_split();

            proxy::proxy(
                remote_in_tcp,
                remote_out_tcp,
                StreamReader::new(BodyStream::new(body)),
                SinkWriter::new(SinkBodySender::new(body_sender)),
            )
            .await
        });

        Ok(response)
    }

    async fn get_remote_addrs(body: &mut Body) -> Result<Vec<SocketAddr>, Error> {
        let data = body
            .try_next()
            .await
            .tap_err(|err| error!(%err, "get remote addr failed"))?;

        match data {
            None => {
                error!("no remote addrs got");

                Err(Error::AddrNotEnough)
            }

            Some(data) => {
                info!("get remote addrs data done");

                addr::parse_addr(&data).await
            }
        }
    }

    #[instrument]
    fn auth_token(&self, request: &Request<Body>) -> bool {
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

impl HyperServer {
    pub fn new(
        token_header: &str,
        auth: Auth,
        tcp_listener: TcpListener,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);
        let inner = Arc::new(HyperServerInner {
            token_header: token_header.to_string(),
            auth,
        });

        let builder = Server::builder(tls_acceptor)
            .http2_initial_stream_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(PING_TIMEOUT)
            .http2_keep_alive_interval(PING_INTERVAL);

        Self {
            inner,
            builder: Some(builder),
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        let inner = self.inner.clone();

        let builder = self.builder.take().expect("server has been stopped");

        builder
            .serve(make_service_fn(move |_conn| {
                let inner = inner.clone();

                future::ready(Ok::<_, Infallible>(service_fn(move |req| {
                    let inner = inner.clone();

                    async move { inner.handle(req).await }
                })))
            }))
            .await?;

        Ok(())
    }
}

pub struct H2Server {
    token_header: Arc<str>,
    auth: Arc<Auth>,
    tcp_listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
}

impl H2Server {
    pub fn new(
        token_header: &str,
        auth: Auth,
        tcp_listener: TcpListener,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        Self {
            token_header: token_header.into(),
            auth: Arc::new(auth),
            tcp_listener,
            tls_acceptor,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        loop {
            let tcp_stream = match self.tcp_listener.accept().await {
                Err(err) => {
                    error!(%err, "accept tcp failed");

                    continue;
                }

                Ok((tcp_stream, _)) => tcp_stream,
            };

            info!("accept tcp stream done");

            let tls_acceptor = self.tls_acceptor.clone();
            let token_header = self.token_header.clone();
            let token_auth = self.auth.clone();

            tokio::spawn(async move {
                let tls_stream = tls_acceptor
                    .accept(tcp_stream)
                    .await
                    .tap_err(|err| error!(%err, "accept tls stream failed"))?;

                info!("accept tls stream done");

                let mut h2_connection = Connection::handshake(tls_stream).await?;

                info!("h2 connection handshake done");

                while let Some(h2_stream) = h2_connection.accept_h2_stream().await {
                    let (h2_request, h2_respond) = h2_stream?;

                    let token_header = token_header.clone();
                    let token_auth = token_auth.clone();

                    tokio::spawn(async move {
                        handle_h2_stream(h2_request, h2_respond, &token_header, &token_auth).await
                    });
                }

                info!("no more h2 stream can be accepted, close h2 connection");

                h2_connection.close().await;

                Ok::<_, Error>(())
            });
        }
    }
}

fn auth(
    token_header: &str,
    h2_request: &mut Request<RecvStream>,
    h2_respond: &mut SendResponse<Bytes>,
    auth: &Auth,
) -> Result<bool, Error> {
    let token = match h2_request.headers().get(token_header) {
        None => {
            error!("the h2 request doesn't have token header, reject it");

            h2_respond.send_reset(Reason::REFUSED_STREAM);

            return Err(Error::AuthFailed);
        }

        Some(token) => token
            .to_str()
            .tap_err(|err| error!(%err,"token is not valid utf8 string"))
            .map_err(|_| Error::AuthFailed)?,
    };

    Ok(auth.auth(token))
}

async fn get_remote_addrs(in_stream: &mut RecvStream) -> Result<Vec<SocketAddr>, Error> {
    let data = match in_stream.next().await {
        None => {
            error!("receive address failed");

            return Err(Error::AddrNotEnough);
        }

        Some(data) => data.tap_err(|err| error!(%err, "receive address failed"))?,
    };

    info!("receive address data done");

    addr::parse_addr(&data).await
}

async fn handle_h2_stream(
    mut h2_request: Request<RecvStream>,
    mut h2_respond: SendResponse<Bytes>,
    token_header: &str,
    token_auth: &Auth,
) -> Result<(), Error> {
    let auth_result = auth(token_header, &mut h2_request, &mut h2_respond, token_auth)?;
    if !auth_result {
        h2_respond.send_reset(Reason::REFUSED_STREAM);

        return Err(Error::AuthFailed);
    }

    info!("token auth pass");

    let mut in_stream = h2_request.into_body();

    let remote_addrs = get_remote_addrs(&mut in_stream).await?;

    info!(?remote_addrs, "get remote addrs done");

    let mut h2_send_stream = h2_respond
        .send_response(Response::new(()), false)
        .tap_err(|err| error!(%err, "send dummy response failed"))?;

    let remote_tcp_stream = match TcpStream::connect(remote_addrs.as_slice()).await {
        Err(err) => {
            error!(%err, ?remote_addrs, "connect to target failed");

            let reason = match err.kind() {
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted => {
                    Reason::REFUSED_STREAM
                }
                ErrorKind::TimedOut => Reason::SETTINGS_TIMEOUT,
                ErrorKind::Interrupted => Reason::CANCEL,

                _ => Reason::INTERNAL_ERROR,
            };

            h2_send_stream.send_reset(reason);

            return Err(err.into());
        }

        Ok(remote_tcp_stream) => remote_tcp_stream,
    };

    info!(?remote_addrs, "connect to remote done");

    let (remote_in_tcp, remote_out_tcp) = remote_tcp_stream.into_split();

    proxy::proxy(
        remote_in_tcp,
        remote_out_tcp,
        AsyncReadRecvStream::new(in_stream),
        AsyncWriteSendStream::new(h2_send_stream),
    )
    .await?;

    Ok::<_, Error>(())
}
