use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_channel::mpsc;
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use share::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use share::hyper_body::{BodyStream, SinkBodySender};
use share::proxy;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, error, info, instrument};

use crate::auth::Auth;
use crate::tls_accept::TlsAcceptor;
use crate::{addr, Error};

pub struct HyperServer {
    handler: Arc<HyperServerHandler>,
    builder: Builder<TokioExecutor>,
    tls_acceptor: TlsAcceptor,
}

#[derive(Debug)]
struct HyperServerHandler {
    token_header: String,
    auth: Auth,
}

impl HyperServerHandler {
    #[instrument]
    async fn handle(
        &self,
        request: Request<Incoming>,
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
        let addrs = match Self::get_remote_addrs(&mut body).await {
            Err(Error::AddrNotEnough) => {
                let mut response = Response::new(Empty::new().boxed());
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

        let (body_tx, body_rx) = mpsc::unbounded();
        let response = Response::new(StreamBody::new(body_rx).boxed());

        tokio::spawn(async move {
            let (remote_in_tcp, remote_out_tcp) = tcp_stream.into_split();

            proxy::proxy(
                remote_in_tcp,
                remote_out_tcp,
                StreamReader::new(BodyStream::from(body)),
                SinkWriter::new(SinkBodySender::from(body_tx)),
            )
            .await
        });

        Ok(response)
    }

    #[instrument(err(Debug))]
    async fn get_remote_addrs(body: &mut Incoming) -> Result<Vec<SocketAddr>, Error> {
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

        addr::parse_addr(&data).await
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

impl HyperServer {
    pub fn new(
        token_header: &str,
        auth: Auth,
        tcp_listener: TcpListener,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);
        let handler = Arc::new(HyperServerHandler {
            token_header: token_header.to_string(),
            auth,
        });

        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http2()
            .timer(TokioTimer::new())
            .initial_stream_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .keep_alive_timeout(PING_TIMEOUT)
            .keep_alive_interval(PING_INTERVAL);

        Self {
            handler,
            builder,
            tls_acceptor,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        loop {
            let stream = match self.tls_acceptor.accept().await {
                Err(err) => {
                    error!(%err, "accept tls failed");

                    continue;
                }

                Ok(stream) => stream,
            };

            let handler = self.handler.clone();
            let builder = self.builder.clone();

            tokio::spawn(async move {
                let connection = builder.serve_connection(
                    stream,
                    service_fn(move |req| {
                        let handler = handler.clone();
                        async move { handler.handle(req).await }
                    }),
                );

                connection.await
            });
        }
        /*let inner = self.inner.clone();

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

        Ok(())*/
    }
}
