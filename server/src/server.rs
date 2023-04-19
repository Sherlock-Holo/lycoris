use std::convert::Infallible;
use std::future;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::TryStreamExt;
use http::{Request, Response, StatusCode, Version};
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Server};
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
