use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use http::{Request, Response};
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{error, info};

use crate::async_read_recv_stream::AsyncReadRecvStream;
use crate::async_write_send_stream::AsyncWriteSendStream;
use crate::auth::Auth;
use crate::h2_connection::Connection;
use crate::{parse, proxy, Error};

pub struct Server {
    token_header: Arc<str>,
    auth: Arc<Auth>,
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new(
        token_header: &str,
        auth: Auth,
        tcp_listener: TcpListener,
        tls_acceptor: TlsAcceptor,
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

async fn get_remote_addr(in_stream: &mut RecvStream) -> Result<SocketAddr, Error> {
    let data = match in_stream.next().await {
        None => {
            error!("receive address failed");

            return Err(Error::AddrNotEnough);
        }

        Some(data) => data.tap_err(|err| error!(%err, "receive address failed"))?,
    };

    info!("receive address data done");

    parse::parse_addr(&data)
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

    let remote_addr = get_remote_addr(&mut in_stream).await?;

    info!(%remote_addr, "get remote addr done");

    let mut h2_send_stream = h2_respond
        .send_response(Response::new(()), false)
        .tap_err(|err| error!(%err, "send dummy response failed"))?;

    let remote_tcp_stream = match TcpStream::connect(remote_addr).await {
        Err(err) => {
            error!(%err, %remote_addr, "connect to target failed");

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

    info!(%remote_addr, "connect to remote done");

    let (remote_in_tcp, remote_out_tcp) = remote_tcp_stream.into_split();

    proxy::proxy(
        remote_in_tcp.compat(),
        remote_out_tcp.compat_write(),
        AsyncReadRecvStream::new(in_stream),
        AsyncWriteSendStream::new(h2_send_stream),
    )
    .await?;

    Ok::<_, Error>(())
}
