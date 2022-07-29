use std::future::poll_fn;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use futures_channel::mpsc;
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_channel::oneshot::{Receiver, Sender};
use futures_util::{AsyncRead, StreamExt};
use h2::client::{ResponseFuture, SendRequest};
use h2::{client, Reason, RecvStream, SendStream};
use http::header::HeaderName;
use http::Request;
use share::async_read_recv_stream::AsyncReadRecvStream;
use share::async_write_send_stream::AsyncWriteSendStream;
use tap::TapFallible;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TikioAsyncWrite, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::{error, info};

use crate::addr;
use crate::err::Error;
use crate::token::TokenGenerator;

#[async_trait::async_trait]
pub trait Connect {
    type Read: AsyncRead + Unpin + Send + 'static;
    type Write: AsyncWrite + Unpin + Send + 'static;

    async fn connect(addr: SocketAddr) -> Result<(Self::Read, Self::Write), Error>;
}

struct ConnectRequest {
    io_stream_sender: Option<
        Sender<
            Result<
                (
                    AsyncReadRecvStream<RecvStream>,
                    AsyncWriteSendStream<SendStream<Bytes>>,
                ),
                h2::Error,
            >,
        >,
    >,
    addr: SocketAddr,
}

pub struct Connector {
    tls_connector: TlsConnector,
    remote_server_name: ServerName,
    remote_addr: SocketAddr,
    token_generator: TokenGenerator,
    token_header: String,
    connect_request_sender: UnboundedSender<ConnectRequest>,
}

impl Connector {
    pub fn new(
        client_config: ClientConfig,
        remote_domain: &str,
        remote_port: u16,
        token_generator: TokenGenerator,
        token_header: &str,
    ) -> Result<Arc<Self>, Error> {
        let remote_addr = SocketAddr::from_str(&format!("{}:{}", remote_domain, remote_port))
            .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?;

        let remote_server_name = ServerName::try_from(remote_domain)
            .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?;

        let tls_connector = TlsConnector::from(Arc::new(client_config));

        let (sender, receiver) = mpsc::unbounded();

        let this = Arc::new(Self {
            tls_connector,
            remote_server_name,
            remote_addr,
            token_generator,
            token_header: token_header.to_string(),
            connect_request_sender: sender,
        });

        {
            let this = this.clone();

            tokio::spawn(async move { this.start_h2_connect_loop(receiver).await });
        }

        Ok(this)
    }

    async fn tls_handshake(&self, tcp_stream: TcpStream) -> Result<TlsStream<TcpStream>, Error> {
        let tls_stream = self
            .tls_connector
            .connect(self.remote_server_name.clone(), tcp_stream)
            .await
            .tap_err(|err| error!(%err, "tls connect failed"))?;

        Ok(tls_stream.into())
    }

    async fn get_new_h2_send_request(&self) -> Result<SendRequest<Bytes>, Error> {
        let tcp_stream = TcpStream::connect(self.remote_addr).await.tap_err(
            |err| error!(%err, remote_addr = %self.remote_addr, "connect to remote addr failed"),
        )?;

        info!(remote_addr = %self.remote_addr, "connect remote done");

        let tls_stream = self.tls_handshake(tcp_stream).await?;

        info!("tls handshake done");

        h2_handshake(tls_stream).await
    }

    async fn start_h2_connect_loop(
        &self,
        mut connect_request_receiver: UnboundedReceiver<ConnectRequest>,
    ) {
        loop {
            let mut send_request = if let Ok(send_request) = self.get_new_h2_send_request().await {
                send_request
            } else {
                continue;
            };

            info!("get new h2 send request done");

            'CONNECT_LOOP: while let Some(mut connect_request) =
                connect_request_receiver.next().await
            {
                let token = self.token_generator.generate_token();
                let mut request = Request::new(());
                request.headers_mut().insert(
                    self.token_header.parse::<HeaderName>().unwrap_or_else(|_| {
                        panic!("token header {} is invalid", self.token_header)
                    }),
                    token
                        .parse()
                        .unwrap_or_else(|_| panic!("token {} is invalid header value", token)),
                );

                match send_request.send_request(request, false) {
                    Err(err) => {
                        error!(%err, "send h2 request failed");

                        let _ = connect_request
                            .io_stream_sender
                            .take()
                            .unwrap()
                            .send(Err(err));

                        break 'CONNECT_LOOP;
                    }

                    Ok((response, send_stream)) => {
                        tokio::spawn(async move {
                            let result =
                                connect_remote_addr(send_stream, response, connect_request.addr)
                                    .await;

                            let _ = connect_request
                                .io_stream_sender
                                .take()
                                .unwrap()
                                .send(result);
                        });
                    }
                }
            }
        }
    }
}

async fn connect_remote_addr(
    mut send_stream: SendStream<Bytes>,
    response: ResponseFuture,
    remote_addr: SocketAddr,
) -> Result<
    (
        AsyncReadRecvStream<RecvStream>,
        AsyncWriteSendStream<SendStream<Bytes>>,
    ),
    h2::Error,
> {
    let remote_addr_data = addr::encode_addr(remote_addr);

    send_stream.reserve_capacity(remote_addr_data.len());

    while send_stream.capacity() < remote_addr_data.len() {
        match poll_fn(|cx| send_stream.poll_capacity(cx)).await {
            None => {
                error!("poll capacity return none");

                return Err(Reason::INTERNAL_ERROR.into());
            }

            Some(Err(err)) => {
                error!(%err, "poll capacity failed");

                return Err(err);
            }

            Some(Ok(_)) => continue,
        }
    }

    send_stream
        .send_data(remote_addr_data, false)
        .tap_err(|err| error!(%err, %remote_addr, "send remote addr failed"))?;

    info!(%remote_addr, "send remote addr done");

    let recv_stream = response
        .await
        .tap_err(|err| error!(%err, "get recv stream failed"))?;
    let recv_stream = recv_stream.into_body();

    info!("get recv stream done");

    Ok((
        AsyncReadRecvStream::new(recv_stream),
        AsyncWriteSendStream::new(send_stream),
    ))
}

async fn h2_handshake<IO: TokioAsyncRead + TikioAsyncWrite + Unpin + Send + 'static>(
    stream: IO,
) -> Result<SendRequest<Bytes>, Error> {
    let (mut send_request, h2_conn) = client::handshake(stream)
        .await
        .tap_err(|err| error!(%err, "h2 handshake failed"))?;

    tokio::spawn(async move {
        if let Err(err) = h2_conn.await {
            error!(%err, "h2 connection meet error");
        }
    });

    info!("h2 handshake done");

    send_request = send_request
        .ready()
        .await
        .tap_err(|err| error!(%err, "wait h2 send request ready failed"))?;

    Ok(send_request)
}
