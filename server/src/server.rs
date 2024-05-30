use std::future::Future;
use std::io;

use futures_rustls::rustls::ServerConfig;
use futures_util::{Stream, StreamExt, TryStreamExt};
use hyper_util::rt::TokioTimer;
use protocol::accept::Executor;
use protocol::auth::Auth;
use protocol::HyperListener;
use share::dns::HickoryDnsResolver;
use share::proxy;
use share::tcp_wrapper::{TcpListenerAddrStream, TokioTcp};
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::Error;

type TokioTcpAcceptor = impl Stream<Item = io::Result<TokioTcp>> + Send + Unpin;

pub struct HyperServer {
    protocol_listener: HyperListener<TokioTcpAcceptor, TokioExecutorWrapper, HickoryDnsResolver>,
}

#[derive(Clone)]
struct TokioExecutorWrapper;

impl Executor for TokioExecutorWrapper {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        tokio::spawn(fut);
    }
}

impl HyperServer {
    pub fn new(
        token_header: String,
        auth: Auth,
        tcp_listener: TcpListener,
        server_tls_config: ServerConfig,
    ) -> Result<Self, Error> {
        let tcp_listener =
            TcpListenerAddrStream::from(tcp_listener).map_ok(|(stream, _)| TokioTcp::from(stream));

        let protocol_listener = HyperListener::new(
            tcp_listener,
            TokioExecutorWrapper,
            server_tls_config,
            token_header,
            auth,
            HickoryDnsResolver::new()?,
            TokioTimer::new(),
        );

        Ok(Self { protocol_listener })
    }

    pub async fn start(self) -> Result<(), Error> {
        let (task, mut acceptor) = self.protocol_listener.listen();

        while let Some(res) = acceptor.next().await {
            let addrs = res.0;
            let writer = res.1;
            let reader = res.2;

            tokio::spawn(async move {
                let tcp_stream = TcpStream::connect(addrs.as_slice())
                    .await
                    .tap_err(|err| error!(?addrs, %err, "connect to target failed"))?;

                info!(?addrs, "connect to remote done");

                let (remote_in_tcp, remote_out_tcp) = tcp_stream.into_split();

                proxy::proxy(remote_in_tcp, remote_out_tcp, reader, writer).await
            });
        }

        task.stop();

        Err(Error::Other("acceptor stopped".into()))
    }
}
