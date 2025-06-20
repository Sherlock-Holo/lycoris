use std::future::Future;

use futures_rustls::rustls::ServerConfig;
use futures_util::StreamExt;
use hyper_util::rt::TokioTimer;
use protocol::accept::Executor;
use protocol::auth::Auth;
use protocol::HyperListener;
use share::dns::HickoryDnsResolver;
use share::proxy;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use self::hidden::*;
use crate::Error;

mod hidden {
    use std::io;

    use futures_util::{Stream, TryStreamExt};
    use share::tcp_wrapper::{TcpListenerAddrStream, TokioTcp};
    use tokio::net::TcpListener;

    pub type TokioTcpAcceptor = impl Stream<Item = io::Result<TokioTcp>> + Send + Unpin;

    #[define_opaque(TokioTcpAcceptor)]
    pub fn new_it(tcp_listener: TcpListener) -> TokioTcpAcceptor {
        TcpListenerAddrStream::from(tcp_listener).map_ok(|(stream, _)| TokioTcp::from(stream))
    }
}

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
        let tcp_listener = new_it(tcp_listener);

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
        tokio::spawn(task);

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

        Err(Error::Other("acceptor stopped".into()))
    }
}
