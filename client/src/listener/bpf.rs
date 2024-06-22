use std::fmt::{Debug, Formatter};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::Context;
use futures_util::stream::SelectAll;
use futures_util::{stream, StreamExt};
use protocol::DomainOrSocketAddr;
use share::tcp_wrapper::TcpListenerAddrStream;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, instrument, warn};

use super::Listener;

pub struct BpfListener {
    listen_addr: SocketAddrV4,
    listen_addr_v6: SocketAddrV6,
    container_bridge_listen_addr: Option<SocketAddrV4>,
    container_bridge_listen_addr_v6: Option<SocketAddrV6>,
    tcp_listeners: SelectAll<TcpListenerAddrStream>,
}

impl Debug for BpfListener {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfListener")
            .field("listen_addr", &self.listen_addr)
            .field("listen_addr_v6", &self.listen_addr_v6)
            .field(
                "container_bridge_listen_addr",
                &self.container_bridge_listen_addr,
            )
            .field(
                "container_bridge_listen_addr_v6",
                &self.container_bridge_listen_addr_v6,
            )
            .finish_non_exhaustive()
    }
}

impl BpfListener {
    pub async fn new(
        listen_addr: SocketAddrV4,
        listen_addr_v6: SocketAddrV6,
        container_bridge_listen_addr: Option<SocketAddrV4>,
        container_bridge_listen_addr_v6: Option<SocketAddrV6>,
    ) -> anyhow::Result<Self> {
        let tcp_listener = TcpListener::bind(listen_addr)
            .await
            .tap_err(|err| error!(%err, %listen_addr, "listen tcp4 failed"))?;
        let tcp_listener6 = TcpListener::bind(listen_addr_v6)
            .await
            .tap_err(|err| error!(%err, "listen tcp6 failed"))?;

        let mut listeners = vec![
            TcpListenerAddrStream::from(tcp_listener),
            TcpListenerAddrStream::from(tcp_listener6),
        ];

        if let Some(addr) = container_bridge_listen_addr {
            let tcp_listener = TcpListener::bind(addr)
                .await
                .tap_err(|err| error!(%err, %addr, "listen container addr tcp4 failed"))?;

            listeners.push(TcpListenerAddrStream::from(tcp_listener));
        }
        if let Some(addr) = container_bridge_listen_addr_v6 {
            let tcp_listener = TcpListener::bind(addr)
                .await
                .tap_err(|err| error!(%err, %addr, "listen container addr tcp6 failed"))?;

            listeners.push(TcpListenerAddrStream::from(tcp_listener));
        }

        let tcp_listeners = stream::select_all(listeners);

        Ok(Self {
            listen_addr,
            listen_addr_v6,
            container_bridge_listen_addr,
            container_bridge_listen_addr_v6,
            tcp_listeners,
        })
    }

    fn is_listen_addr(&self, addr: SocketAddr) -> bool {
        for listen_addr in [
            SocketAddr::from(self.listen_addr),
            SocketAddr::from(self.listen_addr_v6),
        ]
        .into_iter()
        .chain(self.container_bridge_listen_addr.map(SocketAddr::from))
        .chain(self.container_bridge_listen_addr_v6.map(SocketAddr::from))
        {
            if listen_addr == addr {
                return true;
            }
        }

        false
    }
}

impl Listener for BpfListener {
    type Stream = TcpStream;

    #[instrument(err(Debug))]
    async fn accept(&mut self) -> anyhow::Result<(Self::Stream, DomainOrSocketAddr)> {
        while let Some(result) = self.tcp_listeners.next().await {
            let (tcp_stream, _) = match result {
                Err(err) => {
                    warn!(%err, "accept tcp failed");

                    continue;
                }

                Ok(result) => result,
            };

            let addr = tcp_stream
                .local_addr()
                .with_context(|| "get tcp local addr failed")?;

            if self.is_listen_addr(addr) {
                error!(%addr, "origin dst addr is listen addr, that's not allowed");

                continue;
            }

            info!("accept tcp done");

            return Ok((tcp_stream, DomainOrSocketAddr::SocketAddr(addr)));
        }

        Err(anyhow::anyhow!("listener stop unexpectedly"))
    }
}
