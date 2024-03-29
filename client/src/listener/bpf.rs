use std::fmt::{Debug, Formatter};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::Context;
use aya::maps::{HashMap, Map, MapData};
use futures_util::stream::SelectAll;
use futures_util::{stream, StreamExt};
use share::helper::Ipv6AddrExt;
use share::tcp_listener_stream::TcpListenerAddrStream;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, instrument, warn};

use super::Listener;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::addr::DstAddrLookup;
use crate::bpf_share::{
    ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr as ShareIpv4Addr, Ipv6Addr as ShareIpv6Addr,
};

const MAX_RETRY: usize = 3;

pub struct BpfListener {
    v4_dst_addr_map: DstAddrLookup<HashMap<MapData, ConnectedIpv4Addr, ShareIpv4Addr>>,
    v6_dst_addr_map: DstAddrLookup<HashMap<MapData, ConnectedIpv6Addr, ShareIpv6Addr>>,
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
        mut ipv4_map: Map,
        mut ipv6_map: Map,
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

        // fix can't HashMap::try_from
        ipv4_map = match ipv4_map {
            Map::LruHashMap(map_data) => Map::HashMap(map_data),
            _ => unreachable!(),
        };

        // fix can't HashMap::try_from
        ipv6_map = match ipv6_map {
            Map::LruHashMap(map_data) => Map::HashMap(map_data),
            _ => unreachable!(),
        };

        let v4_dst_addr_map = DstAddrLookup::new(
            HashMap::try_from(ipv4_map).tap_err(|err| error!(%err, "create bpf hashmap failed"))?,
        );
        let v6_dst_addr_map = DstAddrLookup::new(
            HashMap::try_from(ipv6_map).tap_err(|err| error!(%err, "create bpf hashmap failed"))?,
        );

        Ok(Self {
            v4_dst_addr_map,
            v6_dst_addr_map,
            listen_addr,
            listen_addr_v6,
            container_bridge_listen_addr,
            container_bridge_listen_addr_v6,
            tcp_listeners,
        })
    }

    async fn handle_v4(
        &self,
        peer_addr: SocketAddrV4,
        tcp_stream: TcpStream,
    ) -> anyhow::Result<Option<(TcpStream, SocketAddr)>> {
        let local_addr = tcp_stream
            .local_addr()
            .with_context(|| "get tcp stream local addr failed")?;
        let local_addr = match local_addr {
            SocketAddr::V4(local_addr) => local_addr,
            SocketAddr::V6(_) => unreachable!("v4 tcp stream local ip must not be ipv6"),
        };

        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: peer_addr.port(),
            dport: local_addr.port(),
            saddr: peer_addr.ip().octets(),
            daddr: local_addr.ip().octets(),
        };

        match self
            .v4_dst_addr_map
            .lookup(&connected_ipv4addr, MAX_RETRY)
            .await?
        {
            None => {
                error!(
                    ?connected_ipv4addr,
                    "origin dst v4 addr not found, has to close tcp"
                );

                Ok(None)
            }

            Some(origin_dst_addr) => {
                info!(
                    ?connected_ipv4addr,
                    %origin_dst_addr,
                    "get origin dst addr by connected ipv4 addr done"
                );

                Ok(Some((tcp_stream, origin_dst_addr)))
            }
        }
    }

    async fn handle_v6(
        &self,
        peer_addr: SocketAddrV6,
        tcp_stream: TcpStream,
    ) -> anyhow::Result<Option<(TcpStream, SocketAddr)>> {
        let local_addr = tcp_stream
            .local_addr()
            .with_context(|| "get tcp stream local addr failed")?;
        let local_addr = match local_addr {
            SocketAddr::V6(local_addr) => local_addr,
            SocketAddr::V4(_) => unreachable!("v6 tcp stream local ip must not be ipv4"),
        };

        let connected_ipv6addr = ConnectedIpv6Addr {
            sport: peer_addr.port(),
            dport: local_addr.port(),
            saddr: peer_addr.ip().network_order_segments(),
            daddr: local_addr.ip().network_order_segments(),
        };

        match self
            .v6_dst_addr_map
            .lookup_v6(&connected_ipv6addr, MAX_RETRY)
            .await?
        {
            None => {
                error!(
                    ?connected_ipv6addr,
                    "origin dst v6 addr not found, has to close tcp"
                );

                Ok(None)
            }

            Some(origin_dst_addr) => {
                info!(
                    ?connected_ipv6addr,
                    %origin_dst_addr,
                    "get origin dst addr by connected ipv6 addr done"
                );

                Ok(Some((tcp_stream, origin_dst_addr)))
            }
        }
    }
}

impl Listener for BpfListener {
    type Stream = TcpStream;

    #[instrument(err(Debug))]
    async fn accept(&mut self) -> anyhow::Result<(Self::Stream, DomainOrSocketAddr)> {
        while let Some(result) = self.tcp_listeners.next().await {
            let (tcp_stream, peer_addr) = match result {
                Err(err) => {
                    warn!(%err, "accept tcp failed");

                    continue;
                }

                Ok(result) => result,
            };

            info!("accept tcp done");

            match peer_addr {
                SocketAddr::V6(peer_addr) => {
                    if let Some(result) = self.handle_v6(peer_addr, tcp_stream).await? {
                        let (tcp_stream, addr) = result;

                        return Ok((tcp_stream, DomainOrSocketAddr::SocketAddr(addr)));
                    }
                }

                SocketAddr::V4(peer_addr) => {
                    if let Some(result) = self.handle_v4(peer_addr, tcp_stream).await? {
                        let (tcp_stream, addr) = result;

                        return Ok((tcp_stream, DomainOrSocketAddr::SocketAddr(addr)));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("listener stop unexpectedly"))
    }
}
