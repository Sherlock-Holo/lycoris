use std::io::{self, ErrorKind};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use aya::maps::{HashMap, Map, MapData};
use futures_util::stream::Select;
use futures_util::{stream, StreamExt};
use share::helper::Ipv6AddrExt;
use share::tcp_listener_stream::TcpListenerAddrStream;
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use super::Listener;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::addr::DstAddrLookup;
use crate::bpf_share::{
    ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr as ShareIpv4Addr, Ipv6Addr as ShareIpv6Addr,
};
use crate::err::Error;

const MAX_RETRY: usize = 3;

pub struct BpfListener {
    v4_dst_addr_map: DstAddrLookup<HashMap<MapData, ConnectedIpv4Addr, ShareIpv4Addr>>,
    v6_dst_addr_map: DstAddrLookup<HashMap<MapData, ConnectedIpv6Addr, ShareIpv6Addr>>,
    listen_addr: SocketAddrV4,
    listen_addr_v6: SocketAddrV6,
    tcp_listener: Select<TcpListenerAddrStream, TcpListenerAddrStream>,
}

impl BpfListener {
    pub async fn new(
        listen_addr: SocketAddrV4,
        listen_addr_v6: SocketAddrV6,
        mut ipv4_map: Map,
        mut ipv6_map: Map,
    ) -> Result<Self, Error> {
        let tcp_listener = TcpListener::bind(listen_addr)
            .await
            .tap_err(|err| error!(%err, %listen_addr, "listen tcp4 failed"))?;
        let tcp_listener6 = TcpListener::bind(listen_addr_v6)
            .await
            .tap_err(|err| error!(%err, "listen tcp6 failed"))?;

        let tcp_listener = stream::select(
            TcpListenerAddrStream::from(tcp_listener),
            TcpListenerAddrStream::from(tcp_listener6),
        );

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
            tcp_listener,
        })
    }

    async fn handle_v4(
        &self,
        peer_addr: SocketAddrV4,
        tcp_stream: TcpStream,
    ) -> Result<Option<(TcpStream, SocketAddr)>, Error> {
        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: peer_addr.port(),
            dport: self.listen_addr.port(),
            saddr: peer_addr.ip().octets(),
            daddr: self.listen_addr.ip().octets(),
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
    ) -> Result<Option<(TcpStream, SocketAddr)>, Error> {
        let connected_ipv6addr = ConnectedIpv6Addr {
            sport: peer_addr.port(),
            dport: self.listen_addr.port(),
            saddr: peer_addr.ip().network_order_segments(),
            daddr: self.listen_addr_v6.ip().network_order_segments(),
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

#[async_trait]
impl Listener for BpfListener {
    type Stream = TcpStream;

    async fn accept(&mut self) -> Result<(Self::Stream, DomainOrSocketAddr), Error> {
        while let Some(result) = self.tcp_listener.next().await {
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

        error!("listener stop unexpectedly");

        Err(Error::Io(io::Error::new(
            ErrorKind::Other,
            "listener stop unexpectedly",
        )))
    }
}
