use std::net::{SocketAddr, SocketAddrV4};

use aya::maps::{HashMap, MapRefMut};
use tap::TapFallible;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::addr::DstAddrLookup;
use crate::bpf_share::{ConnectedIpv4Addr, Ipv4Addr as ShareIpv4Addr};
use crate::err::Error;

pub struct Listener {
    v4_dst_addr_map: DstAddrLookup<HashMap<MapRefMut, ConnectedIpv4Addr, ShareIpv4Addr>>,
    listen_addr: SocketAddrV4,
    tcp_listener: TcpListener,
}

impl Listener {
    pub async fn new(listen_addr: SocketAddrV4, map_ref_mut: MapRefMut) -> Result<Self, Error> {
        let tcp_listener = TcpListener::bind(listen_addr)
            .await
            .tap_err(|err| error!(%err, %listen_addr, "listen tcp failed"))?;
        let v4_dst_addr_map = DstAddrLookup::new(
            HashMap::try_from(map_ref_mut)
                .tap_err(|err| error!(%err, "create bpf hashmap failed"))?,
        );

        Ok(Self {
            v4_dst_addr_map,
            listen_addr,
            tcp_listener,
        })
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), Error> {
        const MAX_RETRY: usize = 3;

        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Err(err) => {
                    warn!(%err, "accept tcp failed");

                    continue;
                }

                Ok(result) => result,
            };

            info!("accept tcp done");

            let peer_addr = match peer_addr {
                SocketAddr::V6(_) => {
                    warn!(%peer_addr, "ipv6 is not supported yet");

                    continue;
                }

                SocketAddr::V4(peer_addr) => peer_addr,
            };

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

                    continue;
                }

                Some(origin_dst_addr) => {
                    info!(
                        ?connected_ipv4addr,
                        %origin_dst_addr,
                        "get origin dst addr by connected ipv4 addr done"
                    );

                    return Ok((tcp_stream, origin_dst_addr));
                }
            }
        }
    }
}
