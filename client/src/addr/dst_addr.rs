use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use aya::maps::{HashMap, MapError, MapRefMut};
use aya::Pod;
use share::helper::ArrayExt;
use tap::TapFallible;
use tokio::sync::RwLock;
use tokio::time;
use tracing::error;

use crate::bpf_share::{
    ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr as ShareIpv4Addr, Ipv6Addr as ShareIpv6Addr,
};
use crate::err::Error;

pub trait LimitedBpfHashMap<K: Pod, V: Pod> {
    fn get(&self, key: &K) -> Result<V, MapError>;

    fn remove(&mut self, key: &K) -> Result<(), MapError>;
}

impl<K: Pod, V: Pod> LimitedBpfHashMap<K, V> for HashMap<MapRefMut, K, V> {
    fn get(&self, key: &K) -> Result<V, MapError> {
        HashMap::<MapRefMut, K, V>::get(self, key, 0)
    }

    fn remove(&mut self, key: &K) -> Result<(), MapError> {
        HashMap::<MapRefMut, K, V>::remove(self, key)
    }
}

pub struct DstAddrLookup<Map> {
    dst_addr_map: RwLock<Map>,
}

impl<Map> DstAddrLookup<Map> {
    pub fn new(map: Map) -> Self {
        Self {
            dst_addr_map: RwLock::new(map),
        }
    }
}

impl<Map: LimitedBpfHashMap<ConnectedIpv4Addr, ShareIpv4Addr>> DstAddrLookup<Map> {
    pub async fn lookup(
        &self,
        connected_addr: &ConnectedIpv4Addr,
        max_retry: usize,
    ) -> Result<Option<SocketAddr>, Error> {
        for _ in 0..max_retry {
            let map = self.dst_addr_map.read().await;
            match map.get(connected_addr) {
                Err(MapError::KeyNotFound) => {
                    time::sleep(Duration::from_millis(50)).await;

                    continue;
                }

                Err(err) => {
                    error!(%err, ?connected_addr, "get dst addr from connected v4 addr failed");

                    return Err(err.into());
                }

                Ok(dst_ipv4_addr) => {
                    let dst_addr = SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(dst_ipv4_addr.addr),
                        dst_ipv4_addr.port,
                    ));

                    drop(map);

                    self.dst_addr_map.write().await.remove(connected_addr).tap_err(
                        |err| error!(%err, ?connected_addr, "remove dst addr by v4 addr failed"),
                    )?;

                    return Ok(Some(dst_addr));
                }
            }
        }

        error!(?connected_addr, "dst addr not found");

        Ok(None)
    }
}

impl<Map: LimitedBpfHashMap<ConnectedIpv6Addr, ShareIpv6Addr>> DstAddrLookup<Map> {
    pub async fn lookup_v6(
        &self,
        connected_addr: &ConnectedIpv6Addr,
        max_retry: usize,
    ) -> Result<Option<SocketAddr>, Error> {
        for _ in 0..max_retry {
            let map = self.dst_addr_map.read().await;
            match map.get(connected_addr) {
                Err(MapError::KeyNotFound) => {
                    time::sleep(Duration::from_millis(50)).await;

                    continue;
                }

                Err(err) => {
                    error!(%err, ?connected_addr, "get dst addr from connected v6 addr failed");

                    return Err(err.into());
                }

                Ok(dst_ipv6_addr) => {
                    let dst_addr = SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(dst_ipv6_addr.addr.swap_bytes()),
                        dst_ipv6_addr.port,
                        0,
                        0,
                    ));

                    drop(map);

                    self.dst_addr_map.write().await.remove(connected_addr).tap_err(
                        |err| error!(%err, ?connected_addr, "remove dst addr by v4 addr failed"),
                    )?;

                    return Ok(Some(dst_addr));
                }
            }
        }

        error!(?connected_addr, "dst addr not found");

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::hash::Hash;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct MockBpfMap<K, V> {
        map: HashMap<K, V>,
        need_retry: AtomicUsize,
    }

    impl<K: Pod + Hash + Eq, V: Pod> LimitedBpfHashMap<K, V> for MockBpfMap<K, V> {
        fn get(&self, key: &K) -> Result<V, MapError> {
            if self.need_retry.load(Ordering::Acquire) == 0 {
                return self.map.get(key).ok_or(MapError::KeyNotFound).copied();
            }

            if self.need_retry.fetch_sub(1, Ordering::AcqRel) - 1 > 0 {
                return Err(MapError::KeyNotFound);
            }

            self.map.get(key).ok_or(MapError::KeyNotFound).copied()
        }

        fn remove(&mut self, key: &K) -> Result<(), MapError> {
            self.map.remove(key);

            Ok(())
        }
    }

    #[tokio::test]
    async fn load_addr_immediately() {
        let mut bpf_map = MockBpfMap {
            map: HashMap::<ConnectedIpv4Addr, ShareIpv4Addr>::new(),
            need_retry: AtomicUsize::new(0),
        };

        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: 80,
            dport: 80,
            saddr: [127, 0, 0, 1],
            daddr: [127, 0, 0, 2],
        };

        bpf_map.map.insert(
            connected_ipv4addr,
            ShareIpv4Addr {
                addr: [127, 0, 0, 2],
                port: 8080,
                _padding: [0; 2],
            },
        );

        let dst_addr_lookup = DstAddrLookup::new(bpf_map);

        assert_eq!(
            dst_addr_lookup
                .lookup(&connected_ipv4addr, 3)
                .await
                .unwrap()
                .unwrap(),
            SocketAddr::from_str("127.0.0.2:8080").unwrap()
        );

        assert!(dst_addr_lookup.dst_addr_map.read().await.map.is_empty());
    }

    #[tokio::test]
    async fn load_addr_after_retry() {
        let mut bpf_map = MockBpfMap {
            map: HashMap::<ConnectedIpv4Addr, ShareIpv4Addr>::new(),
            need_retry: AtomicUsize::new(2),
        };

        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: 80,
            dport: 80,
            saddr: [127, 0, 0, 1],
            daddr: [127, 0, 0, 2],
        };

        bpf_map.map.insert(
            connected_ipv4addr,
            ShareIpv4Addr {
                addr: [127, 0, 0, 2],
                port: 8080,
                _padding: [0; 2],
            },
        );

        let dst_addr_lookup = DstAddrLookup::new(bpf_map);

        assert_eq!(
            dst_addr_lookup
                .lookup(&connected_ipv4addr, 3)
                .await
                .unwrap()
                .unwrap(),
            SocketAddr::from_str("127.0.0.2:8080").unwrap()
        );

        assert!(dst_addr_lookup.dst_addr_map.read().await.map.is_empty());
    }

    #[tokio::test]
    async fn load_addr_timeout() {
        let mut bpf_map = MockBpfMap {
            map: HashMap::<ConnectedIpv4Addr, ShareIpv4Addr>::new(),
            need_retry: AtomicUsize::new(5),
        };

        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: 80,
            dport: 80,
            saddr: [127, 0, 0, 1],
            daddr: [127, 0, 0, 2],
        };

        bpf_map.map.insert(
            connected_ipv4addr,
            ShareIpv4Addr {
                addr: [127, 0, 0, 2],
                port: 8080,
                _padding: [0; 2],
            },
        );

        let dst_addr_lookup = DstAddrLookup::new(bpf_map);

        assert!(dst_addr_lookup
            .lookup(&connected_ipv4addr, 3)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn load_addr_not_exists() {
        let bpf_map = MockBpfMap {
            map: HashMap::<ConnectedIpv4Addr, ShareIpv4Addr>::new(),
            need_retry: AtomicUsize::new(2),
        };

        let connected_ipv4addr = ConnectedIpv4Addr {
            sport: 80,
            dport: 80,
            saddr: [127, 0, 0, 1],
            daddr: [127, 0, 0, 2],
        };

        let dst_addr_lookup = DstAddrLookup::new(bpf_map);

        assert!(dst_addr_lookup
            .lookup(&connected_ipv4addr, 3)
            .await
            .unwrap()
            .is_none());
    }
}
