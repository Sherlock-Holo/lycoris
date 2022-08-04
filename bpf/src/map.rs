use aya_bpf::bindings::BPF_F_NO_PREALLOC;
use aya_bpf::macros::map;
use aya_bpf::maps::{Array, LpmTrie, LruHashMap};

use crate::{ConnectedIpv4Addr, Ipv4Addr};

#[map]
/// key is socket cookie, value is origin dst ipv4 addr
pub static DST_IPV4_ADDR_STORE: LruHashMap<u64, Ipv4Addr> = LruHashMap::with_max_entries(4096, 0);

#[map]
/// key is connected ipv4 addr, value is origin dst ipv4 addr
pub static IPV4_ADDR_MAP: LruHashMap<ConnectedIpv4Addr, Ipv4Addr> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
/// key is need proxy ipv4 addr, value is u8 and it's a bool type
pub static PROXY_IPV4_LIST: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65535, BPF_F_NO_PREALLOC);

#[map]
/// only has 1 element
pub static PROXY_SERVER: Array<Ipv4Addr> = Array::with_max_entries(1, 0);
