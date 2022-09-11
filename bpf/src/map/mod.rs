use aya_bpf::bindings::BPF_F_NO_PREALLOC;
use aya_bpf::macros::map;
use aya_bpf::maps::{Array, LpmTrie, LruHashMap};

use crate::{ConnectedIpv4Addr, Ipv4Addr};

/// key is socket cookie, value is origin dst ipv4 addr
#[map]
pub static DST_IPV4_ADDR_STORE: LruHashMap<u64, Ipv4Addr> = LruHashMap::with_max_entries(4096, 0);

/// key is connected ipv4 addr, value is origin dst ipv4 addr
#[map]
pub static IPV4_ADDR_MAP: LruHashMap<ConnectedIpv4Addr, Ipv4Addr> =
    LruHashMap::with_max_entries(4096, 0);

/// key is need proxy ipv4 addr, value is u8 and it's a bool type
#[map]
pub static PROXY_IPV4_LIST: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65535, BPF_F_NO_PREALLOC);

/// proxy ipv4 list mode, 0 is blacklist mode, 1 is whitelist mode
/// when blacklist mode, the dst ip in list will be proxy
/// when whitelist mode, the dst ip in list will not be proxy
#[map]
pub static PROXY_IPV4_LIST_MODE: Array<u8> = Array::with_max_entries(1, 0);

pub const BLACKLIST_MODE: u8 = 0;

/// only has 1 element
#[map]
pub static PROXY_IPV4_CLIENT: Array<Ipv4Addr> = Array::with_max_entries(1, 0);

pub mod names;
