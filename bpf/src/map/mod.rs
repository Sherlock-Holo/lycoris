use aya_ebpf::bindings::BPF_F_NO_PREALLOC;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap, SockMap};

use crate::{ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr, Ipv6Addr};

/// key is socket cookie, value is origin dst ipv4 addr
#[map]
pub static DST_IPV4_ADDR_STORE: LruHashMap<u64, Ipv4Addr> = LruHashMap::with_max_entries(4096, 0);

/// key is socket cookie, value is origin dst ipv6 addr
#[map]
pub static DST_IPV6_ADDR_STORE: LruHashMap<u64, Ipv6Addr> = LruHashMap::with_max_entries(4096, 0);

/// key is connected ipv4 addr, value is origin dst ipv4 addr
#[map]
pub static IPV4_ADDR_MAP: LruHashMap<ConnectedIpv4Addr, Ipv4Addr> =
    LruHashMap::with_max_entries(4096, 0);

/// key is connected ipv6 addr, value is origin dst ipv6 addr
#[map]
pub static IPV6_ADDR_MAP: LruHashMap<ConnectedIpv6Addr, Ipv6Addr> =
    LruHashMap::with_max_entries(4096, 0);

/// key is need proxy ipv4 addr, value is u8 and it's a bool type
#[map]
pub static PROXY_IPV4_LIST: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65535, BPF_F_NO_PREALLOC);

/// key is need proxy ipv6 addr, value is u8 and it's a bool type
#[map]
pub static PROXY_IPV6_LIST: LpmTrie<[u16; 8], u8> =
    LpmTrie::with_max_entries(65535, BPF_F_NO_PREALLOC);

/// proxy [`PROXY_IPV4_LIST`] and [`PROXY_IPV6_LIST`] list mode
///
/// `0` means the dst ip in list will connect directly
///
/// `1` means the dst ip in list will not be proxy
#[map]
pub static PROXY_LIST_MODE: Array<u8> = Array::with_max_entries(1, 0);

pub const CONNECT_DIRECTLY_MODE: u8 = 0;

/// only has 1 element
#[map]
pub static PROXY_IPV4_CLIENT: Array<Ipv4Addr> = Array::with_max_entries(2, 0);

/// only has 1 element
#[map]
pub static PROXY_IPV6_CLIENT: Array<Ipv6Addr> = Array::with_max_entries(2, 0);

/// process comm map
#[map]
pub static COMM_MAP: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// [`COMM_MAP`] mode
///
/// `0` means when comm in [`COMM_MAP`], connect directly
///
/// `1` means when comm not in [`COMM_MAP`], connect directly
#[map]
pub static COMM_MAP_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// proxy client listening socket map
#[map]
pub static ASSIGN_SOCK_MAP: SockMap = SockMap::with_max_entries(2, 0);
