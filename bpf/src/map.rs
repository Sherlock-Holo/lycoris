use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr;

use aya_ebpf::bindings::BPF_F_NO_PREALLOC;
use aya_ebpf::bindings::bpf_map_type::BPF_MAP_TYPE_SK_STORAGE;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap};

use crate::{ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr, Ipv6Addr};

/// key is ipv4 tcp 4 tuple, value is origin dst ipv4 addr
#[map]
pub static DST_IPV4_ADDR_STORE: LruHashMap<ConnectedIpv4Addr, Ipv4Addr> =
    LruHashMap::with_max_entries(4096, 0);

/// key is ipv6 tcp 4 tuple, value is origin dst ipv6 addr
#[map]
pub static DST_IPV6_ADDR_STORE: LruHashMap<ConnectedIpv6Addr, Ipv6Addr> =
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
/// `1` means the dst ip in list will connect through proxy
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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SkStore<V> {
    r#type: *const [c_int; BPF_MAP_TYPE_SK_STORAGE as _],
    map_flags: *const [c_int; BPF_F_NO_PREALLOC as _],
    key: *const c_int,
    value: *const V,
    max_entries: *const [c_int; 0],
}

unsafe impl<V: Sync> Sync for SkStore<V> {}

#[repr(transparent)]
#[derive(Debug)]
pub struct SkStoreWrapper<V> {
    value: UnsafeCell<SkStore<V>>,
}

impl<V> SkStoreWrapper<V> {
    pub const fn new() -> Self {
        Self {
            value: UnsafeCell::new(SkStore {
                r#type: ptr::null(),
                map_flags: ptr::null(),
                key: ptr::null(),
                value: ptr::null(),
                max_entries: ptr::null(),
            }),
        }
    }

    pub const fn get(&self) -> *mut c_void {
        self.value.get().cast()
    }
}

unsafe impl<V: Sync> Sync for SkStoreWrapper<V> {}

// can't use UnsafeCell or SyncUnsafeCell, otherwise will report error
// ParseError(BtfError(UnexpectedBtfType { type_id: 1 }))
#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "CONNECT_DST_IPV4_ADDR_STORAGE")]
pub static CONNECT_DST_IPV4_ADDR_STORAGE: SkStoreWrapper<Ipv4Addr> = SkStoreWrapper::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "CONNECT_DST_IPV6_ADDR_STORAGE")]
pub static mut CONNECT_DST_IPV6_ADDR_STORAGE: SkStoreWrapper<Ipv6Addr> = SkStoreWrapper::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "PASSIVE_DST_IPV4_ADDR_STORAGE")]
pub static mut PASSIVE_DST_IPV4_ADDR_STORAGE: SkStoreWrapper<Ipv4Addr> = SkStoreWrapper::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "PASSIVE_DST_IPV6_ADDR_STORAGE")]
pub static mut PASSIVE_DST_IPV6_ADDR_STORAGE: SkStoreWrapper<Ipv6Addr> = SkStoreWrapper::new();
