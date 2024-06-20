#![no_std]

use core::mem;

pub use cgroup_connect4::handle_cgroup_connect4;
pub use cgroup_connect6::handle_cgroup_connect6;
pub use getsockname::handle_getsockname;
pub use sockops_callback::handle_sockops;

mod cgroup_connect4;
mod cgroup_connect6;
mod command_check;
mod getsockname;
mod kernel_binding;
mod map;
mod safe_helper;
mod sockops_callback;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectedIpv4Addr {
    pub sport: u16,
    pub dport: u16,

    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv4Addr {
    pub addr: [u8; 4],
    pub port: u16,
    pub _padding: [u8; 2],
}

impl PartialEq<(u32, u16)> for Ipv4Addr {
    fn eq(&self, other: &(u32, u16)) -> bool {
        u32::from_be_bytes(self.addr) == other.0 && u16::from_be(self.port) == other.1
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectedIpv6Addr {
    pub sport: u16,
    pub dport: u16,

    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Ipv6Addr {
    pub addr: [u16; 8],
    pub port: u16,
}

#[inline]
fn connect_directly(in_list_connect_directly: bool, in_list: bool) -> bool {
    in_list_connect_directly && in_list
}

#[inline]
fn u16_ipv6_to_u8_ipv6(addr: [u16; 8]) -> [u8; 16] {
    unsafe { mem::transmute(addr) }
}
