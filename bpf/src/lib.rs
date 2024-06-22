#![no_std]

use core::mem;

pub use cgroup_connect4::handle_cgroup_connect4;
pub use cgroup_connect6::handle_cgroup_connect6;
pub use get_sock_name::{get_sock_name4, get_sock_name6};
pub use sockops_callback::handle_sockops;

mod cgroup_connect4;
mod cgroup_connect6;
mod command_check;
mod get_sock_name;
mod kernel_binding;
mod map;
mod safe_helper;
mod sockops_callback;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectedIpv4Addr {
    /// sport is native order
    pub sport: u16,

    /// dport is native order
    pub dport: u16,

    /// saddr is network order
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv4Addr {
    /// addr is network order
    pub addr: [u8; 4],

    /// port is native order
    pub port: u16,
    pub _padding: [u8; 2],
}

impl PartialEq<([u8; 4], u16)> for Ipv4Addr {
    fn eq(&self, other: &([u8; 4], u16)) -> bool {
        self.addr == other.0 && self.port == other.1
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectedIpv6Addr {
    /// sport is native order
    pub sport: u16,

    /// dport is native order
    pub dport: u16,

    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Ipv6Addr {
    /// addr is network order
    pub addr: [u8; 16],

    /// port is native order
    pub port: u16,
}

#[inline]
fn connect_directly(in_list_connect_directly: bool, in_list: bool) -> bool {
    if in_list_connect_directly {
        in_list
    } else {
        !in_list
    }
}

#[inline]
fn u16_ipv6_to_u8_ipv6(addr: [u16; 8]) -> [u8; 16] {
    unsafe { mem::transmute(addr) }
}
