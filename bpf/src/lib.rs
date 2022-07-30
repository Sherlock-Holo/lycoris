#![no_std]

pub use cgroup_connect4::handle_cgroup_connect4;
pub use sockops_callback::handle_sockops;

mod cgroup_connect4;
mod kernel_binding;
mod map;
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
