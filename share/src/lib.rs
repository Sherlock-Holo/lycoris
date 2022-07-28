#[cfg(feature = "userspace")]
pub mod async_read_recv_stream;
#[cfg(feature = "userspace")]
pub mod async_write_send_stream;
#[cfg_attr(not(feature = "userspace"), no_std)]
#[cfg(feature = "userspace")]
pub mod helper;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "userspace", derive(Debug, Hash, Eq, PartialEq))]
pub struct ConnectedIpv4Addr {
    pub sport: u16,
    pub dport: u16,

    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnectedIpv4Addr {}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "userspace", derive(Debug))]
pub struct Ipv4Addr {
    pub addr: [u8; 4],
    pub port: u16,
    pub _padding: [u8; 2],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for Ipv4Addr {}
