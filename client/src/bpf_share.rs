use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConnectedIpv4Addr {
    pub sport: u16,
    pub dport: u16,

    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

unsafe impl Pod for ConnectedIpv4Addr {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Ipv4Addr {
    pub addr: [u8; 4],
    pub port: u16,
    pub _padding: [u8; 2],
}

unsafe impl Pod for Ipv4Addr {}
