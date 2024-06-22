use core::fmt::Display;
use core::fmt::Formatter;
use core::net::IpAddr;
use core::net::{self, SocketAddr};

use aya::Pod;
use share::helper::ArrayExt;

#[repr(C)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConnectedIpv4Addr {
    /// sport is native order
    pub sport: u16,

    /// dport is native order
    pub dport: u16,

    /// saddr is network order
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

unsafe impl Pod for ConnectedIpv4Addr {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Ipv4Addr {
    /// addr is network order
    pub addr: [u8; 4],

    /// port is native order
    pub port: u16,
    pub _padding: [u8; 2],
}

unsafe impl Pod for Ipv4Addr {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConnectedIpv6Addr {
    /// sport is native order
    pub sport: u16,

    /// dport is native order
    pub dport: u16,

    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

impl Display for ConnectedIpv6Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectedIpv6Addr")
            .field(
                "saddr:sport",
                &SocketAddr::new(
                    IpAddr::V6(net::Ipv6Addr::from(self.saddr.swap_bytes())),
                    self.sport,
                ),
            )
            .field(
                "daddr:dport",
                &SocketAddr::new(
                    IpAddr::V6(net::Ipv6Addr::from(self.daddr.swap_bytes())),
                    self.dport,
                ),
            )
            .finish()
    }
}

unsafe impl Pod for ConnectedIpv6Addr {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Ipv6Addr {
    /// addr is network order
    pub addr: [u8; 16],

    /// port is native order
    pub port: u16,
}

unsafe impl Pod for Ipv6Addr {}
