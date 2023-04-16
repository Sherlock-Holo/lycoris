use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum DomainOrSocketAddr {
    Domain { domain: String, port: u16 },

    SocketAddr(SocketAddr),
}

impl From<SocketAddr> for DomainOrSocketAddr {
    fn from(value: SocketAddr) -> Self {
        Self::SocketAddr(value)
    }
}
