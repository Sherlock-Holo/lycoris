use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
pub use dst_addr::DstAddrLookup;

use self::domain_or_socket_addr::DomainOrSocketAddr;

pub mod domain_or_socket_addr;
mod dst_addr;

/// encode addr to \[addr_type:1, addr:variant, port:2\]
pub fn encode_addr(addr: impl Into<DomainOrSocketAddr>) -> Bytes {
    match addr.into() {
        DomainOrSocketAddr::Domain { domain, port } => {
            let mut buf = BytesMut::with_capacity(1 + 2 + domain.as_bytes().len() + 2);

            buf.put_u8(1);
            buf.put_u16(domain.as_bytes().len() as _);
            buf.put(domain.as_bytes());
            buf.put_u16(port);

            buf.freeze()
        }
        DomainOrSocketAddr::SocketAddr(addr) => match addr {
            SocketAddr::V4(v4_addr) => {
                let mut buf = BytesMut::with_capacity(1 + 4 + 2);

                buf.put_u8(4);
                buf.put(v4_addr.ip().octets().as_slice());
                buf.put_u16(v4_addr.port());

                buf.freeze()
            }

            SocketAddr::V6(v6_addr) => {
                let mut buf = BytesMut::with_capacity(1 + 16 + 2);

                buf.put_u8(6);
                buf.put(v6_addr.ip().octets().as_slice());
                buf.put_u16(v6_addr.port());

                buf.freeze()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encode_v4() {
        let data = encode_addr(SocketAddr::from_str("127.0.0.1:80").unwrap());

        let mut correct = BytesMut::from(&[4, 127, 0, 0, 1][..]);
        correct.put_u16(80);

        assert_eq!(data, correct);
    }

    #[test]
    fn encode_v6() {
        let data = encode_addr(SocketAddr::from_str("[::1]:80").unwrap());

        let mut correct = BytesMut::from(&[6][..]);
        correct.put(Ipv6Addr::from_str("::1").unwrap().octets().as_slice());
        correct.put_u16(80);

        assert_eq!(data, correct);
    }

    #[test]
    fn encode_domain() {
        let data = encode_addr(DomainOrSocketAddr::Domain {
            domain: "www.example.com".to_string(),
            port: 80,
        });

        let mut correct = BytesMut::from(&[1][..]);
        correct.put_u16("www.example.com".as_bytes().len() as _);
        correct.put("www.example.com".as_bytes());
        correct.put_u16(80);

        assert_eq!(data, correct);
    }
}
