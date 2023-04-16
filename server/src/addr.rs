use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Buf;
use tokio::net::lookup_host;

use crate::Error;

/// parse addr from data
/// the data format is \[addr_type:1,addr:variant,port:2\]
pub async fn parse_addr(mut data: &[u8]) -> Result<Vec<SocketAddr>, Error> {
    if data.is_empty() {
        return Err(Error::AddrNotEnough);
    }

    let addrs = match data[0] {
        1 => {
            data.advance(1);

            if data.len() < 2 {
                return Err(Error::AddrNotEnough);
            }

            let domain_len = data.get_u16() as usize;
            if data.len() < domain_len {
                return Err(Error::AddrNotEnough);
            }

            let domain = data.get(0..domain_len).unwrap();
            let domain = match String::from_utf8(domain.to_vec()) {
                Err(_) => {
                    return Err(Error::AddrDomainInvalid);
                }

                Ok(domain) => domain,
            };

            data.advance(domain_len);
            if data.len() < 2 {
                return Err(Error::AddrNotEnough);
            }

            let port = data.get_u16();

            lookup_host((domain, port)).await?.collect::<Vec<_>>()
        }

        4 => {
            data.advance(1);

            if data.len() != 4 + 2 {
                return Err(Error::AddrNotEnough);
            }

            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                u16::from_be_bytes(data[4..6].try_into().unwrap()),
            )]
        }

        6 => {
            data.advance(1);

            // 128 is ipv6 bits
            if data.len() != mem::size_of::<u128>() + 2 {
                return Err(Error::AddrNotEnough);
            }

            vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    data[..16].try_into().unwrap(),
                ))),
                u16::from_be_bytes(data[16..18].try_into().unwrap()),
            )]
        }

        n => return Err(Error::AddrTypeInvalid(n)),
    };

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::str::FromStr;

    use bytes::{BufMut, BytesMut};

    use super::*;

    #[tokio::test]
    #[should_panic]
    async fn test_empty() {
        let data = [];

        parse_addr(&data).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_invalid_type() {
        let data = [1];

        parse_addr(&data).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_not_enough_v4() {
        let data = [4, 1, 2, 3];

        parse_addr(&data).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_not_enough_v6() {
        let data = [6, 1, 2, 3];

        parse_addr(&data).await.unwrap();
    }

    #[tokio::test]
    async fn test_v4() {
        let mut data = [4, 127, 0, 0, 1, 0, 0];
        data[5..].copy_from_slice(&80u16.to_be_bytes());

        assert_eq!(
            parse_addr(&data).await.unwrap(),
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from([127, 0, 0, 1]),
                80,
            ))]
        );
    }

    #[tokio::test]
    async fn test_v6() {
        let mut data = [0; 1 + mem::size_of::<u128>() + 2];
        data[0] = 6;
        data[1..17].copy_from_slice(&Ipv6Addr::from_str("::1").unwrap().octets());
        data[17..].copy_from_slice(&80u16.to_be_bytes());

        assert_eq!(
            parse_addr(&data).await.unwrap(),
            vec![SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_str("::1").unwrap(),
                80,
                0,
                0,
            ))]
        );
    }

    #[tokio::test]
    async fn test_domain() {
        let mut data = BytesMut::from(&[1][..]);
        data.put_u16("www.example.com".as_bytes().len() as _);
        data.put("www.example.com".as_bytes());
        data.put_u16(80);

        let addrs = parse_addr(&data).await.unwrap();
        assert!(!addrs.is_empty());

        dbg!(addrs);
    }
}
