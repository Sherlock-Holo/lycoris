use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::Error;

/// parse addr from data
/// the data format is \[addr_type:1,addr:variant,port:2\]
pub fn parse_addr(mut data: &[u8]) -> Result<SocketAddr, Error> {
    if data.is_empty() {
        return Err(Error::AddrNotEnough);
    }

    let addr = match data[0] {
        4 => {
            data = &data[1..];

            if data.len() != 4 + 2 {
                return Err(Error::AddrNotEnough);
            }

            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                u16::from_be_bytes(data[4..6].try_into().unwrap()),
            )
        }

        6 => {
            data = &data[1..];

            // 128 is ipv6 bits
            if data.len() != mem::size_of::<u128>() + 2 {
                return Err(Error::AddrNotEnough);
            }

            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    data[..16].try_into().unwrap(),
                ))),
                u16::from_be_bytes(data[16..18].try_into().unwrap()),
            )
        }

        n => return Err(Error::AddrTypeInvalid(n)),
    };

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::str::FromStr;

    use super::*;

    #[test]
    #[should_panic]
    fn test_empty() {
        let data = [];

        parse_addr(&data).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_type() {
        let data = [1];

        parse_addr(&data).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_not_enough_v4() {
        let data = [4, 1, 2, 3];

        parse_addr(&data).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_not_enough_v6() {
        let data = [6, 1, 2, 3];

        parse_addr(&data).unwrap();
    }

    #[test]
    fn test_v4() {
        let mut data = [4, 127, 0, 0, 1, 0, 0];
        data[5..].copy_from_slice(&80u16.to_be_bytes());

        assert_eq!(
            parse_addr(&data).unwrap(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from([127, 0, 0, 1]), 80))
        );
    }

    #[test]
    fn test_v6() {
        let mut data = [0; 1 + mem::size_of::<u128>() + 2];
        data[0] = 6;
        data[1..17].copy_from_slice(&Ipv6Addr::from_str("::1").unwrap().octets());
        data[17..].copy_from_slice(&80u16.to_be_bytes());

        assert_eq!(
            parse_addr(&data).unwrap(),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_str("::1").unwrap(),
                80,
                0,
                0,
            ))
        );
    }
}
