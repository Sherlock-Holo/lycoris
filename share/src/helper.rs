use std::io::{Error, ErrorKind};
use std::mem::transmute;
use std::net::Ipv6Addr;

use h2::Reason;

/// convert h2 error to io error
pub fn h2_err_to_io_err(err: h2::Error) -> Error {
    if err.is_io() {
        err.into_io().unwrap()
    } else {
        let reason = if let Some(reason) = err.reason() {
            reason
        } else {
            return Error::new(ErrorKind::Other, err);
        };

        match reason {
            Reason::NO_ERROR | Reason::CONNECT_ERROR => Error::from(ErrorKind::BrokenPipe),
            Reason::PROTOCOL_ERROR | Reason::COMPRESSION_ERROR | Reason::FRAME_SIZE_ERROR => {
                Error::from(ErrorKind::InvalidData)
            }

            reason => Error::new(ErrorKind::Other, reason.description()),
        }
    }
}

pub trait Ipv6AddrExt {
    fn network_order_segments(&self) -> [u16; 8];
}

impl Ipv6AddrExt for Ipv6Addr {
    fn network_order_segments(&self) -> [u16; 8] {
        // SAFETY: `[u8; 16]` is always safe to transmute to `[u16; 8]`.
        unsafe { transmute::<_, [u16; 8]>(self.octets()) }
    }
}
