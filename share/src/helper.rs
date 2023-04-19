use std::mem::transmute;
use std::net::Ipv6Addr;

pub trait Ipv6AddrExt {
    fn network_order_segments(&self) -> [u16; 8];
}

impl Ipv6AddrExt for Ipv6Addr {
    fn network_order_segments(&self) -> [u16; 8] {
        // SAFETY: `[u8; 16]` is always safe to transmute to `[u16; 8]`.
        unsafe { transmute::<_, [u16; 8]>(self.octets()) }
    }
}

pub trait ArrayExt {
    /// swap every element bytes
    fn swap_bytes(self) -> Self;
}

macro_rules! array_ext {
    ($t:ty) => {
        impl<const N: usize> ArrayExt for [$t; N] {
            fn swap_bytes(mut self) -> Self {
                for v in self.iter_mut() {
                    *v = v.swap_bytes();
                }

                self
            }
        }
    };
}

array_ext!(u8);
array_ext!(u16);
