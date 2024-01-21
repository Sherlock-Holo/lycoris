use core::ffi::c_long;
use core::mem;
use core::num::NonZeroUsize;

use aya_bpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_bpf::helpers::*;
use aya_bpf::programs::SockOpsContext;
use aya_log_ebpf::macro_support::IpFormatter;
use aya_log_ebpf::{debug, WriteToBuf};

use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::*;
use crate::{u16_ipv6_to_u8_ipv6, ConnectedIpv4Addr, ConnectedIpv6Addr};

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
pub fn handle_sockops(ctx: SockOpsContext) -> Result<(), c_long> {
    if ctx.op() != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        return Ok(());
    }

    if ctx.family() == AF_INET {
        handle_ipv4(ctx)
    } else if ctx.family() == AF_INET6 {
        handle_ipv6(ctx)
    } else {
        Ok(())
    }
}

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
fn handle_ipv4(ctx: SockOpsContext) -> Result<(), c_long> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as _) };

    let origin_dst_ipv4_addr = unsafe {
        match DST_IPV4_ADDR_STORE.get(&cookie) {
            None => return Ok(()),
            Some(origin_dst_ipv4_addr) => *origin_dst_ipv4_addr,
        }
    };

    DST_IPV4_ADDR_STORE.remove(&cookie)?;

    debug!(
        &ctx,
        "get origin dst addr {:i} done",
        u32::from_be_bytes(origin_dst_ipv4_addr.addr),
        origin_dst_ipv4_addr.port
    );

    let saddr = u32::from_be(ctx.local_ip4()).to_be_bytes();
    let sport = ctx.local_port() as u16;
    let daddr = u32::from_be(ctx.remote_ip4()).to_be_bytes();
    let dport = u32::from_be(ctx.remote_port());
    let dport = dport as u16;

    debug!(
        &ctx,
        "saddr {:i}:{} , daddr {:i}:{}",
        u32::from_be_bytes(saddr),
        sport,
        u32::from_be_bytes(daddr),
        dport,
    );

    let connected_ipv4_addr = ConnectedIpv4Addr {
        sport,
        dport,
        saddr,
        daddr,
    };

    IPV4_ADDR_MAP.insert(&connected_ipv4_addr, &origin_dst_ipv4_addr, 0)?;

    Ok(())
}

/// when the socket is active established, get origin_dst_ipv6_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv6 addr, insert ((saddr, daddr), origin_dst_ipv6_addr) into the map
/// so userspace can get the origin dst ipv6 addr
fn handle_ipv6(ctx: SockOpsContext) -> Result<(), c_long> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as _) };

    let origin_dst_ipv6_addr = unsafe {
        match DST_IPV6_ADDR_STORE.get(&cookie) {
            None => return Ok(()),
            Some(origin_dst_ipv6_addr) => *origin_dst_ipv6_addr,
        }
    };

    DST_IPV6_ADDR_STORE.remove(&cookie)?;

    debug!(
        &ctx,
        "get origin dst addr [{:i}]:{} done",
        u16_ipv6_to_u8_ipv6(origin_dst_ipv6_addr.addr),
        origin_dst_ipv6_addr.port
    );

    let saddr = U32Array4(ctx.local_ip6());
    let sport = ctx.local_port() as u16;
    let daddr = U32Array4(ctx.remote_ip6());
    let dport = u32::from_be(ctx.remote_port());
    let dport = dport as u16;

    debug!(
        &ctx,
        "saddr [{:i}]:{} , daddr [{:i}]:{}", saddr, sport, daddr, dport,
    );

    let connected_ipv6_addr = ConnectedIpv6Addr {
        sport,
        dport,
        saddr: unsafe { mem::transmute(saddr) },
        daddr: unsafe { mem::transmute(daddr) },
    };

    IPV6_ADDR_MAP.insert(&connected_ipv6_addr, &origin_dst_ipv6_addr, 0)?;

    Ok(())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
struct U32Array4([u32; 4]);

impl From<[u32; 4]> for U32Array4 {
    #[inline]
    fn from(value: [u32; 4]) -> Self {
        Self(value)
    }
}

impl WriteToBuf for U32Array4 {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let v = unsafe { *(self.0.as_ptr() as *const u128) };
        v.to_be_bytes().write(buf)
    }
}

impl IpFormatter for U32Array4 {}
