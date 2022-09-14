use core::ffi::c_long;
use core::mem;

use aya_bpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_bpf::helpers::*;
use aya_bpf::programs::SockOpsContext;
use aya_log_ebpf::debug;

use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::*;
use crate::{ConnectedIpv4Addr, ConnectedIpv6Addr};

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
        "get origin dst addr {}.{}.{}.{}:{} done",
        origin_dst_ipv4_addr.addr[0],
        origin_dst_ipv4_addr.addr[1],
        origin_dst_ipv4_addr.addr[2],
        origin_dst_ipv4_addr.addr[3],
        origin_dst_ipv4_addr.port
    );

    let saddr = u32::from_be(ctx.local_ip4()).to_be_bytes();
    let sport = ctx.local_port() as u16;
    let daddr = u32::from_be(ctx.remote_ip4()).to_be_bytes();
    let dport = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "saddr {}.{}.{}.{}:{} , daddr {}.{}.{}.{}:{}",
        saddr[0],
        saddr[1],
        saddr[2],
        saddr[3],
        sport,
        daddr[0],
        daddr[1],
        daddr[2],
        daddr[3],
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
        "get origin dst addr [{}:{}:{}:{}:{}:{}:{}:{}]:{} done",
        u16::from_be(origin_dst_ipv6_addr.addr[0]),
        u16::from_be(origin_dst_ipv6_addr.addr[1]),
        u16::from_be(origin_dst_ipv6_addr.addr[2]),
        u16::from_be(origin_dst_ipv6_addr.addr[3]),
        u16::from_be(origin_dst_ipv6_addr.addr[4]),
        u16::from_be(origin_dst_ipv6_addr.addr[5]),
        u16::from_be(origin_dst_ipv6_addr.addr[6]),
        u16::from_be(origin_dst_ipv6_addr.addr[7]),
        origin_dst_ipv6_addr.port
    );

    let saddr = copy_local_ip6(&ctx);
    let sport = ctx.local_port() as u16;
    let daddr = copy_remote_ip6(&ctx);
    let dport = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "saddr {}:{}:{}:{}:{}:{}:{}:{} , daddr {}:{}:{}:{}:{}:{}:{}:{}",
        u16::from_be(saddr[0]),
        u16::from_be(saddr[1]),
        u16::from_be(saddr[2]),
        u16::from_be(saddr[3]),
        u16::from_be(saddr[4]),
        u16::from_be(saddr[5]),
        u16::from_be(saddr[6]),
        u16::from_be(saddr[7]),
        sport,
        u16::from_be(daddr[0]),
        u16::from_be(daddr[1]),
        u16::from_be(daddr[2]),
        u16::from_be(daddr[3]),
        u16::from_be(daddr[4]),
        u16::from_be(daddr[5]),
        u16::from_be(daddr[6]),
        u16::from_be(daddr[7]),
        dport,
    );

    let connected_ipv6_addr = ConnectedIpv6Addr {
        sport,
        dport,
        saddr,
        daddr,
    };

    IPV6_ADDR_MAP.insert(&connected_ipv6_addr, &origin_dst_ipv6_addr, 0)?;

    Ok(())
}

fn copy_local_ip6(ctx: &SockOpsContext) -> [u16; 8] {
    let ops = unsafe { &*ctx.ops };

    let ip6 = [
        ops.local_ip6[0],
        ops.local_ip6[1],
        ops.local_ip6[2],
        ops.local_ip6[3],
    ];

    unsafe { mem::transmute(ip6) }
}

fn copy_remote_ip6(ctx: &SockOpsContext) -> [u16; 8] {
    let ops = unsafe { &*ctx.ops };

    let ip6 = [
        ops.remote_ip6[0],
        ops.remote_ip6[1],
        ops.remote_ip6[2],
        ops.remote_ip6[3],
    ];

    unsafe { mem::transmute(ip6) }
}
