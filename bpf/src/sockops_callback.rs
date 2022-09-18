use core::ffi::c_long;
use core::mem;

use aya_bpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_bpf::helpers::*;
use aya_bpf::programs::SockOpsContext;
use aya_log_ebpf::debug;

use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::*;
use crate::{get_ipv6_octets, ConnectedIpv4Addr, ConnectedIpv6Addr};

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
        "get origin dst addr {:ipv4} done",
        u32::from_be_bytes(origin_dst_ipv4_addr.addr),
        origin_dst_ipv4_addr.port
    );

    let saddr = u32::from_be(ctx.local_ip4()).to_be_bytes();
    let sport = ctx.local_port() as u16;
    let daddr = u32::from_be(ctx.remote_ip4()).to_be_bytes();
    let dport = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "saddr {:ipv4}:{} , daddr {:ipv4}:{}",
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
        "get origin dst addr [{:ipv6}]:{} done",
        get_ipv6_octets(origin_dst_ipv6_addr.addr),
        origin_dst_ipv6_addr.port
    );

    let saddr = copy_local_ip6(&ctx);
    let saddr_octets = get_ipv6_octets(saddr);
    let sport = ctx.local_port() as u16;
    let daddr = copy_remote_ip6(&ctx);
    let daddr_octets = get_ipv6_octets(daddr);
    let dport = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "saddr [{:ipv6}]:{} , daddr [{:ipv6}]:{}", saddr_octets, sport, daddr_octets, dport,
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
