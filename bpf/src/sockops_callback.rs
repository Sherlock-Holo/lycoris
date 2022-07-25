use core::ffi::c_long;

use aya_bpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_bpf::helpers::*;
use aya_bpf::programs::SockOpsContext;
use aya_log_ebpf::debug;
use share::{ConnectedIpv4Addr, Ipv4Addr};

use crate::kernel_binding::require::AF_INET;
use crate::map::*;

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
pub fn handle_sockops(ctx: SockOpsContext) -> Result<(), c_long> {
    if ctx.op() != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        return Ok(());
    }

    // ignore ipv6 for now
    if ctx.family() != AF_INET {
        return Ok(());
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as _) };

    let origin_dst_ipv4_addr: Ipv4Addr = unsafe {
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

    let connected_ipv4_addr = ConnectedIpv4Addr {
        sport,
        dport,
        saddr,
        daddr,
    };

    IPV4_ADDR_MAP.insert(&connected_ipv4_addr, &origin_dst_ipv4_addr, 0)?;

    Ok(())
}
