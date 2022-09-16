use core::ffi::c_long;
use core::mem;

use aya_bpf::bindings::bpf_sock_addr;
use aya_bpf::helpers::*;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::programs::SockAddrContext;
use aya_log_ebpf::debug;

use crate::kernel_binding::require;
use crate::map::*;
use crate::Ipv6Addr;

/// check connect ipv6 in proxy ipv6 list or not, if in list, save the origin dst ipv6 addr into
/// DST_IPV6_ADDR_STORE with (cookie, origin_dst_ipv6_addr), otherwise let it connect directly
pub fn handle_cgroup_connect6(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != require::__socket_type::SOCK_STREAM
        || sock_addr.family != require::AF_INET6
    {
        return Ok(());
    }

    let user_ipv6 = get_ipv6_segments(sock_addr);
    let key = Key::new(128, user_ipv6);

    let is_blacklist_mode = match PROXY_IPV4_LIST_MODE.get(0) {
        None => {
            debug!(&ctx, "get proxy ipv6 list mode failed");

            return Err(0);
        }

        Some(mode) => *mode == BLACKLIST_MODE,
    };

    let in_list = PROXY_IPV6_LIST.get(&key).copied().unwrap_or(0) > 0;
    if !crate::should_proxy(is_blacklist_mode, in_list) {
        debug!(
            &ctx,
            "{}:{}:{}:{}:{}:{}:{}:{} is direct connect ip",
            u16::from_be(user_ipv6[0]),
            u16::from_be(user_ipv6[1]),
            u16::from_be(user_ipv6[2]),
            u16::from_be(user_ipv6[3]),
            u16::from_be(user_ipv6[4]),
            u16::from_be(user_ipv6[5]),
            u16::from_be(user_ipv6[6]),
            u16::from_be(user_ipv6[7])
        );

        return Ok(());
    }

    let proxy_client: &Ipv6Addr = match PROXY_IPV6_CLIENT.get(0) {
        None => {
            debug!(
                &ctx,
                "maybe proxy server is not set yet, let {}:{}:{}:{}:{}:{}:{}:{} connect directly",
                u16::from_be(user_ipv6[0]),
                u16::from_be(user_ipv6[1]),
                u16::from_be(user_ipv6[2]),
                u16::from_be(user_ipv6[3]),
                u16::from_be(user_ipv6[4]),
                u16::from_be(user_ipv6[5]),
                u16::from_be(user_ipv6[6]),
                u16::from_be(user_ipv6[7])
            );

            return Ok(());
        }

        Some(proxy_server) => proxy_server,
    };

    if user_ipv6 == proxy_client.addr {
        debug!(
            &ctx,
            "proxy client ip {}:{}:{}:{}:{}:{}:{}:{} need connect directly",
            u16::from_be(user_ipv6[0]),
            u16::from_be(user_ipv6[1]),
            u16::from_be(user_ipv6[2]),
            u16::from_be(user_ipv6[3]),
            u16::from_be(user_ipv6[4]),
            u16::from_be(user_ipv6[5]),
            u16::from_be(user_ipv6[6]),
            u16::from_be(user_ipv6[7])
        );

        return Ok(());
    }

    debug!(
        &ctx,
        "{}:{}:{}:{}:{}:{}:{}:{} need proxy",
        u16::from_be(user_ipv6[0]),
        u16::from_be(user_ipv6[1]),
        u16::from_be(user_ipv6[2]),
        u16::from_be(user_ipv6[3]),
        u16::from_be(user_ipv6[4]),
        u16::from_be(user_ipv6[5]),
        u16::from_be(user_ipv6[6]),
        u16::from_be(user_ipv6[7])
    );

    debug!(
        &ctx,
        "get proxy server done [{}:{}:{}:{}:{}:{}:{}:{}]:{}",
        u16::from_be(proxy_client.addr[0]),
        u16::from_be(proxy_client.addr[1]),
        u16::from_be(proxy_client.addr[2]),
        u16::from_be(proxy_client.addr[3]),
        u16::from_be(proxy_client.addr[4]),
        u16::from_be(proxy_client.addr[5]),
        u16::from_be(proxy_client.addr[6]),
        u16::from_be(proxy_client.addr[7]),
        proxy_client.port
    );

    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as _) };
    let origin_dst_ipv6_addr = Ipv6Addr {
        addr: user_ipv6,
        port: u16::from_be(sock_addr.user_port as _),
    };

    DST_IPV6_ADDR_STORE.insert(&cookie, &origin_dst_ipv6_addr, 0)?;

    debug!(&ctx, "set cookie and origin dst ipv6 addr done");

    set_ipv6_segments(sock_addr, proxy_client.addr);
    sock_addr.user_port = proxy_client.port.to_be() as _;

    debug!(&ctx, "set user_ip6 and user_port to proxy server done");

    Ok(())
}

#[inline]
fn get_ipv6_segments(sock_addr: &bpf_sock_addr) -> [u16; 8] {
    let addr = [
        sock_addr.user_ip6[0],
        sock_addr.user_ip6[1],
        sock_addr.user_ip6[2],
        sock_addr.user_ip6[3],
    ];

    // Safety: [u16; 8] equal [u32; 4]
    unsafe { mem::transmute(addr) }
}

#[inline]
fn set_ipv6_segments(sock_addr: &mut bpf_sock_addr, value: [u16; 8]) {
    let value: [u32; 4] = unsafe { mem::transmute(value) };

    sock_addr.user_ip6[0] = value[0];
    sock_addr.user_ip6[1] = value[1];
    sock_addr.user_ip6[2] = value[2];
    sock_addr.user_ip6[3] = value[3];
}