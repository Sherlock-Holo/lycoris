use core::ffi::c_long;

use aya_bpf::helpers::*;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::programs::SockAddrContext;
use aya_log_ebpf::debug;

use crate::kernel_binding::require;
use crate::map::*;
use crate::Ipv4Addr;

/// check connect ipv4 in proxy ipv4 list or not, if in list, save the origin dst ipv4 addr into
/// DST_IPV4_ADDR_STORE with (cookie, origin_dst_ipv4_addr), otherwise let it connect directly
pub fn handle_cgroup_connect4(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != require::__socket_type::SOCK_STREAM
        || sock_addr.family != require::AF_INET
    {
        return Ok(());
    }

    let user_ip4 = u32::from_be(sock_addr.user_ip4).to_be_bytes();
    let key = Key::new(32, user_ip4);

    let is_blacklist_mode = match PROXY_IPV4_LIST_MODE.get(0) {
        None => {
            debug!(&ctx, "get proxy ipv4 list mode failed");

            return Err(0);
        }

        Some(mode) => *mode == BLACKLIST_MODE,
    };

    let in_list = PROXY_IPV4_LIST.get(&key).copied().unwrap_or(0) > 0;
    if !in_list && is_blacklist_mode {
        debug!(
            &ctx,
            "{}.{}.{}.{} is direct connect ip", user_ip4[0], user_ip4[1], user_ip4[2], user_ip4[3]
        );

        return Ok(());
    }

    let proxy_server: &Ipv4Addr = match PROXY_IPv4_SERVER.get(0) {
        None => {
            debug!(
                &ctx,
                "maybe proxy server is not set yet, let {}.{}.{}.{} connect directly",
                user_ip4[0],
                user_ip4[1],
                user_ip4[2],
                user_ip4[3]
            );

            return Ok(());
        }

        Some(proxy_server) => proxy_server,
    };

    if user_ip4 == proxy_server.addr {
        debug!(&ctx, "proxy server ip need connect directly");

        return Ok(());
    }

    debug!(
        &ctx,
        "{}.{}.{}.{} need proxy", user_ip4[0], user_ip4[1], user_ip4[2], user_ip4[3]
    );

    debug!(
        &ctx,
        "get proxy server done {}.{}.{}.{}:{}",
        proxy_server.addr[0],
        proxy_server.addr[1],
        proxy_server.addr[2],
        proxy_server.addr[3],
        proxy_server.port
    );

    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as _) };
    let origin_dst_ipv4_addr = Ipv4Addr {
        addr: user_ip4,
        port: u16::from_be(sock_addr.user_port as _),
        _padding: [0; 2],
    };

    DST_IPV4_ADDR_STORE.insert(&cookie, &origin_dst_ipv4_addr, 0)?;

    debug!(&ctx, "set cookie and origin dst ipv4 addr done");

    sock_addr.user_ip4 = u32::from_be_bytes(proxy_server.addr).to_be();
    sock_addr.user_port = proxy_server.port.to_be() as _;

    debug!(&ctx, "set user_ip4 and user_port to proxy server done");

    Ok(())
}
