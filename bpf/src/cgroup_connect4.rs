use core::ffi::c_long;

use aya_bpf::helpers::*;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::programs::SockAddrContext;
use aya_log_ebpf::debug;
use bridge::Ipv4Addr;

use crate::kernel_binding::require;
use crate::map::*;

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

    let should_proxy = PROXY_IPV4_LIST.get(&key).copied().unwrap_or(0) > 0;
    if !should_proxy {
        debug!(
            &ctx,
            "{}.{}.{}.{} is direct connect ip", user_ip4[0], user_ip4[1], user_ip4[2], user_ip4[3]
        );

        return Ok(());
    }

    debug!(
        &ctx,
        "{}.{}.{}.{} need proxy", user_ip4[0], user_ip4[1], user_ip4[2], user_ip4[3]
    );

    let proxy_server: &Ipv4Addr = match PROXY_SERVER.get(0) {
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
