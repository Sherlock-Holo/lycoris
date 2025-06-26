use core::ffi::c_long;
use core::ptr::addr_of_mut;
use core::{mem, net, ptr};

use aya_ebpf::bindings::{BPF_LOCAL_STORAGE_GET_F_CREATE, bpf_sock_addr};
use aya_ebpf::helpers::*;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::SockAddrContext;
use aya_log_ebpf::{debug, error, info};

use crate::command_check::command_can_connect_directly;
use crate::kernel_binding::require;
use crate::map::*;
use crate::{Ipv6Addr, connect_directly, u16_ipv6_to_u8_ipv6};

/// check connect ipv6 in proxy ipv6 list or not, if in list, save the origin dst ipv6 addr into
/// DST_IPV6_ADDR_STORE with (cookie, origin_dst_ipv6_addr), otherwise let it connect directly
pub fn handle_cgroup_connect6(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != require::__socket_type::SOCK_STREAM
        || sock_addr.family != require::AF_INET6
    {
        return Ok(());
    }

    if command_can_connect_directly(&ctx)? {
        return Ok(());
    }

    let in_container = unsafe {
        let root_netns_cookie = bpf_get_netns_cookie(ptr::null_mut());
        let current_netns_cookie = bpf_get_netns_cookie(ctx.sock_addr as _);

        root_netns_cookie != current_netns_cookie
    };

    let user_ipv6 = get_ipv6_segments(sock_addr);
    let user_ipv6_octets = u16_ipv6_to_u8_ipv6(user_ipv6);
    match net::Ipv6Addr::from(user_ipv6_octets).to_ipv4_mapped() {
        Some(ipv4) => {
            let ipv4_octets = ipv4.octets();
            info!(
                &ctx,
                "ipv6 addr {:i} is ipv4 mapped addr {:i}",
                user_ipv6_octets,
                u32::from_be_bytes(ipv4_octets),
            );

            let key = Key::new(32, ipv4_octets);

            let in_list_connect_directly = match PROXY_LIST_MODE.get(0) {
                None => {
                    debug!(&ctx, "get proxy list mode failed");

                    return Err(0);
                }

                Some(mode) => *mode == CONNECT_DIRECTLY_MODE,
            };

            let in_list = PROXY_IPV4_LIST.get(&key).copied().unwrap_or(0) > 0;
            if connect_directly(in_list_connect_directly, in_list) {
                debug!(
                    &ctx,
                    "{:i} is direct connect ip",
                    u32::from_be_bytes(ipv4_octets)
                );

                return Ok(());
            }
        }

        None => {
            let key = Key::new(128, user_ipv6);

            let in_list_connect_directly = match PROXY_LIST_MODE.get(0) {
                None => {
                    debug!(&ctx, "get proxy list mode failed");

                    return Err(0);
                }

                Some(mode) => *mode == CONNECT_DIRECTLY_MODE,
            };

            let in_list = PROXY_IPV6_LIST.get(&key).copied().unwrap_or(0) > 0;
            if connect_directly(in_list_connect_directly, in_list) {
                debug!(&ctx, "{:i} is direct connect ip", user_ipv6_octets);

                return Ok(());
            }
        }
    }

    let index = if in_container { 1 } else { 0 };
    let proxy_client: &Ipv6Addr = match PROXY_IPV6_CLIENT.get(index) {
        None => {
            debug!(
                &ctx,
                "maybe proxy server is not set yet, let {:i} connect directly", user_ipv6_octets
            );

            return Ok(());
        }

        Some(proxy_server) => proxy_server,
    };

    if in_container && proxy_client.addr == [0; 16] {
        debug!(&ctx, "container bridge listen addr v6 not set, ignore it");

        return Ok(());
    }

    if user_ipv6_octets == proxy_client.addr {
        debug!(
            &ctx,
            "proxy client ip {:i} need connect directly", user_ipv6_octets
        );

        return Ok(());
    }

    debug!(&ctx, "{:i} need proxy", user_ipv6_octets);

    debug!(
        &ctx,
        "get proxy server done [{:i}]:{}", proxy_client.addr, proxy_client.port
    );

    let origin_dst_ipv6_addr = Ipv6Addr {
        addr: user_ipv6_octets,
        port: u16::from_be(sock_addr.user_port as _),
    };

    unsafe {
        let ptr = bpf_sk_storage_get(
            addr_of_mut!(CONNECT_DST_IPV6_ADDR_STORAGE) as _,
            (*ctx.sock_addr).__bindgen_anon_1.sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "get sk_storage ptr failed");

            return Err(0);
        }

        let ptr = ptr as *mut Ipv6Addr;
        ptr.write(origin_dst_ipv6_addr);

        debug!(&ctx, "write sk_storage ptr done");
    }

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
fn set_ipv6_segments(sock_addr: &mut bpf_sock_addr, value: [u8; 16]) {
    let value: [u32; 4] = unsafe { mem::transmute(value) };

    sock_addr.user_ip6[0] = value[0];
    sock_addr.user_ip6[1] = value[1];
    sock_addr.user_ip6[2] = value[2];
    sock_addr.user_ip6[3] = value[3];
}
