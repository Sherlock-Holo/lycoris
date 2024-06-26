use core::ffi::c_long;
use core::ptr;
use core::ptr::addr_of_mut;

use aya_ebpf::bindings::BPF_LOCAL_STORAGE_GET_F_CREATE;
use aya_ebpf::helpers::*;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::SockAddrContext;
use aya_log_ebpf::{debug, error};

use crate::command_check::command_can_connect_directly;
use crate::kernel_binding::require;
use crate::map::*;
use crate::{connect_directly, Ipv4Addr};

/// check connect ipv4 in proxy ipv4 list or not, if in list, save the origin dst ipv4 addr into
/// DST_IPV4_ADDR_STORE with (cookie, origin_dst_ipv4_addr), otherwise let it connect directly
pub fn handle_cgroup_connect4(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != require::__socket_type::SOCK_STREAM
        || sock_addr.family != require::AF_INET
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

    let user_ip4_u32 = u32::from_be(sock_addr.user_ip4);
    let user_ip4 = user_ip4_u32.to_be_bytes();
    let key = Key::new(32, user_ip4);

    let in_list_connect_directly = match PROXY_LIST_MODE.get(0) {
        None => {
            debug!(&ctx, "get proxy list mode failed");

            return Err(0);
        }

        Some(mode) => *mode == CONNECT_DIRECTLY_MODE,
    };

    let in_list = PROXY_IPV4_LIST.get(&key).copied().unwrap_or(0) > 0;
    if connect_directly(in_list_connect_directly, in_list) {
        debug!(&ctx, "{:i} is direct connect ip", user_ip4_u32);

        return Ok(());
    }

    let index = if in_container { 1 } else { 0 };
    let proxy_client: &Ipv4Addr = match PROXY_IPV4_CLIENT.get(index) {
        None => {
            debug!(
                &ctx,
                "maybe proxy server is not set yet, let {:i} connect directly", user_ip4_u32
            );

            return Ok(());
        }

        Some(proxy_server) => proxy_server,
    };

    if in_container && proxy_client.addr == [0; 4] {
        debug!(&ctx, "container bridge listen addr not set, ignore it");

        return Ok(());
    }

    if user_ip4 == proxy_client.addr {
        debug!(
            &ctx,
            "proxy client ip {:i} need connect directly", user_ip4_u32
        );

        return Ok(());
    }

    debug!(&ctx, "{:i} need proxy", user_ip4_u32);

    debug!(
        &ctx,
        "get proxy server done {:i}",
        u32::from_be_bytes(proxy_client.addr)
    );

    let origin_dst_ipv4_addr = Ipv4Addr {
        addr: user_ip4,
        port: u16::from_be(sock_addr.user_port as _),
        _padding: [0; 2],
    };

    unsafe {
        let ptr = bpf_sk_storage_get(
            addr_of_mut!(CONNECT_DST_IPV4_ADDR_STORAGE) as _,
            (*ctx.sock_addr).__bindgen_anon_1.sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "get sk_storage ptr failed");

            return Err(0);
        }

        let ptr = ptr as *mut Ipv4Addr;
        ptr.write(origin_dst_ipv4_addr);

        debug!(&ctx, "write sk_storage ptr done");
    }

    debug!(&ctx, "set cookie and origin dst ipv4 addr done");

    sock_addr.user_ip4 = u32::from_be_bytes(proxy_client.addr).to_be();
    sock_addr.user_port = proxy_client.port.to_be() as _;

    debug!(&ctx, "set user_ip4 and user_port to proxy server done");

    Ok(())
}
