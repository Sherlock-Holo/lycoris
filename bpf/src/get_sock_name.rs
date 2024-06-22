use core::ffi::c_long;
use core::ptr::addr_of_mut;
use core::{net, ptr, slice};

use aya_ebpf::helpers::bpf_sk_storage_get;
use aya_ebpf::programs::SockAddrContext;
use aya_log_ebpf::{debug, info};

use crate::kernel_binding::require::__socket_type::SOCK_STREAM;
use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::{PASSIVE_DST_IPV4_ADDR_STORAGE, PASSIVE_DST_IPV6_ADDR_STORAGE};
use crate::{Ipv4Addr, Ipv6Addr};

pub fn get_sock_name4(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != SOCK_STREAM && sock_addr.family != AF_INET {
        return Ok(());
    }

    unsafe {
        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV4_ADDR_STORAGE) as _,
            sock_addr.__bindgen_anon_1.sk as _,
            ptr::null_mut(),
            0,
        );
        if ptr.is_null() {
            return Ok(());
        }

        let ptr = ptr as *const Ipv4Addr;

        sock_addr.user_ip4 = u32::from_be_bytes((*ptr).addr).to_be();
        sock_addr.user_port = (*ptr).port.to_be() as _;

        debug!(
            &ctx,
            "hook ipv4 getsockname done, origin dst addr {:i}:{}",
            u32::from_be_bytes((*ptr).addr),
            (*ptr).port
        );
    }

    Ok(())
}

pub fn get_sock_name6(ctx: SockAddrContext) -> Result<(), c_long> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    if sock_addr.type_ != SOCK_STREAM && sock_addr.family != AF_INET6 {
        return Ok(());
    }

    unsafe {
        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV6_ADDR_STORAGE) as _,
            sock_addr.__bindgen_anon_1.sk as _,
            ptr::null_mut(),
            0,
        );
        if ptr.is_null() {
            return Ok(());
        }

        let ptr = ptr as *const Ipv6Addr;
        let addr = slice::from_raw_parts((*ptr).addr.as_ptr() as *const u32, 4);

        match net::Ipv6Addr::from((*ptr).addr).to_ipv4_mapped() {
            None => {
                sock_addr.user_ip6[0] = addr[0];
                sock_addr.user_ip6[1] = addr[1];
                sock_addr.user_ip6[2] = addr[2];
                sock_addr.user_ip6[3] = addr[3];
                sock_addr.user_port = (*ptr).port.to_be() as _;
            }

            Some(mut ipv4) => {
                ipv4 = net::Ipv4Addr::from(u32::from_be_bytes(ipv4.octets()));

                info!(
                    &ctx,
                    "ipv6 addr {:i} is ipv4 mapped addr {:i}",
                    (*ptr).addr,
                    u32::from_be_bytes(ipv4.octets()),
                );

                sock_addr.user_ip6[0] = addr[0];
                sock_addr.user_ip6[1] = addr[1];
                sock_addr.user_ip6[2] = addr[2];
                sock_addr.user_ip6[3] = ipv4.to_bits().to_be();
            }
        }

        debug!(
            &ctx,
            "hook ipv6 getsockname done, origin dst addr [{:i}]:{}",
            (*ptr).addr,
            (*ptr).port
        );
    }

    Ok(())
}
