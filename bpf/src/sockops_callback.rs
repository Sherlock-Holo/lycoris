use core::ffi::{c_int, c_long};
use core::ptr::addr_of_mut;
use core::{mem, ptr, slice};

use aya_ebpf::bindings::{
    BPF_LOCAL_STORAGE_GET_F_CREATE, BPF_SOCK_OPS_HDR_OPT_LEN_CB,
    BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_TCP_CONNECT_CB, BPF_SOCK_OPS_WRITE_HDR_OPT_CB, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG,
};
use aya_ebpf::helpers::{
    bpf_load_hdr_opt, bpf_reserve_hdr_opt, bpf_sk_storage_get, bpf_store_hdr_opt,
};
use aya_ebpf::programs::SockOpsContext;
use aya_log_ebpf::{debug, error};

use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::*;
use crate::{Ipv4Addr, Ipv6Addr};

const TCP_OPTION_KIND: u8 = 166;
const IPV4_OPTION_LENGTH: u8 = (2 + size_of::<[u8; 4]>() + size_of::<u16>()) as _;
const IPV6_OPTION_LENGTH: u8 = (2 + size_of::<u128>() + size_of::<u16>()) as _;

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
pub fn handle_sockops(ctx: SockOpsContext) -> Result<(), c_long> {
    match ctx.op() {
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            if ctx.family() == AF_INET {
                handle_passive_established_ipv4(ctx)?;
            } else if ctx.family() == AF_INET6 {
                handle_passive_established_ipv6(ctx)?;
            }
        }

        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            if !dst_is_proxy_client(&ctx) {
                return Ok(());
            }

            let flags = (ctx.cb_flags() as c_int)
                | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG as c_int
                | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG as c_int;

            let _ = ctx.set_cb_flags(flags);
        }

        BPF_SOCK_OPS_HDR_OPT_LEN_CB => {
            if !dst_is_proxy_client(&ctx) {
                return Ok(());
            }

            if ctx.family() == AF_INET {
                unsafe {
                    let res = bpf_reserve_hdr_opt(ctx.ops, IPV4_OPTION_LENGTH as _, 0);
                    if res != 0 {
                        error!(&ctx, "bpf reserve ipv4 hdr opt failed: {}", res);
                    }

                    debug!(&ctx, "bpf reserve ipv4 hdr opt ok");
                }
            } else if ctx.family() == AF_INET6 {
                unsafe {
                    let res = bpf_reserve_hdr_opt(ctx.ops, IPV6_OPTION_LENGTH as _, 0);
                    if res != 0 {
                        error!(&ctx, "bpf reserve ipv6 hdr opt failed: {}", res);
                    }

                    debug!(&ctx, "bpf reserve ipv6 hdr opt ok");
                }
            }
        }

        BPF_SOCK_OPS_WRITE_HDR_OPT_CB => {
            if !dst_is_proxy_client(&ctx) {
                return Ok(());
            }

            if ctx.family() == AF_INET {
                handle_ipv4_write_hdr_opt(ctx)?;
            } else if ctx.family() == AF_INET6 {
                handle_ipv6_write_hdr_opt(ctx)?;
            }
        }

        _ => {}
    }

    Ok(())
}

fn handle_ipv4_write_hdr_opt(ctx: SockOpsContext) -> Result<(), c_long> {
    let addr_ptr = unsafe {
        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Err(0);
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(CONNECT_DST_IPV4_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            0,
        );
        if ptr.is_null() {
            error!(&ctx, "sk_storage ptr is null");

            return Err(0);
        }

        ptr as *mut Ipv4Addr
    };

    let mut buf = [0; IPV4_OPTION_LENGTH as _];
    buf[0] = TCP_OPTION_KIND;
    buf[1] = IPV4_OPTION_LENGTH;

    let res = unsafe {
        buf[2..6].copy_from_slice((*addr_ptr).addr.as_slice());
        buf[6..8].copy_from_slice((*addr_ptr).port.to_be_bytes().as_slice());

        bpf_store_hdr_opt(ctx.ops, buf.as_ptr() as _, buf.len() as _, 0)
    };

    if res != 0 {
        error!(&ctx, "bpf store ipv4 hdr opt failed: {}", res);
    }

    debug!(&ctx, "bpf store ipv4 hdr opt ok");

    Ok(())
}

fn handle_ipv6_write_hdr_opt(ctx: SockOpsContext) -> Result<(), c_long> {
    let addr_ptr = unsafe {
        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Err(0);
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(CONNECT_DST_IPV6_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            0,
        );
        if ptr.is_null() {
            error!(&ctx, "sk_storage ptr is null");

            return Err(0);
        }

        ptr as *mut Ipv6Addr
    };

    let mut buf = [0; IPV6_OPTION_LENGTH as _];
    buf[0] = TCP_OPTION_KIND;
    buf[1] = IPV6_OPTION_LENGTH;

    let res = unsafe {
        buf[2..18].copy_from_slice(slice::from_raw_parts(
            (*addr_ptr).addr.as_ptr() as *const u8,
            16,
        ));
        buf[18..20].copy_from_slice((*addr_ptr).port.to_be_bytes().as_slice());

        bpf_store_hdr_opt(ctx.ops, buf.as_ptr() as _, buf.len() as _, 0)
    };

    if res != 0 {
        error!(&ctx, "bpf store ipv6 hdr opt failed: {}", res);
    }

    debug!(&ctx, "bpf store ipv6 hdr opt ok");

    Ok(())
}

fn handle_passive_established_ipv4(ctx: SockOpsContext) -> Result<(), c_long> {
    let local_addr = u32::from_be(ctx.local_ip4());
    let local_port = ctx.local_port() as u16;

    let ignore = match PROXY_IPV4_CLIENT.get(0) {
        None => true,
        Some(client_addr) => *client_addr != (local_addr, local_port),
    };
    if ignore {
        return Ok(());
    }

    let mut buf = [0; IPV4_OPTION_LENGTH as _];
    buf[0] = TCP_OPTION_KIND;

    unsafe {
        let res = bpf_load_hdr_opt(ctx.ops, buf.as_mut_ptr() as _, buf.len() as _, 0);
        if res < 0 {
            error!(&ctx, "bpf load ipv4 hdr opt failed, res {}", res);

            return Err(0);
        }

        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Ok(());
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV4_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "bpf sk storage set failed");

            return Ok(());
        }

        debug!(&ctx, "bpf sk storage set done");

        let ptr = ptr as *mut Ipv4Addr;
        ptr.write(Ipv4Addr {
            addr: (&buf[2..6]).try_into().unwrap(),
            port: u16::from_be_bytes((&buf[6..8]).try_into().unwrap()),
            _padding: [0; 2],
        });

        debug!(&ctx, "bpf sk storage write origin dst ipv4 done");
    }

    Ok(())
}

fn handle_passive_established_ipv6(ctx: SockOpsContext) -> Result<(), c_long> {
    let local_addr = unsafe {
        mem::transmute::<[u32; 4], [u16; 8]>([
            ctx.local_ip6()[0],
            ctx.local_ip6()[1],
            ctx.local_ip6()[2],
            ctx.local_ip6()[3],
        ])
    };
    let local_port = ctx.local_port() as u16;

    let ignore = match PROXY_IPV6_CLIENT.get(0) {
        None => true,
        Some(client_addr) => {
            *client_addr
                != Ipv6Addr {
                    addr: local_addr,
                    port: local_port,
                }
        }
    };
    if ignore {
        return Ok(());
    }

    let mut buf = [0; IPV6_OPTION_LENGTH as _];
    buf[0] = TCP_OPTION_KIND;

    unsafe {
        let res = bpf_load_hdr_opt(ctx.ops, buf.as_mut_ptr() as _, buf.len() as _, 0);
        if res < 0 {
            error!(&ctx, "bpf load ipv6 hdr opt failed, res {}", res);

            return Err(0);
        }

        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Ok(());
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV6_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "bpf sk storage set failed");

            return Ok(());
        }

        debug!(&ctx, "bpf sk storage set done");

        let ptr = ptr as *mut Ipv6Addr;
        let addr: [u8; 16] = (&buf[2..18]).try_into().unwrap();
        let addr = mem::transmute::<[u8; 16], [u16; 8]>(addr);

        // must set port at first, otherwise will fail on ebpf verifier with
        // R5 bitwise operator &= on pointer prohibited
        (*ptr).port = u16::from_be_bytes((&buf[18..20]).try_into().unwrap());
        (*ptr).addr.copy_from_slice(&addr);

        debug!(&ctx, "bpf sk storage write origin dst ipv6 done");
    }

    Ok(())
}

fn dst_is_proxy_client(ctx: &SockOpsContext) -> bool {
    if ctx.family() == AF_INET {
        let daddr = u32::from_be(ctx.remote_ip4());
        let dport = u32::from_be(ctx.remote_port());
        let dport = dport as u16;

        match PROXY_IPV4_CLIENT.get(0) {
            None => false,
            Some(client_addr) => *client_addr == (daddr, dport),
        }
    } else if ctx.family() == AF_INET6 {
        let daddr = unsafe {
            mem::transmute::<[u32; 4], [u8; 16]>([
                ctx.remote_ip6()[0],
                ctx.remote_ip6()[1],
                ctx.remote_ip6()[2],
                ctx.remote_ip6()[3],
            ])
        };
        let dport = u32::from_be(ctx.remote_port());
        let dport = dport as u16;

        match PROXY_IPV6_CLIENT.get(0) {
            None => false,
            Some(client_addr) => {
                *client_addr
                    == (Ipv6Addr {
                        addr: unsafe { mem::transmute::<[u8; 16], [u16; 8]>(daddr) },
                        port: dport,
                    })
            }
        }
    } else {
        false
    }
}
