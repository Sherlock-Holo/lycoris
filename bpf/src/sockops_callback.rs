use core::ffi::c_long;
use core::ptr::addr_of_mut;
use core::{mem, ptr};

use aya_ebpf::bindings::{
    BPF_LOCAL_STORAGE_GET_F_CREATE, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_TCP_CONNECT_CB,
};
use aya_ebpf::helpers::*;
use aya_ebpf::programs::SockOpsContext;
use aya_log_ebpf::{debug, error};

use crate::kernel_binding::require::{AF_INET, AF_INET6};
use crate::map::*;
use crate::{ConnectedIpv4Addr, ConnectedIpv6Addr, Ipv4Addr, Ipv6Addr};

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
pub fn handle_sockops(ctx: SockOpsContext) -> Result<(), c_long> {
    match ctx.op() {
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            if ctx.family() == AF_INET {
                handle_ipv4_connect(ctx)
            } else if ctx.family() == AF_INET6 {
                handle_ipv6_connect(ctx)
            } else {
                Ok(())
            }
        }

        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            if ctx.family() == AF_INET {
                handle_ipv4_accept(ctx)
            } else if ctx.family() == AF_INET6 {
                handle_ipv6_accept(ctx)
            } else {
                Ok(())
            }
        }

        _ => Ok(()),
    }
}

fn handle_ipv4_connect(ctx: SockOpsContext) -> Result<(), c_long> {
    let dst_addr_ptr = unsafe {
        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Err(0);
        }

        let ptr = bpf_sk_storage_get(
            CONNECT_DST_IPV4_ADDR_STORAGE.get().cast(),
            bpf_sk as _,
            ptr::null_mut(),
            0,
        );

        if ptr.is_null() {
            return Ok(());
        }

        ptr as *mut Ipv4Addr
    };

    let saddr = u32::from_be(ctx.local_ip4()).to_be_bytes();
    let sport = ctx.local_port() as u16;
    let daddr = u32::from_be(ctx.remote_ip4()).to_be_bytes();
    let dport = u32::from_be(ctx.remote_port()) as u16;

    let connected_addr = ConnectedIpv4Addr {
        sport,
        dport,
        saddr,
        daddr,
    };

    let dst_addr = unsafe { &*dst_addr_ptr };

    DST_IPV4_ADDR_STORE.insert(&connected_addr, dst_addr, 0)
}

fn handle_ipv6_connect(ctx: SockOpsContext) -> Result<(), c_long> {
    let dst_addr_ptr = unsafe {
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
            return Ok(());
        }

        ptr as *mut Ipv6Addr
    };

    let saddr = unsafe {
        mem::transmute::<[u32; 4], [u8; 16]>([
            ctx.local_ip6()[0],
            ctx.local_ip6()[1],
            ctx.local_ip6()[2],
            ctx.local_ip6()[3],
        ])
    };
    let sport = ctx.local_port() as u16;
    let daddr = unsafe {
        mem::transmute::<[u32; 4], [u8; 16]>([
            ctx.remote_ip6()[0],
            ctx.remote_ip6()[1],
            ctx.remote_ip6()[2],
            ctx.remote_ip6()[3],
        ])
    };
    let dport = u32::from_be(ctx.remote_port()) as u16;

    let connected_addr = ConnectedIpv6Addr {
        sport,
        dport,
        saddr,
        daddr,
    };

    let dst_addr = unsafe { &*dst_addr_ptr };

    DST_IPV6_ADDR_STORE.insert(&connected_addr, dst_addr, 0)
}

/// when the socket is active established, get origin_dst_ipv4_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv4 addr, insert ((saddr, daddr), origin_dst_ipv4_addr) into the map
/// so userspace can get the origin dst ipv4 addr
fn handle_ipv4_accept(ctx: SockOpsContext) -> Result<(), c_long> {
    let local_addr = u32::from_be(ctx.local_ip4()).to_be_bytes();
    let local_port = ctx.local_port() as u16;
    let remote_addr = u32::from_be(ctx.remote_ip4()).to_be_bytes();
    let remote_port = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "local_addr {:i}:{} , remote_addr {:i}:{}",
        u32::from_be_bytes(local_addr),
        local_port,
        u32::from_be_bytes(remote_addr),
        remote_port,
    );

    let connected_addr = ConnectedIpv4Addr {
        sport: remote_port,
        dport: local_port,
        saddr: remote_addr,
        daddr: local_addr,
    };

    unsafe {
        let dst_addr = match DST_IPV4_ADDR_STORE.get(&connected_addr) {
            None => return Ok(()),
            Some(dst_addr) => *dst_addr,
        };

        let _ = DST_IPV4_ADDR_STORE.remove(&connected_addr);

        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Err(0);
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV4_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "get dst ipv4 addr storage ptr failed");

            return Err(0);
        }

        *(ptr as *mut Ipv4Addr) = dst_addr;
    }

    Ok(())
}

/// when the socket is active established, get origin_dst_ipv6_addr by its cookie, if not exists,
/// ignore it because this socket doesn't a need proxy socket
///
/// when get the origin dst ipv6 addr, insert ((saddr, daddr), origin_dst_ipv6_addr) into the map
/// so userspace can get the origin dst ipv6 addr
fn handle_ipv6_accept(ctx: SockOpsContext) -> Result<(), c_long> {
    let local_addr = unsafe {
        mem::transmute::<[u32; 4], [u8; 16]>([
            ctx.local_ip6()[0],
            ctx.local_ip6()[1],
            ctx.local_ip6()[2],
            ctx.local_ip6()[3],
        ])
    };
    let local_port = ctx.local_port() as u16;
    let remote_addr = unsafe {
        mem::transmute::<[u32; 4], [u8; 16]>([
            ctx.remote_ip6()[0],
            ctx.remote_ip6()[1],
            ctx.remote_ip6()[2],
            ctx.remote_ip6()[3],
        ])
    };
    let remote_port = u32::from_be(ctx.remote_port()) as u16;

    debug!(
        &ctx,
        "local_addr [{:i}]:{} , remote_addr [{:i}]:{}",
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    );

    let connected_addr = ConnectedIpv6Addr {
        sport: remote_port,
        dport: local_port,
        saddr: remote_addr,
        daddr: local_addr,
    };

    unsafe {
        let dst_addr = match DST_IPV6_ADDR_STORE.get(&connected_addr) {
            None => return Ok(()),
            Some(dst_addr) => *dst_addr,
        };

        let _ = DST_IPV6_ADDR_STORE.remove(&connected_addr);

        let bpf_sk = (*ctx.ops).__bindgen_anon_2.sk;
        if bpf_sk.is_null() {
            error!(&ctx, "bpf_sk is null");

            return Err(0);
        }

        let ptr = bpf_sk_storage_get(
            addr_of_mut!(PASSIVE_DST_IPV6_ADDR_STORAGE) as _,
            bpf_sk as _,
            ptr::null_mut(),
            BPF_LOCAL_STORAGE_GET_F_CREATE as _,
        );
        if ptr.is_null() {
            error!(&ctx, "get dst ipv6 addr storage ptr failed");

            return Err(0);
        }

        *(ptr as *mut Ipv6Addr) = dst_addr;
    }

    Ok(())
}
