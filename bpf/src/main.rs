#![no_std]
#![no_main]

use core::ffi::{c_int, c_uint};

use aya_ebpf::macros::{cgroup_sock_addr, sock_ops};
use aya_ebpf::programs::{SockAddrContext, SockOpsContext};

#[cgroup_sock_addr(connect4)]
fn connect4(ctx: SockAddrContext) -> c_int {
    lycoris_bpf::handle_cgroup_connect4(ctx)
        .map(|_| 1)
        .unwrap_or_else(|err| err as _)
}

#[cgroup_sock_addr(connect6)]
fn connect6(ctx: SockAddrContext) -> c_int {
    lycoris_bpf::handle_cgroup_connect6(ctx)
        .map(|_| 1)
        .unwrap_or_else(|err| err as _)
}

#[sock_ops]
fn established_connect(ctx: SockOpsContext) -> c_uint {
    lycoris_bpf::handle_sockops(ctx)
        .map(|_| 1)
        .unwrap_or_else(|err| err as _)
}

#[cgroup_sock_addr(getsockname4)]
fn getsockname4(ctx: SockAddrContext) -> c_int {
    lycoris_bpf::handle_getsockname(ctx)
        .map(|_| 1)
        .unwrap_or_else(|err| err as _)
}

#[cgroup_sock_addr(getsockname6)]
fn getsockname6(ctx: SockAddrContext) -> c_int {
    lycoris_bpf::handle_getsockname(ctx)
        .map(|_| 1)
        .unwrap_or_else(|err| err as _)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
