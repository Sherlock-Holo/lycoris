#![no_std]
#![no_main]

use core::ffi::{c_int, c_uint};

use aya_ebpf::macros::{cgroup_sock_addr, classifier, sock_ops};
use aya_ebpf::programs::{SockAddrContext, SockOpsContext, TcContext};

#[cgroup_sock_addr(connect4)]
fn connect4(ctx: SockAddrContext) -> c_int {
    let _ = lycoris_bpf::handle_cgroup_connect4(ctx);

    1
}

#[cgroup_sock_addr(connect6)]
fn connect6(ctx: SockAddrContext) -> c_int {
    let _ = lycoris_bpf::handle_cgroup_connect6(ctx);

    1
}

#[sock_ops]
fn established_connect(ctx: SockOpsContext) -> c_uint {
    let _ = lycoris_bpf::handle_sockops(ctx);

    1
}

#[classifier]
fn assign_ingress(ctx: TcContext) -> c_int {
    lycoris_bpf::assign_ingress(ctx).unwrap_or_else(|ret| ret)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
