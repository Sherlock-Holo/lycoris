#![no_std]
#![no_main]

use core::ffi::{c_int, c_uint};

use aya_bpf::macros::{cgroup_sock_addr, sock_ops};
use aya_bpf::programs::{SockAddrContext, SockOpsContext};

#[cgroup_sock_addr(connect4)]
fn cgroup_connect4(ctx: SockAddrContext) -> c_int {
    let _ = lycoris_bpf::handle_cgroup_connect4(ctx);

    1
}

#[sock_ops(name = "established_connect")]
fn established_connect(ctx: SockOpsContext) -> c_uint {
    let _ = lycoris_bpf::handle_sockops(ctx);

    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
