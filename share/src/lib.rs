#![cfg_attr(target_arch = "bpf", no_std)]

#[cfg(not(target_arch = "bpf"))]
pub mod dns;
#[cfg(not(target_arch = "bpf"))]
pub mod helper;
#[cfg(not(target_arch = "bpf"))]
pub mod log;
#[cfg(not(target_arch = "bpf"))]
pub mod proxy;
#[cfg(not(target_arch = "bpf"))]
pub mod tcp_wrapper;

pub mod route;
