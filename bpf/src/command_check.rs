use core::ffi::{c_long, CStr};
use core::str::from_utf8_unchecked;

use aya_bpf::programs::SockAddrContext;
use aya_log_ebpf::debug;

use crate::safe_helper;

pub fn command_in_list(ctx: &SockAddrContext) -> Result<bool, c_long> {
    let mut command = [0u8; 64];
    let null_index = safe_helper::bpf_get_current_comm(&mut command)?;
    let command = unsafe { CStr::from_bytes_with_nul_unchecked(&command[..null_index + 1]) };
    let command = command.to_bytes();
    let command = unsafe { from_utf8_unchecked(command) };

    debug!(ctx, "command {}", command);

    Ok(true)
}
