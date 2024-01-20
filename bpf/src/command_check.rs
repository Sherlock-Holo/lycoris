use core::ffi::{c_long, CStr};
use core::str::from_utf8_unchecked;

use aya_bpf::programs::SockAddrContext;
use aya_log_ebpf::debug;

use crate::map::{COMM_MAP, COMM_MAP_MODE};
use crate::safe_helper;

pub fn command_can_connect_directly(ctx: &SockAddrContext) -> Result<bool, c_long> {
    let mut command = [0u8; 16];
    let null_index = safe_helper::bpf_get_current_comm(&mut command)?;

    // default 0 mode
    let mode = COMM_MAP_MODE.get(0).copied().unwrap_or(0);

    let can_connect_directly = unsafe {
        match COMM_MAP.get(&command) {
            None => mode == 1,
            Some(_) => mode == 0,
        }
    };

    let command = unsafe { CStr::from_bytes_with_nul_unchecked(&command[..null_index + 1]) };
    let command = command.to_bytes();
    let command = unsafe { from_utf8_unchecked(command) };

    if can_connect_directly {
        debug!(ctx, "command {} can connect directly", command);
    } else {
        debug!(
            ctx,
            "command {} can not connect directly, need next check step", command
        );
    }

    Ok(can_connect_directly)
}
