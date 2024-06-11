use core::ffi::c_long;

use aya_ebpf::programs::SockAddrContext;
use aya_log_ebpf::debug;

use crate::map::{COMM_MAP, COMM_MAP_MODE};
use crate::safe_helper::CommandStr;

#[inline]
pub fn command_can_connect_directly(ctx: &SockAddrContext) -> Result<bool, c_long> {
    let command_str = CommandStr::get_command()?;

    // default 0 mode
    let mode = COMM_MAP_MODE.get(0).copied().unwrap_or(0);

    let can_connect_directly = unsafe {
        match COMM_MAP.get(command_str.as_array()) {
            None => mode == 1,
            Some(_) => mode == 0,
        }
    };

    if can_connect_directly {
        debug!(ctx, "command {} can connect directly", command_str);
    } else {
        debug!(
            ctx,
            "command {} can not connect directly, need next check step", command_str
        );
    }

    Ok(can_connect_directly)
}
