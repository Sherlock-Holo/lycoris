use core::ffi::c_long;

use aya_ebpf::helpers::gen;
use unroll::unroll_for_loops;

/// get current comm safe helper, will return nul index
pub fn bpf_get_current_comm(buf: &mut [u8; 16]) -> Result<usize, c_long> {
    unsafe {
        let res = gen::bpf_get_current_comm(buf.as_mut_ptr() as *mut _, buf.len() as _);
        if res < 0 {
            return Err(res);
        }
    }

    Ok(find_nul_index(buf))
}

#[unroll_for_loops]
fn find_nul_index(buf: &[u8; 16]) -> usize {
    for i in 0..16 {
        if buf[i] == 0 {
            return i;
        }
    }

    16 - 1
}
