use core::ffi::{c_long, CStr};
use core::num::NonZeroUsize;
use core::str::from_utf8_unchecked;

use aya_ebpf::helpers::gen;
use aya_log_ebpf::macro_support::DefaultFormatter;
use aya_log_ebpf::WriteToBuf;
use unroll::unroll_for_loops;

pub struct CommandStr {
    buf: [u8; 16],
    index: usize,
}

impl CommandStr {
    #[inline]
    pub fn get_command() -> Result<Self, c_long> {
        let mut this = Self {
            buf: [0; 16],
            index: 0,
        };

        let index = bpf_get_current_comm(&mut this.buf)?;
        this.index = index;

        Ok(this)
    }

    pub fn as_str(&self) -> &str {
        let command = unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..self.index + 1]) };

        unsafe { from_utf8_unchecked(command.to_bytes()) }
    }

    pub fn as_array(&self) -> &[u8; 16] {
        &self.buf
    }
}

impl WriteToBuf for CommandStr {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        self.as_str().write(buf)
    }
}

impl DefaultFormatter for CommandStr {}

/// get current comm safe helper, return nul index
fn bpf_get_current_comm(buf: &mut [u8; 16]) -> Result<usize, c_long> {
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
