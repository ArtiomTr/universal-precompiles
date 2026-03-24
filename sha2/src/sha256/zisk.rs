use core::convert::TryInto;

#[derive(Debug)]
#[repr(C)]
struct SyscallSha256Params<'a> {
    pub state: &'a mut [u64; 4],
    pub input: &'a [u64; 8],
}

extern "C" {
    fn syscall_sha256_f(params: &mut SyscallSha256Params);
}

#[inline]
pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // Move state into an aligned representation
    let mut state64 = [0u64; 4];
    unsafe {
        core::ptr::copy_nonoverlapping(
            state.as_ptr() as *const u8,
            state64.as_mut_ptr() as *mut u8,
            32,
        );
    }

    let mut aligned_block = [0u8; 64];

    for block in blocks {
        // Try zero-copy reinterpretation via align_to
        let input: &[u64; 8] = {
            let (prefix, middle, suffix) = unsafe { block.as_slice().align_to::<u64>() };

            if prefix.is_empty() && suffix.is_empty() && middle.len() == 8 {
                // Perfectly aligned
                middle.try_into().unwrap()
            } else {
                // Fallback: copy into aligned buffer
                aligned_block.copy_from_slice(block);
                let (_, middle, _) = unsafe { aligned_block.as_slice().align_to::<u64>() };
                middle.try_into().unwrap()
            }
        };

        let mut params = SyscallSha256Params {
            state: &mut state64,
            input,
        };

        unsafe {
            syscall_sha256_f(&mut params);
        }
    }

    // Copy state back
    unsafe {
        core::ptr::copy_nonoverlapping(
            state64.as_ptr() as *const u8,
            state.as_mut_ptr() as *mut u8,
            32,
        );
    }
}
