//! Safe wrapper over the XKCP ShakingUpAE DWrap primitive via the C shim.
//!
//! The DWrap instance is plain old data (a Keccak sponge state plus a few
//! integers, no pointers), so the opaque byte buffer can be cloned with a
//! simple copy — exactly what `SHAKE_Wrap_Clone` does. That is the whole trick
//! that makes the parallel version safe: every worker clones the keyed base
//! instance and mutates only its own copy.

use std::os::raw::{c_int, c_uint, c_void};

extern "C" {
    fn suw_dwrap_size() -> usize;
    fn suw_dwrap_init(
        d: *mut c_void,
        k: *const u8,
        klen: c_uint,
        taglen: c_uint,
        rho: c_uint,
        c: c_uint,
    );
    fn suw_dwrap_wrap(
        d: *mut c_void,
        c_out: *mut u8,
        a: *const u8,
        alen: usize,
        p: *const u8,
        plen: usize,
    );
    fn suw_dwrap_unwrap(
        d: *mut c_void,
        p: *mut u8,
        a: *const u8,
        alen: usize,
        c_in: *const u8,
        clen: usize,
    ) -> c_int;
}

/// A keyed DWrap instance. Cheap to clone (a byte-buffer copy == C clone).
#[derive(Clone)]
pub struct DWrap {
    buf: Vec<u8>,
}

// The buffer is just bytes; it owns no foreign resources.
unsafe impl Send for DWrap {}
unsafe impl Sync for DWrap {}

impl DWrap {
    pub fn new(key: &[u8], taglen: u32, rho: u32, capacity: u32) -> Self {
        let size = unsafe { suw_dwrap_size() };
        let mut buf = vec![0u8; size];
        unsafe {
            suw_dwrap_init(
                buf.as_mut_ptr() as *mut c_void,
                key.as_ptr(),
                key.len() as c_uint,
                taglen as c_uint,
                rho as c_uint,
                capacity as c_uint,
            );
        }
        DWrap { buf }
    }

    /// Encrypt `plaintext` into `out` (which must be `plaintext.len() + taglen`).
    pub fn wrap(&mut self, out: &mut [u8], aad: &[u8], plaintext: &[u8]) {
        unsafe {
            suw_dwrap_wrap(
                self.buf.as_mut_ptr() as *mut c_void,
                out.as_mut_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
            );
        }
    }

    /// Decrypt+verify `ciphertext` into `out`. Returns true iff the tag is valid.
    pub fn unwrap(&mut self, out: &mut [u8], aad: &[u8], ciphertext: &[u8]) -> bool {
        let r = unsafe {
            suw_dwrap_unwrap(
                self.buf.as_mut_ptr() as *mut c_void,
                out.as_mut_ptr(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        r == 0
    }
}
