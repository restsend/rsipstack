//! Randomness seam (no_std only).
//!
//! The embassy backend otherwise derives Call-IDs / tags / branches from a
//! fixed-seed xorshift, so every boot repeats the same values; the embedder
//! installs a CSPRNG (hardware RNG) via [`set_fill_fn`].

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};

type FillFn = fn(&mut [u8]);

static FILL_FN: AtomicPtr<FillFn> = AtomicPtr::new(core::ptr::null_mut());

/// Installs the embedder's CSPRNG (thread-safe; call once at boot).
pub fn set_fill_fn(f: FillFn) {
    let leaked = Box::leak(Box::new(f));
    FILL_FN.store(leaked as *mut FillFn, Ordering::Release);
}

/// Fills `buf` from the installed CSPRNG; `false` when none is set.
pub fn try_fill(buf: &mut [u8]) -> bool {
    let ptr = FILL_FN.load(Ordering::Acquire);
    if ptr.is_null() {
        return false;
    }
    // SAFETY: `ptr` was set from a leaked `FillFn` and never cleared.
    unsafe { (*ptr)(buf) };
    true
}
