//! 64-bit atomic counters that degrade gracefully on targets without 64-bit
//! atomics (ESP32-S3 etc.): backed by `AtomicU32`, values wrap at 2^32 —
//! fine for transaction IDs / counters within a session lifetime.

#[cfg(target_has_atomic = "64")]
pub use core::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
#[derive(Debug, Default)]
pub struct AtomicU64(core::sync::atomic::AtomicU32);

#[cfg(not(target_has_atomic = "64"))]
impl AtomicU64 {
    pub const fn new(v: u64) -> Self {
        Self(core::sync::atomic::AtomicU32::new(v as u32))
    }
    pub fn load(&self, o: core::sync::atomic::Ordering) -> u64 {
        self.0.load(o) as u64
    }
    pub fn store(&self, v: u64, o: core::sync::atomic::Ordering) {
        self.0.store(v as u32, o)
    }
    pub fn fetch_add(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
        self.0.fetch_add(v as u32, o) as u64
    }
    pub fn fetch_sub(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
        self.0.fetch_sub(v as u32, o) as u64
    }
    pub fn swap(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
        self.0.swap(v as u32, o) as u64
    }
    pub fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: core::sync::atomic::Ordering,
        failure: core::sync::atomic::Ordering,
    ) -> Result<u64, u64> {
        self.0
            .compare_exchange(current as u32, new as u32, success, failure)
            .map(|v| v as u64)
            .map_err(|v| v as u64)
    }
}
