//! Internal data-structure primitives, implemented per backend:
//!
//! - std (platform-tokio): parking_lot (non-poisoning, matches the
//!   semantics of the existing code).
//! - no_std (platform-embassy): spin locks (the target cores have atomic
//!   CAS; ESP32-S3 included). Short critical sections only — **never
//!   await while holding a lock** (all in-tree call sites are short).

#![allow(clippy::module_inception)]

#[cfg(feature = "std")]
pub use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(all(feature = "std", feature = "platform-tokio"))]
pub use parking_lot as parking_reexport;

#[cfg(feature = "std")]
mod rwmap_impl {
    use super::RwLock;
    use alloc::collections::BTreeMap;

    /// DashMap-shaped shim: `RwLock<BTreeMap>`, covering the subset of
    /// methods used in-tree.
    pub struct RwMap<K: Ord, V> {
        inner: RwLock<BTreeMap<K, V>>,
    }

    impl<K: Ord, V> Default for RwMap<K, V> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: Ord, V> RwMap<K, V> {
        pub fn new() -> Self {
            Self {
                inner: RwLock::new(BTreeMap::new()),
            }
        }

        pub fn insert(&self, key: K, value: V) -> Option<V> {
            self.inner.write().insert(key, value)
        }

        pub fn remove(&self, key: &K) -> Option<V> {
            self.inner.write().remove(key)
        }

        pub fn get(&self, key: &K) -> Option<V>
        where
            V: Clone,
        {
            self.inner.read().get(key).cloned()
        }

        pub fn len(&self) -> usize {
            self.inner.read().len()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.read().is_empty()
        }

        pub fn contains_key(&self, key: &K) -> bool {
            self.inner.read().contains_key(key)
        }

        pub fn retain(&self, f: impl FnMut(&K, &mut V) -> bool) {
            self.inner.write().retain(f);
        }

        /// Read-only escape hatch (iteration/aggregation).
        pub fn with<R>(&self, f: impl FnOnce(&BTreeMap<K, V>) -> R) -> R {
            f(&self.inner.read())
        }

        /// Mutable escape hatch.
        pub fn with_mut<R>(&self, f: impl FnOnce(&mut BTreeMap<K, V>) -> R) -> R {
            f(&mut self.inner.write())
        }
    }
}

#[cfg(all(feature = "std", feature = "platform-tokio"))]
pub use rwmap_impl::*;

// ── no_std (platform-embassy): spin locks ──
#[cfg(not(feature = "std"))]
mod spin_lock {
    use core::cell::UnsafeCell;
    use core::ops::{Deref, DerefMut};
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct SpinLock<T> {
        locked: AtomicBool,
        data: UnsafeCell<T>,
    }

    /// Read/write wrapper (matches the parking_lot RwLock read/write call
    /// shape; implemented as a mutex — writers spin briefly under
    /// read-heavy workloads, which is acceptable).
    pub struct RwLock<T>(SpinLock<T>);

    impl<T> RwLock<T> {
        pub const fn new(value: T) -> Self {
            Self(SpinLock::new(value))
        }

        pub fn read(&self) -> SpinGuard<'_, T> {
            self.0.lock()
        }

        pub fn write(&self) -> SpinGuard<'_, T> {
            self.0.lock()
        }
    }

    unsafe impl<T: Send> Send for SpinLock<T> {}
    unsafe impl<T: Send> Sync for SpinLock<T> {}

    impl<T> SpinLock<T> {
        pub const fn new(value: T) -> Self {
            Self {
                locked: AtomicBool::new(false),
                data: UnsafeCell::new(value),
            }
        }

        pub fn lock(&self) -> SpinGuard<'_, T> {
            while self.locked.swap(true, Ordering::Acquire) {
                core::hint::spin_loop();
            }
            SpinGuard { lock: self }
        }
    }

    pub struct SpinGuard<'a, T> {
        lock: &'a SpinLock<T>,
    }

    impl<T> Drop for SpinGuard<'_, T> {
        fn drop(&mut self) {
            self.lock.locked.store(false, Ordering::Release);
        }
    }

    impl<T> Deref for SpinGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { &*self.lock.data.get() }
        }
    }

    // parking_lot's guards forward Display/Debug; mirror that here so
    // logging call sites like `%old_state` behave identically on both
    // backends.
    impl<T: core::fmt::Display> core::fmt::Display for SpinGuard<'_, T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(&**self, f)
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for SpinGuard<'_, T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(&**self, f)
        }
    }

    impl<T> DerefMut for SpinGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { &mut *self.lock.data.get() }
        }
    }
}

#[cfg(not(feature = "std"))]
pub use spin_lock::{RwLock, SpinGuard, SpinLock};

#[cfg(not(feature = "std"))]
pub type Mutex<T> = SpinLock<T>;
#[cfg(not(feature = "std"))]
pub type MutexGuard<'a, T> = SpinGuard<'a, T>;
#[cfg(not(feature = "std"))]
pub type RwLockReadGuard<'a, T> = SpinGuard<'a, T>;
#[cfg(not(feature = "std"))]
pub type RwLockWriteGuard<'a, T> = SpinGuard<'a, T>;

#[cfg(not(feature = "std"))]
mod rwmap_impl {
    use super::Mutex;
    use alloc::collections::BTreeMap;

    /// DashMap-shaped shim (no_std: spin `Mutex<BTreeMap>`).
    pub struct RwMap<K: Ord, V> {
        inner: Mutex<BTreeMap<K, V>>,
    }

    impl<K: Ord, V> Default for RwMap<K, V> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: Ord, V> RwMap<K, V> {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(BTreeMap::new()),
            }
        }

        pub fn insert(&self, key: K, value: V) -> Option<V> {
            self.inner.lock().insert(key, value)
        }

        pub fn remove(&self, key: &K) -> Option<V> {
            self.inner.lock().remove(key)
        }

        pub fn get(&self, key: &K) -> Option<V>
        where
            V: Clone,
        {
            self.inner.lock().get(key).cloned()
        }

        pub fn len(&self) -> usize {
            self.inner.lock().len()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.lock().is_empty()
        }

        pub fn contains_key(&self, key: &K) -> bool {
            self.inner.lock().contains_key(key)
        }

        pub fn retain(&self, f: impl FnMut(&K, &mut V) -> bool) {
            self.inner.lock().retain(f);
        }

        /// Read-only escape hatch (iteration/aggregation).
        pub fn with<R>(&self, f: impl FnOnce(&BTreeMap<K, V>) -> R) -> R {
            let guard = self.inner.lock();
            f(&guard)
        }

        /// Mutable escape hatch.
        pub fn with_mut<R>(&self, f: impl FnOnce(&mut BTreeMap<K, V>) -> R) -> R {
            f(&mut self.inner.lock())
        }
    }
}

#[cfg(not(feature = "std"))]
pub use rwmap_impl::*;
