//! Platform abstraction layer — multi-backend (WP0→WP3).
//!
//! Every runtime primitive used by the library core is routed through this
//! module. Two backends:
//!
//! | feature | backend | target |
//! |---|---|---|
//! | `platform-tokio` (default, implies `std`) | tokio + parking_lot | server/desktop |
//! | `platform-embassy` | embassy-time / embassy-sync / critical-section | embedded (ESP32-S3) |
//!
//! Deliberate differences:
//! - `spawn` on the embassy backend goes through an **injected function
//!   pointer** (`set_spawn_fn`), implemented by the application (rtcembed)
//!   on top of its executor's task pool — rsipstack does not depend on any
//!   specific executor and therefore stays neutral about the target
//!   chip/arch. Panics when unset (same as tokio without a runtime).
//! - `mpsc::channel(n)` capacity is ignored on the embassy backend
//!   (effectively unbounded); core usage is all low-frequency paths.
//! - `tokio::net` transports (udp/tcp/tls/websocket/stream) exist only in
//!   `platform-tokio` builds (gated since WP1).
//!
//! The select combinators ([`select2`]/[`select3`]) are backend-agnostic;
//! see [`select`].

use core::future::Future;
use core::time::Duration;

#[cfg(feature = "platform-embassy")]
pub mod mpsc;
#[cfg(feature = "platform-tokio")]
pub use tokio::sync::mpsc;
pub mod atomic64;
pub mod net;
pub mod select;

pub use select::{select2, select3, Either, Select2, Select3, Which3};

// ── tokio backend ──
#[cfg(feature = "platform-tokio")]
pub type BoundedSender<T> = tokio::sync::mpsc::Sender<T>;
#[cfg(feature = "platform-tokio")]
pub type BoundedReceiver<T> = tokio::sync::mpsc::Receiver<T>;
#[cfg(feature = "platform-tokio")]
pub use std::time::Instant;
#[cfg(feature = "platform-tokio")]
pub use tokio::sync::Notify;
#[cfg(feature = "platform-tokio")]
pub use tokio::task::JoinHandle;
#[cfg(feature = "platform-tokio")]
pub use tokio::time::error::Elapsed;
#[cfg(feature = "platform-tokio")]
pub use tokio_util::sync::CancellationToken;

/// Sleeps for the given duration.
#[cfg(feature = "platform-tokio")]
pub async fn sleep(dur: Duration) {
    tokio::time::sleep(dur).await;
}

/// Applies a timeout to a future.
#[cfg(feature = "platform-tokio")]
pub async fn timeout<T>(dur: Duration, future: impl Future<Output = T>) -> Result<T, Elapsed> {
    tokio::time::timeout(dur, future).await
}

/// Spawns a task on the platform runtime.
#[cfg(feature = "platform-tokio")]
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// Spawns a task that resolves through the returned `JoinHandle`.
#[cfg(feature = "platform-tokio")]
pub fn spawn_with_result<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future)
}

// ── embassy backend ──
//
// sleep/Instant → embassy-time；Notify → embassy-sync Signal；
// mpsc → this crate's unbounded channel (critical-section + Signal);
// spawn → injected function pointer (the application calls
// [`set_spawn_fn`] after executor init).
// CancellationToken keeps using tokio-util's `sync` feature — it does not
// depend on the tokio runtime.
#[cfg(feature = "platform-embassy")]
pub mod embassy_impl {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::sync::atomic::{AtomicPtr, Ordering};

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::signal::Signal;

    /// Spawn function injected by the application: hands a boxed future to the
    /// executor's task pool.
    pub type SpawnFn = fn(Box<dyn Future<Output = ()> + Send>);

    static SPAWN_FN: AtomicPtr<SpawnFn> = AtomicPtr::new(core::ptr::null_mut());

    /// Called once by the application after executor init (thread-safe).
    pub fn set_spawn_fn(f: SpawnFn) {
        let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(f));
        SPAWN_FN.store(leaked as *mut SpawnFn, Ordering::Release);
    }

    /// Internal shared Notify channel (Signal's `()` semantics match tokio
    /// Notify's waiter wakeup).
    #[derive(Clone)]
    pub struct Notify {
        signal: Arc<Signal<CriticalSectionRawMutex, ()>>,
    }

    impl Notify {
        pub fn new() -> Self {
            Self {
                signal: Arc::new(Signal::new()),
            }
        }

        /// Cancel-safe (`Signal::wait` guarantees no lost values).
        pub fn notified(&self) -> impl Future<Output = ()> + '_ {
            self.signal.wait()
        }

        pub fn notify_waiters(&self) {
            self.signal.signal(());
        }

        pub fn notify_one(&self) {
            self.signal.signal(());
        }
    }

    impl Default for Notify {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Waits inside the executor context until the spawn function is injected
    /// (briefly enters a critical section internally).
    pub(crate) fn with_spawn_fn<R>(f: impl FnOnce(SpawnFn) -> R) -> R {
        critical_section::with(|_| {
            let ptr = SPAWN_FN.load(Ordering::Acquire);
            assert!(!ptr.is_null(), "platform: spawn fn not configured");
            f(unsafe { *ptr })
        })
    }
}

#[cfg(feature = "platform-embassy")]
pub use embassy_impl::{set_spawn_fn, Notify as EmbassyNotify};
#[cfg(feature = "platform-embassy")]
pub use mpsc::bounded::{Receiver as BoundedReceiver, Sender as BoundedSender};
#[cfg(feature = "platform-embassy")]
pub use EmbassyNotify as Notify;

/// Instant wrapper: unifies the `+ core::time::Duration` and
/// `checked_duration_since` call shapes (std backend =
/// `std::time::Instant`; embassy = `embassy_time::Instant`).
#[cfg(feature = "platform-embassy")]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(embassy_time::Instant);

#[cfg(feature = "platform-embassy")]
impl Instant {
    pub fn now() -> Self {
        Self(embassy_time::Instant::now())
    }

    pub fn checked_duration_since(&self, earlier: Self) -> Option<core::time::Duration> {
        if self.0 >= earlier.0 {
            let d = self.0 - earlier.0;
            let micros = d.as_micros();
            Some(core::time::Duration::from_micros(micros))
        } else {
            None
        }
    }
}

#[cfg(feature = "platform-embassy")]
impl core::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: Duration) -> Instant {
        Self(
            self.0
                + embassy_time::Duration::from_micros(rhs.as_micros().min(u64::MAX as u128) as u64),
        )
    }
}

#[cfg(feature = "platform-embassy")]
pub async fn sleep(dur: Duration) {
    embassy_time::Timer::after(embassy_time::Duration::from_micros(
        dur.as_micros().min(u64::MAX as u128) as u64,
    ))
    .await;
}

/// Applies a timeout to a future. `Err` = timed out (callers only
/// distinguish success from timeout).
#[cfg(feature = "platform-embassy")]
pub async fn timeout<T>(
    dur: Duration,
    future: impl Future<Output = T>,
) -> Result<T, embassy_time::TimeoutError> {
    embassy_time::with_timeout(
        embassy_time::Duration::from_micros(dur.as_micros().min(u64::MAX as u128) as u64),
        future,
    )
    .await
}

/// Spawns a task through the injected spawn function (see [`set_spawn_fn`]).
///
/// The embassy backend cannot provide a `JoinHandle` for an arbitrary
/// future — call sites that need the result use [`spawn_with_result`]
/// (a capacity-1 result channel + a Future-shaped handle).
#[cfg(feature = "platform-embassy")]
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let boxed: alloc::boxed::Box<dyn Future<Output = ()> + Send> = alloc::boxed::Box::new(future);
    embassy_impl::with_spawn_fn(|spawn| spawn(boxed));
}

/// embassy backend JoinHandle: receiving end of a capacity-1 result
/// channel (impl Future).
#[cfg(feature = "platform-embassy")]
pub struct JoinHandle<T> {
    rx: crate::platform::mpsc::BoundedReceiver<T>,
}

#[cfg(feature = "platform-embassy")]
impl<T: Send + 'static> Future for JoinHandle<T> {
    type Output = T;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<T> {
        let this = self.get_mut();
        let fut = this.rx.recv();
        let mut fut = core::pin::pin!(fut);
        core::future::Future::poll(fut.as_mut(), cx) // Receiver::recv is cancel-safe; recv yields Option<T> and the spawn side always sends a value
            .map(|opt| opt.expect("spawn_with_result sender alive"))
    }
}

/// Spawns a task that resolves through the returned `JoinHandle`.
#[cfg(feature = "platform-embassy")]
pub fn spawn_with_result<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = crate::platform::mpsc::channel::<T>(1);
    spawn(async move {
        let out = future.await;
        let _ = tx.send(out);
    });
    JoinHandle { rx }
}

#[cfg(all(not(feature = "platform-tokio"), not(feature = "platform-embassy")))]
compile_error!(
    "rsipstack: no platform backend enabled; enable \"platform-tokio\" (host) \
     or \"platform-embassy\" (embedded, WP3)"
);

// ── internal data-structure primitives (implemented per backend in sync.rs) ──
pub mod sync;

// ── CancellationToken for the embassy backend (tokio-util `sync` does
// not depend on the tokio runtime) ──
#[cfg(feature = "platform-embassy")]
pub mod token;
#[cfg(feature = "platform-embassy")]
pub use token::CancellationToken;
