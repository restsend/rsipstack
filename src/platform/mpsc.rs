//! Unbounded async MPSC channel (embassy backend).
//!
//! Matches the tokio unbounded semantics the core uses (`send` never blocks,
//! `recv` waits). Grows on demand (alloc); embedded deployments should keep
//! the queue shallow by construction — the transport loop is the only
//! high-rate producer and the endpoint drains it continuously.
//!
//! Cancel-safety: `recv` is cancel-safe (nothing is lost if the future is
//! dropped before a value is available).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

pub mod error {
    //! Error shapes aligned with tokio mpsc.

    #[derive(Debug, PartialEq, Eq)]
    pub struct SendError<T>(pub T);

    #[derive(Debug, PartialEq, Eq)]
    pub enum TrySendError<T> {
        Full(T),
        Closed(T),
    }
}

pub use error::{SendError, TrySendError};

impl<T> core::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("channel closed")
    }
}

impl<T> core::fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrySendError::Full(_) => f.write_str("channel full"),
            TrySendError::Closed(_) => f.write_str("channel closed"),
        }
    }
}

impl<T> From<SendError<T>> for TrySendError<T> {
    fn from(e: SendError<T>) -> Self {
        TrySendError::Closed(e.0)
    }
}

struct Inner<T> {
    queue: critical_section::Mutex<RefCell<VecDeque<T>>>,
    notify: Signal<CriticalSectionRawMutex, ()>,
    closed: AtomicBool,
}

/// Unbounded channel sender.
pub struct Sender<T> {
    inner: Arc<Inner<T>>,
}

/// Unbounded channel receiver.
pub struct Receiver<T> {
    inner: Arc<Inner<T>>,
}

pub type UnboundedSender<T> = Sender<T>;
pub type UnboundedReceiver<T> = Receiver<T>;

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sender")
    }
}

impl<T> Sender<T> {
    /// Unbounded: never blocks.
    pub fn send(&self, value: T) -> Result<(), error::SendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(error::SendError(value));
        }
        critical_section::with(|cs| self.inner.queue.borrow_ref_mut(cs).push_back(value));
        self.inner.notify.signal(());
        Ok(())
    }

    /// Under unbounded semantics this equals `send` (never full).
    pub fn try_send(&self, value: T) -> Result<(), error::TrySendError<T>> {
        self.send(value).map_err(error::SendError::into)
    }
}

impl<T> Receiver<T> {
    /// Waits for the next value; `None` when the channel is closed and drained.
    pub async fn recv(&self) -> Option<T> {
        loop {
            if let Some(v) = self.try_recv_inner() {
                return Some(v);
            }
            if self.inner.closed.load(Ordering::Acquire) {
                return None;
            }
            self.inner.notify.wait().await;
        }
    }

    fn try_recv_inner(&self) -> Option<T> {
        critical_section::with(|cs| self.inner.queue.borrow_ref_mut(cs).pop_front())
    }
}

/// Creates an unbounded channel pair.
pub fn unbounded_channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(Inner {
        queue: critical_section::Mutex::new(RefCell::new(VecDeque::new())),
        notify: Signal::new(),
        closed: AtomicBool::new(false),
    });
    (
        Sender {
            inner: inner.clone(),
        },
        Receiver { inner },
    )
}

/// Bounded channel (async `send`; matches the tokio `channel(n)` call
/// shape). embassy `Channel` needs a compile-time capacity: fixed at 64
/// (in-tree uses are 4/16 — both covered).
pub mod bounded {
    use super::error;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::Channel;

    const CAPACITY: usize = 64;

    pub(crate) struct Inner<T> {
        pub(crate) channel: Channel<CriticalSectionRawMutex, T, CAPACITY>,
        pub(crate) closed: AtomicBool,
    }

    /// Bounded channel pair (`cap` ignored: embassy `Channel` capacity is
    /// fixed at compile time as CAPACITY).
    pub fn pair<T>() -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(Inner {
            channel: Channel::new(),
            closed: AtomicBool::new(false),
        });
        (
            Sender {
                inner: inner.clone(),
            },
            Receiver { inner },
        )
    }

    pub struct Sender<T> {
        inner: Arc<Inner<T>>,
    }

    pub struct Receiver<T> {
        inner: Arc<Inner<T>>,
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for Sender<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("bounded::Sender")
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for Receiver<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("bounded::Receiver")
        }
    }

    impl<T> Sender<T> {
        /// Bounded semantics: waits when full (matches tokio bounded
        /// `send().await`).
        pub async fn send(&self, value: T) -> Result<(), error::SendError<T>> {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(error::SendError(value));
            }
            self.inner.channel.send(value).await;
            Ok(())
        }

        pub fn try_send(&self, value: T) -> Result<(), error::TrySendError<T>> {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(error::TrySendError::Closed(value));
            }
            self.inner.channel.try_send(value).map_err(|e| match e {
                embassy_sync::channel::TrySendError::Full(v) => error::TrySendError::Full(v),
            })
        }
    }

    impl<T> Receiver<T> {
        pub async fn recv(&self) -> Option<T> {
            if self.inner.closed.load(Ordering::Acquire) {
                return None;
            }
            Some(self.inner.channel.receive().await)
        }
    }
}

pub use bounded::{Receiver as BoundedReceiver, Sender as BoundedSender};

/// Bounded channel pair (embassy backend capacity is always 64; `cap`
/// exists for API parity).
pub fn channel<T>(_capacity: usize) -> (bounded::Sender<T>, bounded::Receiver<T>) {
    bounded::pair()
}

/// Closes the channel (`recv` returns None once drained).
pub fn close<T>(rx: &Receiver<T>) {
    rx.inner.closed.store(true, Ordering::Release);
    rx.inner.notify.signal(());
}
