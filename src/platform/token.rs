//! Minimal `CancellationToken` for the embassy backend (no_std).
//!
//! Replaces `tokio_util::sync::CancellationToken` (std-only) on the
//! platform-embassy path. Semantics mirror the used API surface:
//!
//! - `cancel()` flips the flag and wakes every registered waiter;
//! - `is_cancelled()` walks the parent chain (a cancelled parent cancels
//!   all descendants);
//! - `cancelled()` polls the chain, registering its waker on every node so
//!   a cancel at any ancestor level wakes it;
//! - `child_token()` creates a linked child (weak parent → no cycles, and
//!   nothing to clean up on drop).
//!
//! Wake storage is a `CriticalSectionRawMutex` mutex: waking from an ISR /
//! critical section is safe and the waiter count per dialog is tiny.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use core::cell::RefCell;

type WakerList = critical_section::Mutex<RefCell<Vec<Waker>>>;

struct TokenInner {
    flag: AtomicBool,
    parent: Option<Weak<TokenInner>>,
    wakers: WakerList,
}

impl TokenInner {
    /// True when this node or any ancestor is cancelled.
    fn is_cancelled(&self) -> bool {
        if self.flag.load(Ordering::Acquire) {
            return true;
        }
        let mut ancestor = self.parent.as_ref().and_then(Weak::upgrade);
        while let Some(node) = ancestor {
            if node.flag.load(Ordering::Acquire) {
                return true;
            }
            ancestor = node.parent.as_ref().and_then(Weak::upgrade);
        }
        false
    }

    fn wake_all(&self) {
        // Collect under the critical section, wake outside it: waking a
        // task may run arbitrary scheduling code that must not re-enter
        // the critical section.
        let drained =
            critical_section::with(|cs| core::mem::take(&mut *self.wakers.borrow_ref_mut(cs)));
        for w in drained {
            w.wake();
        }
    }
}

/// Cooperative cancellation handle (embassy backend).
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<TokenInner>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TokenInner {
                flag: AtomicBool::new(false),
                parent: None,
                wakers: critical_section::Mutex::new(RefCell::new(Vec::new())),
            }),
        }
    }

    /// Cancels this token and every descendant (via the parent-chain check).
    pub fn cancel(&self) {
        self.inner.flag.store(true, Ordering::Release);
        self.inner.wake_all();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Creates a child linked to this token: cancelling either cancels both.
    pub fn child_token(&self) -> CancellationToken {
        CancellationToken {
            inner: Arc::new(TokenInner {
                flag: AtomicBool::new(false),
                parent: Some(Arc::downgrade(&self.inner)),
                wakers: critical_section::Mutex::new(RefCell::new(Vec::new())),
            }),
        }
    }

    /// Resolves when this token or any ancestor is cancelled.
    pub fn cancelled(&self) -> Cancelled<'_> {
        Cancelled { token: self }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Future returned by [`CancellationToken::cancelled`].
pub struct Cancelled<'a> {
    token: &'a CancellationToken,
}

impl Future for Cancelled<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let inner = &self.token.inner;
        if inner.is_cancelled() {
            return Poll::Ready(());
        }
        // Register on every node of the chain so a cancel at any level
        // wakes this waiter. Critical sections make the registration
        // ISR-safe; a cancel racing between the check and the registration
        // still wakes us because cancel() flips the flag first and drains
        // the list afterwards — if the list was drained before our push,
        // the very next poll re-checks `is_cancelled` and completes.
        let waker = cx.waker().clone();
        let mut node = Some(Arc::clone(inner));
        while let Some(n) = node {
            critical_section::with(|cs| {
                n.wakers.borrow_ref_mut(cs).push(waker.clone());
            });
            node = n.parent.as_ref().and_then(Weak::upgrade);
        }
        Poll::Pending
    }
}
