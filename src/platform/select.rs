//! Backend-agnostic racing combinators (replace `tokio::select!` at the
//! drive-loop sites). Poll-based and unbiased: both futures are polled on
//! every wake; whichever completes first wins.
//!
//! Futures are taken by value — callers pass `&mut` of `core::pin::pin!(..)`
//! bindings (`&mut Pin<&mut F>` is a Future and is Unpin).
//!
//! Cancel-safety matches `tokio::select!`: when the combinator completes on
//! one arm, the other arm's future is dropped (work on it stops).

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_util::FutureExt;

/// Two-arm race output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Either<A, B> {
    A(A),
    B(B),
}

/// Three-arm race output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which3<A, B, C> {
    A(A),
    B(B),
    C(C),
}

/// Races two futures; see [`select2`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Select2<A: Future, B: Future> {
    a: A,
    b: B,
}

/// Races two futures.
pub fn select2<A: Future, B: Future>(a: A, b: B) -> Select2<A, B> {
    Select2 { a, b }
}

impl<A: Future + Unpin, B: Future + Unpin> Future for Select2<A, B> {
    type Output = Either<A::Output, B::Output>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Poll::Ready(v) = this.a.poll_unpin(cx) {
            return Poll::Ready(Either::A(v));
        }
        if let Poll::Ready(v) = this.b.poll_unpin(cx) {
            return Poll::Ready(Either::B(v));
        }
        Poll::Pending
    }
}

/// Races three futures; see [`select3`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Select3<A: Future, B: Future, C: Future> {
    a: A,
    b: B,
    c: C,
}

/// Races three futures.
pub fn select3<A: Future, B: Future, C: Future>(a: A, b: B, c: C) -> Select3<A, B, C> {
    Select3 { a, b, c }
}

impl<A: Future + Unpin, B: Future + Unpin, C: Future + Unpin> Future for Select3<A, B, C> {
    type Output = Which3<A::Output, B::Output, C::Output>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Poll::Ready(v) = this.a.poll_unpin(cx) {
            return Poll::Ready(Which3::A(v));
        }
        if let Poll::Ready(v) = this.b.poll_unpin(cx) {
            return Poll::Ready(Which3::B(v));
        }
        if let Poll::Ready(v) = this.c.poll_unpin(cx) {
            return Poll::Ready(Which3::C(v));
        }
        Poll::Pending
    }
}
