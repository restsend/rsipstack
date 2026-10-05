//! Backend-agnostic UDP socket seam for the transport layer (WP3).
//!
//! `transport::udp::UdpConnection` stores `Arc<dyn UdpSocket>`; the tokio
//! backend implements the trait for `tokio::net::UdpSocket`. Embedded
//! backends implement it over embassy-net (wrapping the `&mut self` recv in
//! an internal mutex to provide the shared-`&self` model the connection
//! clones need).

use crate::Result;
use alloc::boxed::Box;
use core::net::SocketAddr;

/// A UDP socket shared across connection clones: all async methods take
/// `&self`, so implementors must be internally synchronised.
#[async_trait::async_trait]
pub trait UdpSocket: Send + Sync + 'static {
    /// Receives one datagram into `buf`, returning `(len, source)`.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Sends one datagram; for UDP this always equals `buf.len()`.
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    fn local_addr(&self) -> Result<SocketAddr>;
}

#[cfg(feature = "platform-tokio")]
pub mod tokio_impl {
    use super::UdpSocket;
    use crate::Result;
    use core::net::SocketAddr;

    #[async_trait::async_trait]
    impl UdpSocket for tokio::net::UdpSocket {
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            Ok(tokio::net::UdpSocket::recv_from(self, buf).await?)
        }
        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
            Ok(tokio::net::UdpSocket::send_to(self, buf, addr).await?)
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Ok(tokio::net::UdpSocket::local_addr(self)?)
        }
    }
}
