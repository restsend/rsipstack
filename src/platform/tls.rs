//! Backend-agnostic TLS client seam (SIPS).
//!
//! `transport::tls::TlsConnection::connect` consults the connector registered
//! here before falling back to the built-in rustls path, so custom TLS stacks
//! — including embedded ones over embassy-net (embedded-tls, esp-mbedtls) —
//! can provide SIPS without tokio or rustls. Host builds are unaffected when
//! nothing is registered.
//!
//! The connector **owns the TCP dial**: each backend brings its own TCP stack
//! (tokio on the host, embassy-net on embedded), so the seam only passes the
//! target address. Streams expose async-fn IO with owned buffers, which is
//！ directly implementable over `embedded-io-async` / rustls alike; the host
//! adapter buffers chunks when bridging into tokio's poll-based halves.

use crate::Result;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Backend-agnostic TLS client configuration (PEM encodings).
#[derive(Debug, Clone, Default)]
pub struct TlsClientConfig {
    /// SNI / certificate verification name (e.g. `pbx.example.com`).
    pub server_name: String,
    /// Root certificates to trust (PEM). `None`/empty: backend default trust.
    pub root_certs: Option<Vec<u8>>,
    /// Client certificate for mTLS (PEM).
    pub client_cert: Option<Vec<u8>>,
    /// Client key for mTLS (PEM).
    pub client_key: Option<Vec<u8>>,
}

/// An established TLS client session (handshake already completed).
#[async_trait::async_trait]
pub trait TlsStream: Send + Sync + 'static {
    /// Reads the next chunk of application data (one backend buffer's worth;
    /// chunking carries no message framing).
    async fn recv(&self) -> Result<Vec<u8>>;

    /// Sends all of `data`.
    async fn send_all(&self, data: Vec<u8>) -> Result<()>;

    /// Closes the session (TLS close_notify + TCP shutdown when supported).
    async fn shutdown(&self) -> Result<()>;

    /// Local socket address of the underlying TCP connection.
    fn local_addr(&self) -> Result<SocketAddr>;
}

/// Factory for outbound TLS sessions (SIPS client role). Owns the TCP dial.
#[async_trait::async_trait]
pub trait TlsConnector: Send + Sync + 'static {
    async fn connect(
        &self,
        config: &TlsClientConfig,
        addr: SocketAddr,
    ) -> Result<Box<dyn TlsStream>>;
}

static CLIENT_CONNECTOR: AtomicPtr<Arc<dyn TlsConnector>> = AtomicPtr::new(core::ptr::null_mut());

/// Registers the process-wide TLS client connector (thread-safe, leak-once).
/// Call once during startup, before any SIPS connection.
pub fn set_client_connector(connector: Arc<dyn TlsConnector>) {
    let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(connector));
    CLIENT_CONNECTOR.store(leaked as *mut Arc<dyn TlsConnector>, Ordering::Release);
}

/// Clears a previously registered connector (mainly for tests).
pub fn clear_client_connector() {
    CLIENT_CONNECTOR.store(core::ptr::null_mut(), Ordering::Release);
}

/// Returns the registered connector, if any.
pub fn client_connector() -> Option<Arc<dyn TlsConnector>> {
    let ptr = CLIENT_CONNECTOR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // The Arc was leaked at registration and outlives the process.
        unsafe { Some((*ptr).clone()) }
    }
}
