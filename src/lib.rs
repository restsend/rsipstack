// A SIP stack in Rust

//! # RSIPStack - A SIP Stack Implementation in Rust
//!
//! RSIPStack is a comprehensive Session Initiation Protocol (SIP) implementation
//! written in Rust. It provides a complete SIP stack with support for multiple
//! transport protocols, transaction management, dialog handling, and more.
//!
//! ## Features
//!
//! * **Complete SIP Implementation** - Full RFC 3261 compliance
//! * **Multiple Transports** - UDP, TCP, TLS, WebSocket support
//! * **Transaction Layer** - Automatic retransmissions and timer management
//! * **Dialog Management** - Full dialog state machine implementation
//! * **Async/Await Support** - Built on Tokio for high performance
//! * **Type Safety** - Leverages Rust's type system for protocol correctness
//! * **Extensible** - Modular design for easy customization
//!
//! ## Architecture
//!
//! The stack is organized into several layers following the SIP specification:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │           Application Layer         │
//! ├─────────────────────────────────────┤
//! │           Dialog Layer              │
//! ├─────────────────────────────────────┤
//! │         Transaction Layer           │
//! ├─────────────────────────────────────┤
//! │          Transport Layer            │
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ### Creating a SIP Endpoint
//!
//! ```rust,no_run
//! use rsipstack::EndpointBuilder;
//! use tokio_util::sync::CancellationToken;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a SIP endpoint
//!     let endpoint = EndpointBuilder::new()
//!         .with_user_agent("MyApp/1.0")
//!         .build();
//!
//!     // Get incoming transactions
//!     let mut incoming = endpoint.incoming_transactions().expect("incoming_transactions");
//!
//!     // Start the endpoint (in production, you'd run this in a separate task)
//!     // let endpoint_inner = endpoint.inner.clone();
//!     // tokio::spawn(async move {
//!     //     endpoint_inner.serve().await.ok();
//!     // });
//!
//!     // Process incoming requests
//!     while let Some(transaction) = incoming.recv().await {
//!         // Handle the transaction
//!         println!("Received: {}", transaction.original.method);
//!         break; // Exit for example
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Sending SIP Requests
//!
//! ```rust,no_run
//! use rsipstack::dialog::dialog_layer::DialogLayer;
//! use rsipstack::dialog::invitation::InviteOption;
//! use rsipstack::transaction::endpoint::EndpointInner;
//! use std::sync::Arc;
//!
//! # async fn example() -> rsipstack::Result<()> {
//! # let endpoint: Arc<EndpointInner> = todo!();
//! # let state_sender = todo!();
//! # let sdp_body = vec![];
//! // Create a dialog layer
//! let dialog_layer = DialogLayer::new(endpoint.clone());
//!
//! // Send an INVITE
//! let invite_option = InviteOption {
//!     caller: rsip::Uri::try_from("sip:alice@example.com")?,
//!     callee: rsip::Uri::try_from("sip:bob@example.com")?,
//!     contact: rsip::Uri::try_from("sip:alice@myhost.com:5060")?,
//!     content_type: Some("application/sdp".to_string()),
//!     offer: Some(sdp_body),
//!     ..Default::default()
//! };
//!
//! let (dialog, response) = dialog_layer.do_invite(invite_option, state_sender).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Core Components
//!
//! ### Transport Layer
//!
//! The transport layer handles network communication across different protocols:
//!
//! * [`SipConnection`](transport::SipConnection) - Abstraction over transport protocols
//! * [`SipAddr`](transport::SipAddr) - SIP addressing with transport information
//! * [`TransportLayer`](transport::TransportLayer) - Transport management
//!
//! ### Transaction Layer
//!
//! The transaction layer provides reliable message delivery:
//!
//! * [`Transaction`](transaction::transaction::Transaction) - SIP transaction implementation
//! * [`Endpoint`](transaction::Endpoint) - SIP endpoint for transaction management
//! * [`TransactionState`](transaction::TransactionState) - Transaction state machine
//!
//! ### Dialog Layer
//!
//! The dialog layer manages SIP dialogs and sessions:
//!
//! * [`Dialog`](dialog::dialog::Dialog) - SIP dialog representation
//! * [`DialogId`](dialog::DialogId) - Dialog identification
//! * [`DialogState`](dialog::dialog::DialogState) - Dialog state management
//!
//! ## Error Handling
//!
//! The stack uses a comprehensive error type that covers all layers:
//!
//! ```rust
//! use rsipstack::{Result, Error};
//!
//! fn handle_sip_error(error: Error) {
//!     match error {
//!         Error::TransportLayerError(msg, addr) => {
//!             eprintln!("Transport error at {msg}: {addr}");
//!         },
//!         Error::TransactionError(msg, key) => {
//!             eprintln!("Transaction error {msg}: {key}");
//!         },
//!         Error::DialogError(msg, id, code) => {
//!             eprintln!("Dialog error {msg}: {id} (Status code: {code})");
//!         },
//!         _ => eprintln!("Other error: {}", error),
//!     }
//! }
//! ```
//!
//! ## Configuration
//!
//! The stack can be configured for different use cases:
//!
//! ### Basic UDP Server
//!
//! ```rust,no_run
//! use rsipstack::EndpointBuilder;
//! use rsipstack::transport::{TransportLayer, udp::UdpConnection};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example() -> rsipstack::Result<()> {
//! # let cancel_token = CancellationToken::new();
//! let transport_layer = TransportLayer::new(cancel_token.child_token());
//! let udp_conn = UdpConnection::create_connection("0.0.0.0:5060".parse()?, None, Some(cancel_token.child_token())).await?;
//! transport_layer.add_transport(udp_conn.into());
//!
//! let endpoint = EndpointBuilder::new()
//!     .with_transport_layer(transport_layer)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ### Secure TLS Server
//!
//! ```rust,no_run
//! #[cfg(feature = "rustls")]
//! use rsipstack::transport::tls::{TlsConnection, TlsConfig};
//! use rsipstack::transport::TransportLayer;
//!
//! # async fn example() -> rsipstack::Result<()> {
//! # let cert_pem = vec![];
//! # let key_pem = vec![];
//! # let transport_layer: TransportLayer = todo!();
//! // Configure TLS transport
//! let tls_config = TlsConfig {
//!     cert: Some(cert_pem),
//!     key: Some(key_pem),
//!     ..Default::default()
//! };
//!
//! // TLS connections would be created using the TLS configuration
//! // let tls_conn = TlsConnection::serve_listener(...).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Standards Compliance
//!
//! RSIPStack implements the following RFCs:
//!
//! * **RFC 3261** - SIP: Session Initiation Protocol (core specification)
//! * **RFC 3581** - Symmetric Response Routing (rport)
//! * **RFC 6026** - Correct Transaction Handling for 2xx Responses to INVITE
//!
//! ## Performance
//!
//! The stack is designed for high performance:
//!
//! * **Zero-copy parsing** where possible
//! * **Async I/O** with Tokio for scalability
//! * **Efficient timer management** for large numbers of transactions
//! * **Memory-safe** with Rust's ownership system
//!
//! ## Testing
//!
//! Comprehensive test suite covering:
//!
//! * Unit tests for all components
//! * Integration tests for protocol compliance
//! * Performance benchmarks
//! * Interoperability testing
//!
//! ## Examples
//!
//! See the `examples/` directory for complete working examples:
//!
//! * Simple SIP client
//! * SIP proxy server
//! * WebSocket SIP gateway
//! * Load testing tools

pub type Result<T> = std::result::Result<T, crate::error::Error>;
pub use crate::error::Error;
pub mod dialog;
pub mod error;
pub mod resolver;
pub mod transaction;
pub mod transport;
pub use transaction::EndpointBuilder;
pub mod rsip_ext;

pub const VERSION: &str = concat!("rsipstack/", env!("CARGO_PKG_VERSION"));
