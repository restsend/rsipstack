use super::{sip_addr::SipAddr, stream::StreamConnection, tcp::TcpConnection, udp::UdpConnection};
use crate::transport::channel::ChannelConnection;
use crate::transport::websocket::{WebSocketConnection, WebSocketListenerConnection};
use crate::transport::{
    tcp_listener::TcpListenerConnection,
    tls::{TlsConnection, TlsListenerConnection},
};
use crate::Result;
use get_if_addrs::IfAddr;
use rsip::{
    prelude::{HeadersExt, ToTypedHeader},
    Param, SipMessage,
};
use std::net::{IpAddr, Ipv4Addr};
use std::{fmt, net::SocketAddr};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Transport Layer Events
///
/// `TransportEvent` represents events that occur at the transport layer,
/// such as incoming messages, new connections, and connection closures.
/// These events are used to coordinate between the transport layer and
/// higher protocol layers.
///
/// # Events
///
/// * `Incoming` - A SIP message was received from the network
/// * `New` - A new connection has been established
/// * `Closed` - An existing connection has been closed
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transport::connection::TransportEvent;
///
/// # fn handle_event(event: TransportEvent) {
/// match event {
///     TransportEvent::Incoming(message, connection, source) => {
///         // Process incoming SIP message
///         println!("Received message from {}", source);
///     },
///     TransportEvent::New(connection) => {
///         // Handle new connection
///         println!("New connection established");
///     },
///     TransportEvent::Closed(connection) => {
///         // Handle connection closure
///         println!("Connection closed");
///     }
/// }
/// # }
/// ```
#[derive(Debug)]
pub enum TransportEvent {
    Incoming(SipMessage, SipConnection, SipAddr),
    New(SipConnection),
    Closed(SipConnection),
}

pub type TransportReceiver = UnboundedReceiver<TransportEvent>;
pub type TransportSender = UnboundedSender<TransportEvent>;

pub const KEEPALIVE_REQUEST: &[u8] = b"\r\n\r\n";
pub const KEEPALIVE_RESPONSE: &[u8] = b"\r\n";
pub const MAX_UDP_BUF_SIZE: usize = 8192;

/// SIP Connection
///
/// `SipConnection` is an enum that abstracts different transport protocols
/// used for SIP communication. It provides a unified interface for sending
/// SIP messages regardless of the underlying transport mechanism.
///
/// # Supported Transports
///
/// * `Udp` - UDP transport for connectionless communication
/// * `Channel` - In-memory channel for testing and local communication
/// * `Tcp` - TCP transport for reliable connection-oriented communication
/// * `Tls` - TLS transport for secure communication over TCP
/// * `WebSocket` - WebSocket transport for web-based SIP clients
///
/// # Key Features
///
/// * Transport abstraction - uniform interface across protocols
/// * Reliability detection - distinguishes reliable vs unreliable transports
/// * Address management - tracks local and remote addresses
/// * Message sending - handles protocol-specific message transmission
/// * Via header processing - automatic received parameter handling
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transport::{SipConnection, SipAddr};
/// use rsip::SipMessage;
///
/// // Send a message through any connection type
/// async fn send_message(
///     connection: &SipConnection,
///     message: SipMessage,
///     destination: Option<&SipAddr>
/// ) -> rsipstack::Result<()> {
///     connection.send(message, destination).await?;
///     Ok(())
/// }
///
/// # fn example(connection: &SipConnection) {
/// // Check if transport is reliable
/// let is_reliable = connection.is_reliable();
/// if is_reliable {
///     println!("Using reliable transport");
/// } else {
///     println!("Using unreliable transport - retransmissions may be needed");
/// }
/// # }
/// ```
///
/// # Transport Characteristics
///
/// ## UDP
/// * Connectionless and unreliable
/// * Requires retransmission handling
/// * Lower overhead
/// * Default SIP transport
///
/// ## TCP
/// * Connection-oriented and reliable
/// * No retransmission needed
/// * Higher overhead
/// * Better for large messages
///
/// ## TLS
/// * Secure TCP with encryption
/// * Reliable transport
/// * Certificate-based authentication
/// * Used for SIPS URIs
///
/// ## WebSocket
/// * Web-friendly transport
/// * Reliable connection
/// * Firewall and NAT friendly
/// * Used in web applications
///
/// # Via Header Processing
///
/// SipConnection automatically handles Via header processing for incoming
/// messages, adding 'received' and 'rport' parameters as needed per RFC 3261.
#[derive(Clone, Debug)]
pub enum SipConnection {
    Channel(ChannelConnection),
    Udp(UdpConnection),
    Tcp(TcpConnection),
    TcpListener(TcpListenerConnection),
    #[cfg(feature = "rustls")]
    Tls(TlsConnection),
    #[cfg(feature = "rustls")]
    TlsListener(TlsListenerConnection),
    #[cfg(feature = "websocket")]
    WebSocket(WebSocketConnection),
    #[cfg(feature = "websocket")]
    WebSocketListener(WebSocketListenerConnection),
}

impl SipConnection {
    pub fn is_reliable(&self) -> bool {
        match self {
            SipConnection::Udp(_) => false,
            _ => true,
        }
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        match self {
            SipConnection::Channel(transport) => transport.cancel_token(),
            SipConnection::Udp(transport) => transport.cancel_token(),
            SipConnection::Tcp(transport) => transport.cancel_token(),
            #[cfg(feature = "rustls")]
            SipConnection::Tls(transport) => transport.cancel_token(),
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(transport) => transport.cancel_token(),
            _ => None,
        }
    }
    pub fn get_addr(&self) -> &SipAddr {
        match self {
            SipConnection::Channel(transport) => transport.get_addr(),
            SipConnection::Udp(transport) => transport.get_addr(),
            SipConnection::Tcp(transport) => transport.get_addr(),
            SipConnection::TcpListener(transport) => transport.get_addr(),
            #[cfg(feature = "rustls")]
            SipConnection::Tls(transport) => transport.get_addr(),
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(transport) => transport.get_addr(),
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(transport) => transport.get_addr(),
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(transport) => transport.get_addr(),
        }
    }
    pub async fn send(&self, msg: rsip::SipMessage, destination: Option<&SipAddr>) -> Result<()> {
        match self {
            SipConnection::Channel(transport) => transport.send(msg).await,
            SipConnection::Udp(transport) => transport.send(msg, destination).await,
            SipConnection::Tcp(transport) => transport.send_message(msg).await,
            SipConnection::TcpListener(_) => {
                debug!("SipConnection::send: TcpListener cannot send messages");
                Ok(())
            }
            #[cfg(feature = "rustls")]
            SipConnection::Tls(transport) => transport.send_message(msg).await,
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(_) => {
                debug!("SipConnection::send: TlsListener cannot send messages");
                Ok(())
            }
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(transport) => transport.send_message(msg).await,
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(_) => {
                debug!("SipConnection::send: WebSocketListener cannot send messages");
                Ok(())
            }
        }
    }
    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        match self {
            SipConnection::Channel(transport) => transport.serve_loop(sender).await,
            SipConnection::Udp(transport) => transport.serve_loop(sender).await,
            SipConnection::Tcp(transport) => transport.serve_loop(sender).await,
            SipConnection::TcpListener(_) => {
                debug!("SipConnection::serve_loop: TcpListener does not have serve_loop");
                Ok(())
            }
            #[cfg(feature = "rustls")]
            SipConnection::Tls(transport) => transport.serve_loop(sender).await,
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(_) => {
                debug!("SipConnection::serve_loop: TlsListener does not have serve_loop");
                Ok(())
            }
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(transport) => transport.serve_loop(sender).await,
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(_) => {
                debug!("SipConnection::serve_loop: WebSocketListener does not have serve_loop");
                Ok(())
            }
        }
    }

    pub async fn close(&self) -> Result<()> {
        match self {
            SipConnection::Channel(transport) => transport.close().await,
            SipConnection::Udp(_) => Ok(()), // UDP has no connection state
            SipConnection::Tcp(transport) => transport.close().await,
            SipConnection::TcpListener(transport) => transport.close().await,
            #[cfg(feature = "rustls")]
            SipConnection::Tls(transport) => transport.close().await,
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(transport) => transport.close().await,
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(transport) => transport.close().await,
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(transport) => transport.close().await,
        }
    }
}

impl SipConnection {
    pub fn update_msg_received(
        msg: SipMessage,
        addr: SocketAddr,
        transport: rsip::transport::Transport,
    ) -> Result<SipMessage> {
        match msg {
            SipMessage::Request(mut req) => {
                let via = req.via_header_mut()?;
                Self::build_via_received(via, addr, transport)?;
                Ok(req.into())
            }
            SipMessage::Response(_) => Ok(msg),
        }
    }

    pub fn resolve_bind_address(addr: SocketAddr) -> SocketAddr {
        let ip = addr.ip();
        if ip.is_unspecified() {
            // 0.0.0.0 or ::
            let interfaces = match get_if_addrs::get_if_addrs() {
                Ok(interfaces) => interfaces,
                Err(_) => return addr,
            };
            for interface in interfaces {
                if interface.is_loopback() {
                    continue;
                }
                match interface.addr {
                    IfAddr::V4(v4addr) => {
                        return SocketAddr::new(IpAddr::V4(v4addr.ip), addr.port());
                    }
                    //TODO: don't support ipv6 for now
                    _ => continue,
                }
            }
            // fallback to loopback
            return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port());
        }
        addr
    }
    pub fn build_via_received(
        via: &mut rsip::headers::Via,
        addr: SocketAddr,
        transport: rsip::transport::Transport,
    ) -> Result<()> {
        let received = addr.into();
        let mut typed_via = via.typed()?;

        typed_via.params.retain(|param| {
            if let Param::Other(key, _) = param {
                !key.value().eq_ignore_ascii_case("rport")
            } else if matches!(param, Param::Received(_)) {
                false
            } else {
                true
            }
        });

        // Only add received parameter if the source address differs from Via header
        if typed_via.uri.host_with_port == received {
            return Ok(());
        }

        // For reliable transports (TCP/TLS/WS), we need to be more careful about received parameter
        let should_add_received = match transport {
            rsip::transport::Transport::Udp => true,
            _ => {
                // For connection-oriented protocols, only add if explicitly different
                typed_via.uri.host_with_port.host != received.host
            }
        };

        if !should_add_received {
            return Ok(());
        }

        if transport != rsip::transport::Transport::Udp && typed_via.transport != transport {
            typed_via.params.push(Param::Transport(transport));
        }

        *via = typed_via
            .with_param(Param::Received(rsip::param::Received::new(
                received.host.to_string(),
            )))
            .with_param(Param::Other(
                rsip::param::OtherParam::new("rport"),
                Some(rsip::param::OtherParamValue::new(addr.port().to_string())),
            ))
            .into();
        Ok(())
    }

    pub fn parse_target_from_via(
        via: &rsip::headers::untyped::Via,
    ) -> Result<(rsip::Transport, rsip::HostWithPort)> {
        let mut host_with_port = via.uri()?.host_with_port;
        let mut transport = via.trasnport().unwrap_or(rsip::Transport::Udp);
        if let Ok(params) = via.params().as_ref() {
            for param in params {
                match param {
                    Param::Received(v) => {
                        if let Ok(addr) = v.parse() {
                            host_with_port.host = addr.into();
                        }
                    }
                    Param::Transport(t) => {
                        transport = t.clone();
                    }
                    Param::Other(key, Some(value)) if key.value().eq_ignore_ascii_case("rport") => {
                        if let Ok(port) = value.value().try_into() {
                            host_with_port.port = Some(port);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok((transport, host_with_port))
    }

    pub fn get_destination(msg: &rsip::SipMessage) -> Result<SocketAddr> {
        let host_with_port = match msg {
            rsip::SipMessage::Request(req) => req.uri().host_with_port.clone(),
            rsip::SipMessage::Response(res) => Self::parse_target_from_via(res.via_header()?)?.1,
        };
        host_with_port.try_into().map_err(Into::into)
    }
}

impl fmt::Display for SipConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipConnection::Channel(t) => write!(f, "{}", t),
            SipConnection::Udp(t) => write!(f, "UDP {}", t),
            SipConnection::Tcp(t) => write!(f, "TCP {}", t),
            SipConnection::TcpListener(t) => write!(f, "TCP LISTEN {}", t),
            #[cfg(feature = "rustls")]
            SipConnection::Tls(t) => write!(f, "{}", t),
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(t) => write!(f, "TLS LISTEN {}", t),
            #[cfg(feature = "websocket")]
            SipConnection::WebSocket(t) => write!(f, "{}", t),
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(t) => write!(f, "WS LISTEN {}", t),
        }
    }
}

impl From<ChannelConnection> for SipConnection {
    fn from(connection: ChannelConnection) -> Self {
        SipConnection::Channel(connection)
    }
}

impl From<UdpConnection> for SipConnection {
    fn from(connection: UdpConnection) -> Self {
        SipConnection::Udp(connection)
    }
}

impl From<TcpConnection> for SipConnection {
    fn from(connection: TcpConnection) -> Self {
        SipConnection::Tcp(connection)
    }
}

impl From<TcpListenerConnection> for SipConnection {
    fn from(connection: TcpListenerConnection) -> Self {
        SipConnection::TcpListener(connection)
    }
}

impl From<TlsConnection> for SipConnection {
    fn from(connection: TlsConnection) -> Self {
        SipConnection::Tls(connection)
    }
}

#[cfg(feature = "rustls")]
impl From<TlsListenerConnection> for SipConnection {
    fn from(connection: TlsListenerConnection) -> Self {
        SipConnection::TlsListener(connection)
    }
}

impl From<WebSocketConnection> for SipConnection {
    fn from(connection: WebSocketConnection) -> Self {
        SipConnection::WebSocket(connection)
    }
}

#[cfg(feature = "websocket")]
impl From<WebSocketListenerConnection> for SipConnection {
    fn from(connection: WebSocketListenerConnection) -> Self {
        SipConnection::WebSocketListener(connection)
    }
}
