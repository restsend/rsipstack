use crate::Result;
use rsip::{host_with_port, HostWithPort, Transport};
use std::{fmt, hash::Hash, net::SocketAddr};

/// SIP Address
///
/// `SipAddr` represents a SIP network address that combines a host/port
/// with an optional transport protocol. It provides a unified way to
/// handle SIP addressing across different transport types.
///
/// # Fields
///
/// * `r#type` - Optional transport protocol (UDP, TCP, TLS, WS, WSS)
/// * `addr` - Host and port information
///
/// # Transport Types
///
/// * `UDP` - User Datagram Protocol (unreliable)
/// * `TCP` - Transmission Control Protocol (reliable)
/// * `TLS` - Transport Layer Security over TCP (reliable, encrypted)
/// * `WS` - WebSocket (reliable)
/// * `WSS` - WebSocket Secure (reliable, encrypted)
///
/// # Examples
///
/// ```rust
/// use rsipstack::transport::SipAddr;
/// use rsip::transport::Transport;
/// use std::net::SocketAddr;
///
/// // Create from socket address
/// let socket_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
/// let sip_addr = SipAddr::from(socket_addr);
///
/// // Create with specific transport
/// let sip_addr = SipAddr::new(
///     Transport::Tcp,
///     rsip::HostWithPort::try_from("example.com:5060").unwrap()
/// );
///
/// // Convert to socket address (for IP addresses)
/// if let Ok(socket_addr) = sip_addr.get_socketaddr() {
///     println!("Socket address: {}", socket_addr);
/// }
/// ```
///
/// # Usage in SIP
///
/// SipAddr is used throughout the stack for:
/// * Via header processing
/// * Contact header handling
/// * Route and Record-Route processing
/// * Transport layer addressing
/// * Connection management
///
/// # Conversion
///
/// SipAddr can be converted to/from:
/// * `SocketAddr` (for IP addresses only)
/// * `rsip::Uri` (SIP URI format)
/// * `rsip::HostWithPort` (host/port only)
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct SipAddr {
    pub r#type: Option<rsip::transport::Transport>,
    pub addr: HostWithPort,
}

impl fmt::Display for SipAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipAddr {
                r#type: Some(r#type),
                addr,
            } => write!(f, "{} {}", r#type, addr),
            SipAddr { r#type: None, addr } => write!(f, "{}", addr),
        }
    }
}

impl Hash for SipAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.r#type.hash(state);
        match self.addr.host {
            host_with_port::Host::Domain(ref domain) => domain.hash(state),
            host_with_port::Host::IpAddr(ref ip_addr) => ip_addr.hash(state),
        }
        self.addr.port.map(|port| port.value().hash(state));
    }
}

impl SipAddr {
    pub fn new(transport: rsip::transport::Transport, addr: HostWithPort) -> Self {
        SipAddr {
            r#type: Some(transport),
            addr,
        }
    }

    pub fn get_socketaddr(&self) -> Result<SocketAddr> {
        match &self.addr.host {
            host_with_port::Host::Domain(domain) => Err(crate::Error::Error(format!(
                "Cannot convert domain {} to SocketAddr",
                domain
            ))),
            host_with_port::Host::IpAddr(ip_addr) => {
                let port = self.addr.port.map_or(5060, |p| p.value().to_owned());
                Ok(SocketAddr::new(ip_addr.to_owned(), port))
            }
        }
    }
}

impl From<SipAddr> for rsip::HostWithPort {
    fn from(val: SipAddr) -> Self {
        val.addr
    }
}

impl From<SipAddr> for rsip::Uri {
    fn from(val: SipAddr) -> Self {
        Self::from(&val)
    }
}

impl From<&SipAddr> for rsip::Uri {
    fn from(addr: &SipAddr) -> Self {
        let params = match addr.r#type {
            Some(Transport::Tcp) => vec![rsip::Param::Transport(Transport::Tcp)],
            Some(Transport::Tls) => vec![rsip::Param::Transport(Transport::Tls)],
            Some(Transport::Ws) => vec![rsip::Param::Transport(Transport::Ws)],
            Some(Transport::Wss) => vec![rsip::Param::Transport(Transport::Wss)],
            Some(Transport::TlsSctp) => vec![rsip::Param::Transport(Transport::TlsSctp)],
            Some(Transport::Sctp) => vec![rsip::Param::Transport(Transport::Sctp)],
            _ => vec![],
        };
        let scheme = match addr.r#type {
            Some(rsip::transport::Transport::Wss)
            | Some(rsip::transport::Transport::Tls)
            | Some(rsip::transport::Transport::TlsSctp) => rsip::Scheme::Sips,
            _ => rsip::Scheme::Sip,
        };
        rsip::Uri {
            scheme: Some(scheme),
            host_with_port: addr.addr.clone(),
            params,
            ..Default::default()
        }
    }
}

impl From<SocketAddr> for SipAddr {
    fn from(addr: SocketAddr) -> Self {
        let host_with_port = HostWithPort {
            host: addr.ip().into(),
            port: Some(addr.port().into()),
        };
        SipAddr {
            r#type: None,
            addr: host_with_port,
        }
    }
}

impl From<rsip::host_with_port::HostWithPort> for SipAddr {
    fn from(host_with_port: rsip::host_with_port::HostWithPort) -> Self {
        SipAddr {
            r#type: None,
            addr: host_with_port,
        }
    }
}

impl TryFrom<&rsip::Uri> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: &rsip::Uri) -> Result<Self> {
        let transport = uri.transport().cloned();
        Ok(SipAddr {
            r#type: transport,
            addr: uri.host_with_port.clone(),
        })
    }
}

impl TryFrom<rsip::Uri> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: rsip::Uri) -> Result<Self> {
        let transport = uri.transport().cloned();
        Ok(SipAddr {
            r#type: transport,
            addr: uri.host_with_port,
        })
    }
}

impl<'a> TryFrom<std::borrow::Cow<'a, rsip::Uri>> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: std::borrow::Cow<'a, rsip::Uri>) -> Result<Self> {
        match uri {
            std::borrow::Cow::Owned(uri) => uri.try_into(),
            std::borrow::Cow::Borrowed(uri) => uri.try_into(),
        }
    }
}
