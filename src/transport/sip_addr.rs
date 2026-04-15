use crate::sip::uri::ParamsExt;
use crate::sip::{Host, HostWithPort, Param, Scheme, Transport, Uri};
use crate::Result;
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
/// use rsipstack::sip::{HostWithPort, Transport};
/// use std::net::SocketAddr;
///
/// // Create from socket address
/// let socket_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
/// let sip_addr = SipAddr::from(socket_addr);
///
/// // Create with specific transport
/// let sip_addr = SipAddr::new(
///     Transport::Tcp,
///     HostWithPort::try_from("example.com:5060").unwrap()
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
/// * `rsipstack::sip::Uri` (SIP URI format)
/// * `rsipstack::sip::HostWithPort` (host/port only)
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct SipAddr {
    pub r#type: Option<Transport>,
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
            Host::Domain(ref domain) => domain.hash(state),
            Host::IpAddr(ref ip_addr) => ip_addr.hash(state),
        }
        if let Some(port) = self.addr.port {
            port.value().hash(state)
        }
    }
}

impl SipAddr {
    pub fn new(transport: Transport, addr: HostWithPort) -> Self {
        SipAddr {
            r#type: Some(transport),
            addr,
        }
    }

    pub fn get_socketaddr(&self) -> Result<SocketAddr> {
        match &self.addr.host {
            Host::Domain(domain) => Err(crate::Error::Error(format!(
                "Cannot convert domain {} to SocketAddr",
                domain
            ))),
            Host::IpAddr(ip_addr) => {
                let port = self.addr.port.map_or(5060, |p| p.value().to_owned());
                Ok(SocketAddr::new(ip_addr.to_owned(), port))
            }
        }
    }
}

impl From<SipAddr> for HostWithPort {
    fn from(val: SipAddr) -> Self {
        val.addr
    }
}

impl From<SipAddr> for Uri {
    fn from(val: SipAddr) -> Self {
        Self::from(&val)
    }
}

impl From<&SipAddr> for Uri {
    fn from(addr: &SipAddr) -> Self {
        let params = match addr.r#type {
            Some(Transport::Tcp) => vec![Param::Transport(Transport::Tcp)],
            Some(Transport::Tls) => vec![Param::Transport(Transport::Tls)],
            Some(Transport::Ws) => vec![Param::Transport(Transport::Ws)],
            Some(Transport::Wss) => vec![Param::Transport(Transport::Wss)],
            Some(Transport::TlsSctp) => vec![Param::Transport(Transport::TlsSctp)],
            Some(Transport::Sctp) => vec![Param::Transport(Transport::Sctp)],
            _ => vec![],
        };
        let scheme = match addr.r#type {
            Some(Transport::Wss) | Some(Transport::Tls) | Some(Transport::TlsSctp) => Scheme::Sips,
            _ => Scheme::Sip,
        };
        Uri {
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

impl From<HostWithPort> for SipAddr {
    fn from(host_with_port: HostWithPort) -> Self {
        SipAddr {
            r#type: None,
            addr: host_with_port,
        }
    }
}

impl TryFrom<&Uri> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: &Uri) -> Result<Self> {
        let transport = uri.transport().cloned();
        Ok(SipAddr {
            r#type: transport,
            addr: uri.host_with_port.clone(),
        })
    }
}

impl TryFrom<Uri> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: Uri) -> Result<Self> {
        let transport = uri.transport().cloned();
        Ok(SipAddr {
            r#type: transport,
            addr: uri.host_with_port,
        })
    }
}

impl<'a> TryFrom<std::borrow::Cow<'a, Uri>> for SipAddr {
    type Error = crate::Error;

    fn try_from(uri: std::borrow::Cow<'a, Uri>) -> Result<Self> {
        match uri {
            std::borrow::Cow::Owned(uri) => uri.try_into(),
            std::borrow::Cow::Borrowed(uri) => uri.try_into(),
        }
    }
}
