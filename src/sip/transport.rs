use crate::sip::{Error, Scheme};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[derive(Default)]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    Tls,
    TlsSctp,
    Sctp,
    Ws,
    Wss,
}

impl Transport {
    pub fn default_port(&self) -> Port {
        match self {
            Self::Udp => Port(5060),
            Self::Tcp => Port(5060),
            Self::Sctp => Port(5060),
            Self::TlsSctp => Port(5061),
            Self::Tls => Port(5061),
            Self::Ws => Port(80),
            Self::Wss => Port(443),
        }
    }

    pub fn protocol(&self) -> Self {
        match self {
            Self::Tls => Self::Tcp,
            Self::TlsSctp => Self::Sctp,
            Self::Wss => Self::Ws,
            _ => *self,
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Tls | Self::TlsSctp | Self::Wss)
    }

    pub fn sip_scheme(&self) -> Scheme {
        if self.is_secure() {
            Scheme::Sips
        } else {
            Scheme::Sip
        }
    }
}


impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Tls => write!(f, "TLS"),
            Self::Sctp => write!(f, "SCTP"),
            Self::TlsSctp => write!(f, "TLS-SCTP"),
            Self::Ws => write!(f, "WS"),
            Self::Wss => write!(f, "WSS"),
        }
    }
}

impl std::str::FromStr for Transport {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("UDP") => Ok(Self::Udp),
            s if s.eq_ignore_ascii_case("TCP") => Ok(Self::Tcp),
            s if s.eq_ignore_ascii_case("TLS") => Ok(Self::Tls),
            s if s.eq_ignore_ascii_case("SCTP") => Ok(Self::Sctp),
            s if s.eq_ignore_ascii_case("TLS-SCTP") => Ok(Self::TlsSctp),
            s if s.eq_ignore_ascii_case("WS") => Ok(Self::Ws),
            s if s.eq_ignore_ascii_case("WSS") => Ok(Self::Wss),
            s => Err(Error::ParseError(format!("unknown transport: {}", s))),
        }
    }
}

impl std::convert::TryFrom<&str> for Transport {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::convert::TryFrom<&[u8]> for Transport {
    type Error = Error;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.parse()
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Hash)]
pub struct Port(pub u16);

impl Port {
    pub fn value(&self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for Port {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

impl std::str::FromStr for Port {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Port(s.trim().parse()?))
    }
}

impl std::convert::TryFrom<&str> for Port {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
