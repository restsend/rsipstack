/// 传输协议配置模块
///
/// 支持的 SIP 传输协议：UDP、TCP、WebSocket 和 TLS
use std::str::FromStr;

/// SIP 传输协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// UDP 传输协议（默认）
    #[default]
    Udp,
    /// TCP 传输协议
    Tcp,
    /// WebSocket 传输协议
    Ws,
    /// WebSocket Secure (TLS) 传输协议
    Wss,
}

impl Protocol {
    /// 返回协议的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
            Protocol::Ws => "ws",
            Protocol::Wss => "wss",
        }
    }

    /// 返回协议的默认端口
    #[cfg(test)]
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp => 5060,
            Protocol::Tcp => 5060,
            Protocol::Ws => 80,
            Protocol::Wss => 443,
        }
    }

    /// 判断是否为安全协议
    #[cfg(test)]
    pub fn is_secure(&self) -> bool {
        matches!(self, Protocol::Wss)
    }

    /// 判断是否为 WebSocket 协议
    #[cfg(test)]
    pub fn is_websocket(&self) -> bool {
        matches!(self, Protocol::Ws | Protocol::Wss)
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            "ws" | "websocket" => Ok(Protocol::Ws),
            "wss" | "websocket-secure" => Ok(Protocol::Wss),
            _ => Err(format!(
                "无效的协议类型 '{}', 支持的协议: udp, tcp, ws, wss",
                s
            )),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str().to_uppercase())
    }
}

/// 从 rsip::Transport 转换为 Protocol
impl From<rsip::transport::Transport> for Protocol {
    fn from(transport: rsip::transport::Transport) -> Self {
        match transport {
            rsip::transport::Transport::Udp => Protocol::Udp,
            rsip::transport::Transport::Tcp => Protocol::Tcp,
            rsip::transport::Transport::Ws => Protocol::Ws,
            rsip::transport::Transport::Wss => Protocol::Wss,
            rsip::transport::Transport::Tls => Protocol::Tcp, // TLS over TCP
            rsip::transport::Transport::Sctp => Protocol::Udp, // Fallback to UDP
            rsip::transport::Transport::TlsSctp => Protocol::Tcp, // Fallback to TCP
        }
    }
}

/// 从 Protocol 转换为 rsip::Transport
impl From<Protocol> for rsip::transport::Transport {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Udp => rsip::transport::Transport::Udp,
            Protocol::Tcp => rsip::transport::Transport::Tcp,
            Protocol::Ws => rsip::transport::Transport::Ws,
            Protocol::Wss => rsip::transport::Transport::Wss,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert_eq!("UDP".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("ws".parse::<Protocol>().unwrap(), Protocol::Ws);
        assert_eq!("websocket".parse::<Protocol>().unwrap(), Protocol::Ws);
        assert_eq!("wss".parse::<Protocol>().unwrap(), Protocol::Wss);
        assert!("http".parse::<Protocol>().is_err());
    }

    #[test]
    fn test_protocol_default_port() {
        assert_eq!(Protocol::Udp.default_port(), 5060);
        assert_eq!(Protocol::Tcp.default_port(), 5060);
        assert_eq!(Protocol::Ws.default_port(), 80);
        assert_eq!(Protocol::Wss.default_port(), 443);
    }

    #[test]
    fn test_protocol_is_secure() {
        assert!(!Protocol::Udp.is_secure());
        assert!(!Protocol::Tcp.is_secure());
        assert!(!Protocol::Ws.is_secure());
        assert!(Protocol::Wss.is_secure());
    }

    #[test]
    fn test_protocol_is_websocket() {
        assert!(!Protocol::Udp.is_websocket());
        assert!(!Protocol::Tcp.is_websocket());
        assert!(Protocol::Ws.is_websocket());
        assert!(Protocol::Wss.is_websocket());
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Ws.to_string(), "WS");
        assert_eq!(Protocol::Wss.to_string(), "WSS");
    }
}
