use crate::sip::uri::{Branch, HostWithPort, Received};
use crate::sip::{uri::Param, Error, Header, Transport, Uri, Version};
use std::net::IpAddr;
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Via {
    pub version: Version,
    pub transport: Transport,
    pub uri: Uri,
    pub params: Vec<Param>,
}

impl Via {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        let mut slashes = s.splitn(3, '/');
        let _proto = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing protocol".into()))?;
        let _ver = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing version".into()))?;
        let rest = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing transport+host".into()))?
            .trim();

        let (transport_str, addr_and_params) = rest
            .split_once(|c: char| c.is_whitespace())
            .ok_or_else(|| Error::ParseError("Via: missing host after transport".into()))?;

        let transport = Transport::try_from(transport_str.trim())?;
        let addr_and_params = addr_and_params.trim();

        let (addr_str, params_str) = match addr_and_params.split_once(';') {
            Some((a, p)) => (a.trim(), Some(p)),
            None => (addr_and_params, None),
        };

        let host_with_port = HostWithPort::try_from(addr_str)?;
        let uri = crate::sip::uri::Uri {
            scheme: Some(crate::sip::uri::Scheme::Sip),
            auth: None,
            host_with_port,
            params: vec![],
            headers: vec![],
        };

        let params = if let Some(p) = params_str {
            crate::sip::uri::parse_params(p)
        } else {
            Ok(vec![])
        }?;

        Ok(Via {
            version: Version::V2,
            transport,
            uri,
            params,
        })
    }

    pub fn branch(&self) -> Option<&Branch> {
        self.params.iter().find_map(|p| match p {
            Param::Branch(b) => Some(b),
            _ => None,
        })
    }

    pub fn received(&self) -> Option<Result<IpAddr, Error>> {
        self.params.iter().find_map(|p| match p {
            Param::Received(r) => Some(r.parse().map_err(Into::into)),
            _ => None,
        })
    }

    pub fn sent_by(&self) -> &HostWithPort {
        &self.uri.host_with_port
    }

    pub fn with_branch(mut self, branch: Branch) -> Self {
        self.params.retain(|p| !matches!(p, Param::Branch(_)));
        self.params.push(Param::Branch(branch));
        self
    }

    pub fn with_received(mut self, received: Received) -> Self {
        self.params.retain(|p| !matches!(p, Param::Received(_)));
        self.params.push(Param::Received(received));
        self
    }

    pub fn rport(&self) -> Option<Option<u16>> {
        self.params.iter().find_map(|p| match p {
            Param::Rport(r) => Some(*r),
            _ => None,
        })
    }

    pub fn with_rport(mut self, port: Option<u16>) -> Self {
        self.params.retain(|p| !matches!(p, Param::Rport(_)));
        self.params.push(Param::Rport(port));
        self
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SIP/2.0/{} {}", self.transport, self.uri.host_with_port)?;
        for p in &self.params {
            write!(f, "{}", p)?;
        }
        Ok(())
    }
}

impl std::convert::From<Via> for String {
    fn from(v: Via) -> String {
        v.to_string()
    }
}

impl std::convert::From<Via> for Header {
    fn from(v: Via) -> Header {
        Header::Via(crate::sip::headers::untyped::Via::new(v.to_string()))
    }
}

impl std::convert::From<Via> for crate::sip::headers::untyped::Via {
    fn from(v: Via) -> crate::sip::headers::untyped::Via {
        crate::sip::headers::untyped::Via::new(v.to_string())
    }
}

impl<'a> super::TypedHeader<'a> for Via {}

#[cfg(test)]
mod tests {
    use super::Via;
    use crate::sip::Transport;

    #[test]
    fn via_basic_parse() {
        let v = Via::parse("SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest").unwrap();
        assert_eq!(v.transport, Transport::Udp);
        assert_eq!(v.uri.host_with_port.to_string(), "ua.restsend.com");
        assert_eq!(v.branch().map(|b| b.value()), Some("z9hG4bKtest"));
        assert_eq!(v.rport(), None);
    }

    #[test]
    fn via_rport_no_value() {
        let v = Via::parse("SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest;rport").unwrap();
        assert_eq!(v.rport(), Some(None));
        assert!(v.to_string().contains(";rport"));
        assert!(!v.to_string().contains(";rport="));
    }

    #[test]
    fn via_rport_with_value() {
        let v = Via::parse(
            "SIP/2.0/UDP ua.restsend.com:5060;branch=z9hG4bKtest;rport=51372;received=192.0.2.1",
        )
        .unwrap();
        assert_eq!(v.rport(), Some(Some(51372)));
        assert!(v.to_string().contains(";rport=51372"));
    }

    #[test]
    fn via_received() {
        let v =
            Via::parse("SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest;received=10.0.0.5").unwrap();
        let rcvd = v.received().unwrap().unwrap();
        assert_eq!(rcvd.to_string(), "10.0.0.5");
    }

    #[test]
    fn via_tcp_transport() {
        let v = Via::parse("SIP/2.0/TCP proxy.restsend.com:5060;branch=z9hG4bKabc").unwrap();
        assert_eq!(v.transport, Transport::Tcp);
        assert_eq!(v.uri.host_with_port.to_string(), "proxy.restsend.com:5060");
    }

    #[test]
    fn via_with_rport_builder() {
        let v = Via::parse("SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest").unwrap();
        let v = v.with_rport(None);
        assert_eq!(v.rport(), Some(None));
        let s = v.to_string();
        assert!(s.contains(";rport"));
        assert!(!s.contains(";rport="));

        let v2 = Via::parse("SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest").unwrap();
        let v2 = v2.with_rport(Some(5070));
        assert_eq!(v2.rport(), Some(Some(5070)));
        assert!(v2.to_string().contains(";rport=5070"));
    }
}
