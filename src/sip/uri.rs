use crate::sip::{Error, Method, Transport};
use std::convert::TryFrom;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Scheme {
    Sip,
    Sips,
    Other(String),
}

impl Default for Scheme {
    fn default() -> Self {
        Self::Sip
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sip => write!(f, "sip"),
            Self::Sips => write!(f, "sips"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("sip") => Ok(Self::Sip),
            s if s.eq_ignore_ascii_case("sips") => Ok(Self::Sips),
            s => Ok(Self::Other(s.to_string())),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Default)]
pub struct Auth {
    pub user: String,
    pub password: Option<String>,
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.password {
            Some(pw) => write!(
                f,
                "{}:{}",
                percent_encode_user(&self.user),
                percent_encode_password(pw)
            ),
            None => write!(f, "{}", percent_encode_user(&self.user)),
        }
    }
}

fn percent_encode_component(input: &str, allowed: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || allowed.contains(byte) {
            out.push(char::from(*byte));
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", byte));
        }
    }
    out
}

fn percent_encode_user(input: &str) -> String {
    percent_encode_component(input, b"-_.!~*'()&=+$,;?/")
}

fn percent_encode_password(input: &str) -> String {
    percent_encode_component(input, b"-_.!~*'()&=+$,")
}

impl<S: Into<String>> From<S> for Auth {
    fn from(s: S) -> Self {
        let s = s.into();
        if let Some(idx) = s.find(':') {
            Auth {
                user: s[..idx].to_string(),
                password: Some(s[idx + 1..].to_string()),
            }
        } else {
            Auth {
                user: s,
                password: None,
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Host {
    Domain(Domain),
    IpAddr(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(d) => write!(f, "{}", d),
            Self::IpAddr(ip @ IpAddr::V6(_)) => write!(f, "[{}]", ip),
            Self::IpAddr(ip) => write!(f, "{}", ip),
        }
    }
}

impl From<Domain> for Host {
    fn from(d: Domain) -> Self {
        Self::Domain(d)
    }
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddr(ip)
    }
}

impl FromStr for Host {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(Host::IpAddr(ip))
        } else {
            Ok(Host::Domain(Domain::from(s)))
        }
    }
}

impl TryFrom<&str> for Host {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<Host> for IpAddr {
    type Error = Error;
    fn try_from(h: Host) -> Result<Self, Self::Error> {
        match h {
            Host::IpAddr(ip) => Ok(ip),
            Host::Domain(d) => d.0.parse::<IpAddr>().map_err(Into::into),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Domain(pub String);

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Into<String>> From<S> for Domain {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl From<Domain> for HostWithPort {
    fn from(d: Domain) -> Self {
        HostWithPort {
            host: Host::Domain(d),
            port: None,
        }
    }
}

pub use crate::sip::transport::Port;
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct HostWithPort {
    pub host: Host,
    pub port: Option<Port>,
}

impl Default for HostWithPort {
    fn default() -> Self {
        Self {
            host: Host::Domain(Domain::from("localhost")),
            port: None,
        }
    }
}

impl fmt::Display for HostWithPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.port {
            Some(port) => write!(f, "{}:{}", self.host, port),
            None => write!(f, "{}", self.host),
        }
    }
}

impl From<std::net::SocketAddr> for HostWithPort {
    fn from(sa: std::net::SocketAddr) -> Self {
        Self {
            host: Host::IpAddr(sa.ip()),
            port: Some(Port(sa.port())),
        }
    }
}

impl From<IpAddr> for HostWithPort {
    fn from(ip: IpAddr) -> Self {
        Self {
            host: Host::IpAddr(ip),
            port: None,
        }
    }
}

impl TryFrom<HostWithPort> for std::net::SocketAddr {
    type Error = Error;
    fn try_from(h: HostWithPort) -> Result<Self, Self::Error> {
        let port = h.port.map(|p| p.0).unwrap_or(5060);
        match h.host {
            Host::IpAddr(ip) => Ok(std::net::SocketAddr::new(ip, port)),
            Host::Domain(d) => {
                let ip: IpAddr = d.0.parse()?;
                Ok(std::net::SocketAddr::new(ip, port))
            }
        }
    }
}

impl TryFrom<&str> for HostWithPort {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_host_with_port(s.trim())
    }
}

impl TryFrom<String> for HostWithPort {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_host_with_port(s.trim())
    }
}

fn parse_host_with_port(s: &str) -> Result<HostWithPort, Error> {
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let ip_str = &s[1..close];
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| Error::ParseError(format!("invalid IPv6: {}", ip_str)))?;
            let port = if s.len() > close + 1 && s.as_bytes()[close + 1] == b':' {
                Some(Port(s[close + 2..].parse()?))
            } else {
                None
            };
            return Ok(HostWithPort {
                host: Host::IpAddr(ip),
                port,
            });
        }
    }

    if let Some(colon_pos) = s.rfind(':') {
        let after = &s[colon_pos + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = after
                .parse()
                .map_err(|_| Error::ParseError(format!("invalid port: {}", after)))?;
            let host_str = &s[..colon_pos];
            let host: Host = host_str.parse()?;
            return Ok(HostWithPort {
                host,
                port: Some(Port(port)),
            });
        }
    }

    let host: Host = s.parse()?;
    Ok(HostWithPort { host, port: None })
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Param {
    Transport(Transport),
    User(User),
    Method(Method),
    Ttl(Ttl),
    Maddr(Maddr),
    Lr,
    Ob,
    Rport(Option<u16>),
    Branch(Branch),
    Received(Received),
    Tag(Tag),
    Expires(Expires),
    Q(Q),
    Other(OtherParam, Option<OtherParamValue>),
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(t) => write!(f, ";transport={}", t),
            Self::User(u) => write!(f, ";user={}", u),
            Self::Method(m) => write!(f, ";method={}", m),
            Self::Ttl(t) => write!(f, ";ttl={}", t),
            Self::Maddr(m) => write!(f, ";maddr={}", m),
            Self::Lr => write!(f, ";lr"),
            Self::Ob => write!(f, ";ob"),
            Self::Rport(None) => write!(f, ";rport"),
            Self::Rport(Some(p)) => write!(f, ";rport={}", p),
            Self::Branch(b) => write!(f, ";branch={}", b),
            Self::Received(r) => write!(f, ";received={}", r),
            Self::Tag(t) => write!(f, ";tag={}", t),
            Self::Expires(e) => write!(f, ";expires={}", e),
            Self::Q(q) => write!(f, ";q={}", q),
            Self::Other(name, Some(val)) => write!(f, ";{}={}", name, val),
            Self::Other(name, None) => write!(f, ";{}", name),
        }
    }
}

impl TryFrom<(&str, Option<&str>)> for Param {
    type Error = Error;
    fn try_from((name, value): (&str, Option<&str>)) -> Result<Self, Self::Error> {
        match (name, value) {
            (n, Some(v)) if n.eq_ignore_ascii_case("transport") => Ok(Param::Transport(v.parse()?)),
            (n, Some(v)) if n.eq_ignore_ascii_case("user") => Ok(Param::User(User::new(v))),
            (n, Some(v)) if n.eq_ignore_ascii_case("method") => Ok(Param::Method(v.parse()?)),
            (n, Some(v)) if n.eq_ignore_ascii_case("ttl") => Ok(Param::Ttl(Ttl::new(v))),
            (n, Some(v)) if n.eq_ignore_ascii_case("maddr") => Ok(Param::Maddr(Maddr::new(v))),
            (n, Some(v)) if n.eq_ignore_ascii_case("branch") => Ok(Param::Branch(Branch::new(v))),
            (n, Some(v)) if n.eq_ignore_ascii_case("received") => {
                Ok(Param::Received(Received::new(v)))
            }
            (n, Some(v)) if n.eq_ignore_ascii_case("tag") => Ok(Param::Tag(Tag::new(v))),
            (n, Some(v)) if n.eq_ignore_ascii_case("expires") => {
                Ok(Param::Expires(Expires::new(v)))
            }
            (n, Some(v)) if n.eq_ignore_ascii_case("q") => Ok(Param::Q(Q::new(v))),
            (n, None) if n.eq_ignore_ascii_case("lr") => Ok(Param::Lr),
            (n, None) if n.eq_ignore_ascii_case("ob") => Ok(Param::Ob),
            (n, None) if n.eq_ignore_ascii_case("rport") => Ok(Param::Rport(None)),
            (n, Some(v)) if n.eq_ignore_ascii_case("rport") => {
                let port = v
                    .parse::<u16>()
                    .map_err(|_| Error::ParseError(format!("invalid rport: {}", v)))?;
                Ok(Param::Rport(Some(port)))
            }
            (n, v) => Ok(Param::Other(
                OtherParam::new(n),
                v.map(OtherParamValue::new),
            )),
        }
    }
}

impl FromStr for Param {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches(';').trim();
        if let Some(eq) = s.find('=') {
            let name = &s[..eq];
            let value = &s[eq + 1..];
            Param::try_from((name, Some(value)))
        } else {
            Param::try_from((s, None))
        }
    }
}

macro_rules! string_newtype {
    ($name:ident) => {
        #[derive(Debug, PartialEq, Eq, Clone, Default, Hash)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn value(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl From<$name> for String {
            fn from(s: $name) -> String {
                s.0
            }
        }
        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype!(Branch);
string_newtype!(Received);
string_newtype!(Tag);
string_newtype!(Expires);
string_newtype!(Q);
string_newtype!(User);
string_newtype!(Ttl);
string_newtype!(Maddr);
string_newtype!(OtherParam);
string_newtype!(OtherParamValue);

impl Received {
    pub fn parse(&self) -> Result<IpAddr, std::net::AddrParseError> {
        self.0.parse()
    }
}

impl From<Tag> for Param {
    fn from(t: Tag) -> Self {
        Param::Tag(t)
    }
}

impl From<Branch> for Param {
    fn from(b: Branch) -> Self {
        Param::Branch(b)
    }
}

impl From<Received> for Param {
    fn from(r: Received) -> Self {
        Param::Received(r)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default, Hash)]
pub struct Uri {
    pub scheme: Option<Scheme>,
    pub auth: Option<Auth>,
    pub host_with_port: HostWithPort,
    pub params: Vec<Param>,
    pub headers: Vec<(String, String)>,
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(f, "{}:", scheme)?;
        }
        if let Some(auth) = &self.auth {
            write!(f, "{}@", auth)?;
        }
        write!(f, "{}", self.host_with_port)?;
        for param in &self.params {
            write!(f, "{}", param)?;
        }
        if !self.headers.is_empty() {
            write!(f, "?")?;
            let parts: Vec<_> = self
                .headers
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            write!(f, "{}", parts.join("&"))?;
        }
        Ok(())
    }
}

impl Uri {
    pub fn user(&self) -> Option<&str> {
        self.auth.as_ref().map(|a| a.user.as_str())
    }
}

impl TryFrom<&str> for Uri {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_uri(s.trim())
    }
}

impl From<HostWithPort> for Uri {
    fn from(hwp: HostWithPort) -> Self {
        Uri {
            scheme: Some(Scheme::Sip),
            auth: None,
            host_with_port: hwp,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }
}

impl TryFrom<String> for Uri {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_uri(s.trim())
    }
}

impl FromStr for Uri {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_uri(s.trim())
    }
}

pub fn parse_uri(s: &str) -> Result<Uri, Error> {
    let s = s.trim();
    let s = s.trim_start_matches('<');
    let s = s.trim_end_matches('>');
    let s = s.trim();

    let (main, hdrs_str) = if let Some(q) = s.find('?') {
        (&s[..q], Some(&s[q + 1..]))
    } else {
        (s, None)
    };

    let (host_part, params_str) = split_at_first_semicolon(main);

    let (scheme, user_host) = if let Some(colon) = host_part.find(':') {
        let potential_scheme = &host_part[..colon];
        if potential_scheme.chars().all(|c| c.is_ascii_alphabetic()) {
            (
                Some(potential_scheme.parse::<Scheme>()?),
                &host_part[colon + 1..],
            )
        } else {
            (None, host_part)
        }
    } else {
        (None, host_part)
    };

    let (auth, host_str) = if let Some(at) = user_host.rfind('@') {
        (Some(Auth::from(&user_host[..at])), &user_host[at + 1..])
    } else {
        (None, user_host)
    };

    let host_with_port = parse_host_with_port(host_str)?;

    let params = parse_params(params_str.unwrap_or(""))?;

    let headers = if let Some(h) = hdrs_str {
        h.split('&')
            .filter_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                let k = parts.next()?.to_string();
                let v = parts.next().unwrap_or("").to_string();
                Some((k, v))
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Uri {
        scheme,
        auth,
        host_with_port,
        params,
        headers,
    })
}

fn split_at_first_semicolon(s: &str) -> (&str, Option<&str>) {
    if let Some(pos) = s.find(';') {
        (&s[..pos], Some(&s[pos + 1..]))
    } else {
        (s, None)
    }
}

pub fn parse_params(s: &str) -> Result<Vec<Param>, Error> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    let mut params = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let param = part.parse::<Param>()?;
        params.push(param);
    }
    Ok(params)
}

pub type UriWithParams = Uri;
pub type UriWithParamsList = Vec<Uri>;

pub trait ParamsExt {
    fn params(&self) -> &[Param];
    fn params_mut(&mut self) -> &mut Vec<Param>;

    fn tag(&self) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Tag(t) = p {
                Some(t.value())
            } else {
                None
            }
        })
    }
    fn branch(&self) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Branch(b) = p {
                Some(b.value())
            } else {
                None
            }
        })
    }
    fn transport(&self) -> Option<&Transport> {
        self.params().iter().find_map(|p| {
            if let Param::Transport(t) = p {
                Some(t)
            } else {
                None
            }
        })
    }
    fn received(&self) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Received(r) = p {
                Some(r.value())
            } else {
                None
            }
        })
    }
    fn rport(&self) -> Option<Option<u16>> {
        self.params().iter().find_map(|p| {
            if let Param::Rport(r) = p {
                Some(*r)
            } else {
                None
            }
        })
    }
    fn has_lr(&self) -> bool {
        self.params().iter().any(|p| matches!(p, Param::Lr))
    }
    fn expires(&self) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Expires(e) = p {
                Some(e.value())
            } else {
                None
            }
        })
    }
    fn q(&self) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Q(q) = p {
                Some(q.value())
            } else {
                None
            }
        })
    }
    fn other_param(&self, name: &str) -> Option<&str> {
        self.params().iter().find_map(|p| {
            if let Param::Other(n, v) = p {
                if n.value().eq_ignore_ascii_case(name) {
                    return Some(v.as_ref().map(|v| v.value()).unwrap_or(""));
                }
            }
            None
        })
    }

    fn set_tag(&mut self, tag: impl Into<String>) {
        let new = Param::Tag(Tag::new(tag));
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| matches!(p, Param::Tag(_))) {
            *p = new;
        } else {
            params.push(new);
        }
    }
    fn set_branch(&mut self, branch: impl Into<String>) {
        let new = Param::Branch(Branch::new(branch));
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| matches!(p, Param::Branch(_))) {
            *p = new;
        } else {
            params.push(new);
        }
    }
    fn set_transport(&mut self, t: Transport) {
        let new = Param::Transport(t);
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| matches!(p, Param::Transport(_))) {
            *p = new;
        } else {
            params.push(new);
        }
    }
    fn set_rport(&mut self, port: Option<u16>) {
        let new = Param::Rport(port);
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| matches!(p, Param::Rport(_))) {
            *p = new;
        } else {
            params.push(new);
        }
    }
    fn set_expires(&mut self, value: impl Into<String>) {
        let new = Param::Expires(Expires::new(value));
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| matches!(p, Param::Expires(_))) {
            *p = new;
        } else {
            params.push(new);
        }
    }
    fn set_other_param(&mut self, name: &str, value: Option<&str>) {
        let new = Param::Other(OtherParam::new(name), value.map(OtherParamValue::new));
        let params = self.params_mut();
        if let Some(p) = params.iter_mut().find(|p| {
            if let Param::Other(n, _) = p {
                n.value().eq_ignore_ascii_case(name)
            } else {
                false
            }
        }) {
            *p = new;
        } else {
            params.push(new);
        }
    }

    fn remove_tag(&mut self) {
        self.params_mut().retain(|p| !matches!(p, Param::Tag(_)));
    }
    fn remove_branch(&mut self) {
        self.params_mut().retain(|p| !matches!(p, Param::Branch(_)));
    }
    fn remove_transport(&mut self) {
        self.params_mut()
            .retain(|p| !matches!(p, Param::Transport(_)));
    }
    fn remove_rport(&mut self) {
        self.params_mut().retain(|p| !matches!(p, Param::Rport(_)));
    }
    fn remove_lr(&mut self) {
        self.params_mut().retain(|p| !matches!(p, Param::Lr));
    }
    fn remove_param(&mut self, name: &str) {
        self.params_mut().retain(|p| {
            if let Param::Other(n, _) = p {
                !n.value().eq_ignore_ascii_case(name)
            } else {
                true
            }
        });
    }

    fn pop_tag(&mut self) -> Option<String> {
        let params = self.params_mut();
        let pos = params.iter().position(|p| matches!(p, Param::Tag(_)))?;
        if let Param::Tag(t) = params.remove(pos) {
            Some(t.0)
        } else {
            None
        }
    }
    fn pop_branch(&mut self) -> Option<String> {
        let params = self.params_mut();
        let pos = params.iter().position(|p| matches!(p, Param::Branch(_)))?;
        if let Param::Branch(b) = params.remove(pos) {
            Some(b.0)
        } else {
            None
        }
    }
}

impl ParamsExt for Vec<Param> {
    fn params(&self) -> &[Param] {
        self.as_slice()
    }
    fn params_mut(&mut self) -> &mut Vec<Param> {
        self
    }
}

impl ParamsExt for Uri {
    fn params(&self) -> &[Param] {
        &self.params
    }
    fn params_mut(&mut self) -> &mut Vec<Param> {
        &mut self.params
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_uri, Host, Param, Scheme};

    #[test]
    fn uri_param_value_keeps_colons_and_following_params() {
        let uri = parse_uri(
            "sip:82.202.218.130;lr=on;ftag=d4nwJ0jF;du=sip:95.143.188.49:5060;did=893.d6d1",
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            "sip:82.202.218.130;lr=on;ftag=d4nwJ0jF;du=sip:95.143.188.49:5060;did=893.d6d1"
        );
        assert!(uri.params.iter().any(|param| matches!(param, Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("du") && value.value() == "sip:95.143.188.49:5060")));
        assert!(uri.params.iter().any(|param| matches!(param, Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("did") && value.value() == "893.d6d1")));
    }

    #[test]
    fn uri_preserves_username_with_period() {
        let uri = parse_uri("sip:alice.smith@restsend.com").unwrap();
        assert_eq!(uri.auth.unwrap().user, "alice.smith");
    }

    #[test]
    fn uri_display_percent_encodes_user_and_password() {
        let uri = parse_uri("sip:al ice:pa:ss@restsend.com").unwrap();
        assert_eq!(uri.to_string(), "sip:al%20ice:pa%3Ass@restsend.com");
    }

    #[test]
    fn user_param_is_parsed_as_uri_param() {
        let uri = parse_uri("sip:alice@restsend.com;user=phone").unwrap();
        assert!(matches!(uri.params.first(), Some(Param::User(value)) if value.value() == "phone"));
    }

    #[test]
    fn uri_rport_without_value() {
        let uri = parse_uri("sip:alice@restsend.com;rport").unwrap();
        assert!(matches!(uri.params.first(), Some(Param::Rport(None))));
        assert_eq!(uri.to_string(), "sip:alice@restsend.com;rport");
    }

    #[test]
    fn uri_rport_with_value() {
        let uri = parse_uri("sip:alice@restsend.com;rport=51372").unwrap();
        assert!(matches!(
            uri.params.first(),
            Some(Param::Rport(Some(51372)))
        ));
        assert_eq!(uri.to_string(), "sip:alice@restsend.com;rport=51372");
    }

    #[test]
    fn uri_rport_with_other_params() {
        let uri = parse_uri("sip:alice@ua.restsend.com;transport=tcp;rport").unwrap();
        assert!(uri.params.iter().any(|p| matches!(p, Param::Rport(None))));
        assert!(uri.params.iter().any(|p| matches!(p, Param::Transport(_))));
    }

    #[test]
    fn uri_branch_param() {
        let uri = parse_uri("sip:proxy.restsend.com;branch=z9hG4bK776asdhds").unwrap();
        assert!(
            matches!(uri.params.first(), Some(Param::Branch(b)) if b.value() == "z9hG4bK776asdhds")
        );
    }

    #[test]
    fn uri_lr_flag_param() {
        let uri = parse_uri("sip:proxy.restsend.com;lr").unwrap();
        assert!(matches!(uri.params.first(), Some(Param::Lr)));
        assert_eq!(uri.to_string(), "sip:proxy.restsend.com;lr");
    }

    #[test]
    fn uri_sips_scheme() {
        let uri = parse_uri("sips:alice@restsend.com").unwrap();
        assert_eq!(uri.scheme, Some(Scheme::Sips));
        assert_eq!(uri.to_string(), "sips:alice@restsend.com");
    }

    #[test]
    fn uri_ipv4_host() {
        let uri = parse_uri("sip:bob@192.0.2.4").unwrap();
        assert!(matches!(uri.host_with_port.host, Host::IpAddr(_)));
        assert_eq!(uri.to_string(), "sip:bob@192.0.2.4");
    }

    #[test]
    fn uri_ipv4_host_with_port() {
        let uri = parse_uri("sip:alice@192.0.2.1:5060").unwrap();
        assert!(uri.host_with_port.port.is_some());
        assert_eq!(uri.to_string(), "sip:alice@192.0.2.1:5060");
    }

    #[test]
    fn uri_ipv6_host() {
        let uri = parse_uri("sip:alice@[2001:db8::1]").unwrap();
        assert!(matches!(uri.host_with_port.host, Host::IpAddr(_)));
        assert_eq!(uri.to_string(), "sip:alice@[2001:db8::1]");
    }

    #[test]
    fn uri_ipv6_host_with_port() {
        let uri = parse_uri("sip:alice@[2001:db8::1]:5060").unwrap();
        assert!(uri.host_with_port.port.is_some());
        assert_eq!(uri.to_string(), "sip:alice@[2001:db8::1]:5060");
    }

    #[test]
    fn uri_transport_tcp_param() {
        use crate::sip::Transport;
        let uri = parse_uri("sip:alice@restsend.com;transport=tcp").unwrap();
        assert!(matches!(
            uri.params.first(),
            Some(Param::Transport(Transport::Tcp))
        ));
        assert_eq!(uri.to_string(), "sip:alice@restsend.com;transport=TCP");
    }

    #[test]
    fn uri_transport_tls_param() {
        use crate::sip::Transport;
        let uri = parse_uri("sip:alice@restsend.com;transport=tls").unwrap();
        assert!(matches!(
            uri.params.first(),
            Some(Param::Transport(Transport::Tls))
        ));
    }

    #[test]
    fn uri_roundtrip_complex() {
        let s = "sip:alice@restsend.com;transport=tcp;tag=1928301774";
        let uri = parse_uri(s).unwrap();
        assert_eq!(
            uri.to_string(),
            "sip:alice@restsend.com;transport=TCP;tag=1928301774"
        );
    }

    #[test]
    fn uri_host_only_no_user() {
        let uri = parse_uri("sip:restsend.com").unwrap();
        assert!(uri.auth.is_none());
        assert_eq!(uri.host_with_port.host, Host::Domain("restsend.com".into()));
    }

    #[test]
    fn uri_with_headers() {
        let uri = parse_uri("sip:alice@restsend.com?subject=project&priority=urgent").unwrap();
        assert_eq!(uri.headers.len(), 2);
        assert_eq!(uri.headers[0], ("subject".into(), "project".into()));
        assert_eq!(uri.headers[1], ("priority".into(), "urgent".into()));
    }

    #[test]
    fn uri_maddr_param() {
        let uri = parse_uri("sip:alice@restsend.com;maddr=239.255.255.1").unwrap();
        assert!(
            matches!(uri.params.first(), Some(Param::Maddr(m)) if m.value() == "239.255.255.1")
        );
    }

    #[test]
    fn uri_ttl_param() {
        let uri = parse_uri("sip:alice@restsend.com;ttl=15").unwrap();
        assert!(matches!(uri.params.first(), Some(Param::Ttl(t)) if t.value() == "15"));
    }

    #[test]
    fn uri_tag_param() {
        let uri = parse_uri("sip:alice@restsend.com;tag=1928301774").unwrap();
        assert!(matches!(uri.params.first(), Some(Param::Tag(t)) if t.value() == "1928301774"));
    }

    #[test]
    fn uri_multiple_params() {
        let uri = parse_uri("sip:alice@restsend.com;transport=tcp;tag=1928301774;lr").unwrap();
        assert_eq!(uri.params.len(), 3);
    }

    #[test]
    fn uri_password_auth() {
        let uri = parse_uri("sip:alice:secret@restsend.com").unwrap();
        let auth = uri.auth.unwrap();
        assert_eq!(auth.user, "alice");
        assert_eq!(auth.password, Some("secret".into()));
    }

    #[test]
    fn uri_anonymous() {
        let uri = parse_uri("sip:anonymous@anonymous.invalid").unwrap();
        assert_eq!(uri.auth.unwrap().user, "anonymous");
    }
}
