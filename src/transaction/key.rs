use crate::prelude::*;
use crate::sip::{
    prelude::{HeadersExt, ToTypedHeader},
    typed::Via,
    HostWithPort, Method, Param, Request, Response, Scheme, Uri,
};
use crate::{Error, Result};
use alloc::boxed::Box;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Copy)]
pub enum TransactionRole {
    Client,
    Server,
}
impl core::fmt::Display for TransactionRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Client => "c",
            Self::Server => "s",
        })
    }
}

/// An unambiguous transaction identity. Its display form is for diagnostics,
/// not a wire format. Server and client matching follow different RFC rules.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionKey(Key);

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum Key {
    Client {
        branch: String,
        method: String,
    },
    Server {
        branch: String,
        sent_by: (String, u16),
        method: String,
    },
    // Keep uncommon compatibility data out of every modern key/timer.
    Legacy(Box<LegacyKey>),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
struct LegacyKey {
    call_id: String,
    cseq: u32,
    from_tag: Option<String>,
    to_tag: Option<String>,
    method: String,
    uri: RequestUri,
    via: ViaKey,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
struct ViaKey {
    protocol: String,
    sent_by: (String, u16),
    params: Vec<(String, Option<String>)>,
}

/// SIP URI comparison is not an equivalence relation for extension parameters
/// (RFC 3261 §19.1.4). Keep structural Eq/Ord for map storage and use `matches`
/// for the legacy lookup, rather than violating Hash/Eq/Ord contracts.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum RequestUri {
    Sip {
        scheme: String,
        user: Option<String>,
        password: Option<String>,
        host: String,
        port: Option<u16>,
        params: Vec<(String, Option<String>)>,
    },
    Other(String),
}

impl core::fmt::Debug for TransactionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Key::Client { branch, method } => f
                .debug_struct("Client")
                .field("branch", branch)
                .field("method", method)
                .finish(),
            Key::Server {
                branch,
                sent_by,
                method,
            } => f
                .debug_struct("Server")
                .field("branch", branch)
                .field("sent_by", sent_by)
                .field("method", method)
                .finish(),
            // Request-URI can contain a password; keep it out of transaction
            // diagnostics even though legacy matching must retain it.
            Key::Legacy(k) => f
                .debug_struct("LegacyServer")
                .field("call_id", &k.call_id)
                .field("cseq", &k.cseq)
                .field("from_tag", &k.from_tag)
                .field("to_tag", &k.to_tag)
                .field("method", &k.method)
                .field("via", &k.via)
                .finish_non_exhaustive(),
        }
    }
}
impl core::fmt::Display for TransactionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl TransactionKey {
    pub fn from_request(req: &Request, role: TransactionRole) -> Result<Self> {
        let via = req.top_via_header()?.typed()?;
        let method = req.method.to_string();
        if role == TransactionRole::Client {
            return Self::client(&via, method);
        }
        let method = if req.method == Method::Ack {
            "INVITE".into()
        } else {
            method
        };
        if let Some(branch) = via.branch().filter(|b| b.value().starts_with("z9hG4bK")) {
            return Ok(Self(Key::Server {
                branch: branch.to_string(),
                sent_by: sent_by(&via),
                method,
            }));
        }
        // RFC 3261 §17.2.3: both missing and non-cookie branches use the
        // RFC 2543 compatibility rules. Tags can be absent on legacy requests.
        Ok(Self(Key::Legacy(Box::new(LegacyKey {
            call_id: req.call_id_header()?.value().to_string(),
            cseq: req.cseq_header()?.seq()?,
            from_tag: req.from_header()?.tag()?.map(|t| t.to_string()),
            to_tag: req.to_header()?.tag()?.map(|t| t.to_string()),
            method,
            uri: RequestUri::new(&req.uri),
            via: ViaKey::new(&via),
        }))))
    }

    pub fn from_response(resp: &Response, role: TransactionRole) -> Result<Self> {
        let via = resp.top_via_header()?.typed()?;
        let method = resp.cseq_header()?.method()?.to_string();
        if role == TransactionRole::Client {
            // RFC 3261 §17.1.3: neither sent-by nor Call-ID/CSeq number/tags
            // are part of client transaction matching. CANCEL stays separate.
            return Self::client(&via, method);
        }
        if let Some(branch) = via.branch().filter(|b| b.value().starts_with("z9hG4bK")) {
            return Ok(Self(Key::Server {
                branch: branch.to_string(),
                sent_by: sent_by(&via),
                method,
            }));
        }
        // A response has no Request-URI, so a legacy server key cannot be
        // recovered from it (RFC 3261 §17.2.3, final paragraph).
        Err(Error::Error(
            "legacy server transaction requires the original request".into(),
        ))
    }

    fn client(via: &Via, method: String) -> Result<Self> {
        let branch = via.branch().ok_or_else(|| {
            Error::Error("client transaction requires a Via branch (RFC 3261 §8.1.1.7)".into())
        })?;
        Ok(Self(Key::Client {
            branch: branch.to_string(),
            method,
        }))
    }

    pub(crate) fn is_legacy(&self) -> bool {
        matches!(self.0, Key::Legacy(_))
    }

    /// Restrict exceptional (legacy/CANCEL/ACK) lookup to a contiguous map
    /// range. Do not scan unrelated calls or all modern transactions.
    pub(crate) fn candidates<'a, V>(
        &'a self,
        map: &'a alloc::collections::BTreeMap<Self, V>,
    ) -> impl Iterator<Item = (&'a Self, &'a V)> + 'a {
        let mut start = self.clone();
        match &mut start.0 {
            Key::Client { method, .. } | Key::Server { method, .. } => method.clear(),
            Key::Legacy(k) => {
                k.to_tag = None;
                k.method.clear();
            }
        }
        map.range(start..)
            .take_while(move |(candidate, _)| match (&self.0, &candidate.0) {
                (Key::Client { branch: a, .. }, Key::Client { branch: b, .. }) => a == b,
                (
                    Key::Server {
                        branch: a,
                        sent_by: sa,
                        ..
                    },
                    Key::Server {
                        branch: b,
                        sent_by: sb,
                        ..
                    },
                ) => a == b && sa == sb,
                (Key::Legacy(a), Key::Legacy(b)) => {
                    a.call_id == b.call_id && a.cseq == b.cseq && a.from_tag == b.from_tag
                }
                _ => false,
            })
    }

    pub(crate) fn matches_request(&self, candidate: &Self) -> bool {
        match (&self.0, &candidate.0) {
            (Key::Legacy(a), Key::Legacy(b)) => a.matches(b, false, false),
            _ => self == candidate,
        }
    }

    /// Match a CANCEL to the original transaction, independently of the
    /// CANCEL's own identity (RFC 3261 §9.2).
    pub(crate) fn cancels(&self, candidate: &Self) -> bool {
        match (&self.0, &candidate.0) {
            (
                Key::Server {
                    branch: a,
                    sent_by: sa,
                    method: ma,
                },
                Key::Server {
                    branch: b,
                    sent_by: sb,
                    method: mb,
                },
            ) => ma == "CANCEL" && mb != "CANCEL" && mb != "ACK" && a == b && sa == sb,
            (Key::Legacy(a), Key::Legacy(b)) => {
                a.method == "CANCEL"
                    && b.method != "CANCEL"
                    && b.method != "ACK"
                    && a.matches(b, true, false)
            }
            _ => false,
        }
    }

    /// Legacy non-2xx ACK: compare the To tag with the response, all other
    /// fields with the original INVITE (RFC 3261 §17.2.3).
    pub(crate) fn matches_legacy_ack(
        &self,
        candidate: &Self,
        response_tag: &Option<String>,
    ) -> bool {
        match (&self.0, &candidate.0) {
            (Key::Legacy(a), Key::Legacy(b)) => {
                a.method == "INVITE"
                    && b.method == "INVITE"
                    && &a.to_tag == response_tag
                    && a.matches(b, false, true)
            }
            _ => false,
        }
    }
}

impl LegacyKey {
    fn matches(&self, other: &Self, ignore_method: bool, ignore_to: bool) -> bool {
        self.call_id == other.call_id
            && self.cseq == other.cseq
            && self.from_tag == other.from_tag
            && (ignore_to || self.to_tag == other.to_tag)
            && (ignore_method || self.method == other.method)
            && self.via == other.via
            && self.uri.matches(&other.uri)
    }
}

fn host(host: &crate::sip::Host) -> String {
    host.to_string().to_ascii_lowercase()
}
fn sent_by(via: &Via) -> (String, u16) {
    let HostWithPort { host: h, port } = via.sent_by();
    (
        host(h),
        port.unwrap_or_else(|| via.transport.default_port()).into(),
    )
}

impl ViaKey {
    fn new(via: &Via) -> Self {
        let mut params: Vec<_> = via
            .params
            .iter()
            .map(|p| {
                let raw = p.to_string();
                let (name, value) = raw[1..]
                    .split_once('=')
                    .map_or((&raw[1..], None), |(n, v)| (n, Some(v)));
                let value = value.map(|v| {
                    if matches!(p, Param::Branch(_) | Param::Tag(_)) || v.starts_with('"') {
                        v.to_string()
                    } else {
                        v.to_ascii_lowercase()
                    }
                });
                (name.to_ascii_lowercase(), value)
            })
            .collect();
        params.sort();
        Self {
            protocol: format!("{}/{}", via.version, via.transport),
            sent_by: sent_by(via),
            params,
        }
    }
}

impl RequestUri {
    fn new(uri: &Uri) -> Self {
        if !matches!(uri.scheme, Some(Scheme::Sip | Scheme::Sips)) {
            return Self::Other(uri.to_string());
        }
        let mut params: Vec<_> = uri
            .params
            .iter()
            .filter(|p| !matches!(p, Param::Method(_)))
            .map(|p| {
                let raw = p.to_string();
                let (name, value) = raw[1..]
                    .split_once('=')
                    .map_or((&raw[1..], None), |(n, v)| (n, Some(v)));
                (
                    unescape(name).to_ascii_lowercase(),
                    value.map(|v| unescape(v).to_ascii_lowercase()),
                )
            })
            .collect();
        params.sort();
        // Headers and the method parameter are disallowed in Request-URI and
        // SHOULD be ignored if present (§19.1.1, Table 1).
        Self::Sip {
            scheme: uri.scheme.as_ref().unwrap().to_string(),
            user: uri.auth.as_ref().map(|a| unescape(&a.user)),
            password: uri
                .auth
                .as_ref()
                .and_then(|a| a.password.as_ref().map(|p| unescape(p))),
            host: host(&uri.host_with_port.host),
            port: uri.host_with_port.port.map(Into::into),
            params,
        }
    }
    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Sip {
                    scheme: a,
                    user: u,
                    password: p,
                    host: h,
                    port: po,
                    params: ps,
                },
                Self::Sip {
                    scheme: b,
                    user: v,
                    password: q,
                    host: i,
                    port: qo,
                    params: qs,
                },
            ) => {
                a == b
                    && u == v
                    && p == q
                    && h == i
                    && po == qo
                    && params_match(ps, qs)
                    && params_match(qs, ps)
            }
            _ => self == other,
        }
    }
}
fn params_match(a: &[(String, Option<String>)], b: &[(String, Option<String>)]) -> bool {
    a.iter()
        .all(|(name, value)| match b.iter().find(|(n, _)| n == name) {
            Some((_, other)) => value == other,
            None => !matches!(name.as_str(), "transport" | "user" | "ttl" | "maddr"),
        })
}

/// Normalize escaped unreserved ASCII characters; never decode a reserved
/// delimiter into a different URI component (RFC 3261 §19.1.4).
fn unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                let c = (a * 16 + b) as u8;
                if c.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&c) {
                    out.push(c);
                } else {
                    out.extend_from_slice(&[
                        b'%',
                        bytes[i + 1].to_ascii_uppercase(),
                        bytes[i + 2].to_ascii_uppercase(),
                    ]);
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Only ASCII escapes were replaced; existing UTF-8 remains intact.
    String::from_utf8(out).expect("URI normalization preserves UTF-8")
}
