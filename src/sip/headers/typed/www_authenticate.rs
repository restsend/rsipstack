use crate::sip::{Error, Header};
use crate::sip::headers::auth::{Algorithm, Qop, Scheme};
use super::tokenizers::AuthTokenizer;

fn find_param<'a>(params: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    params.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) { Some(*value) } else { None }
    })
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct WwwAuthenticate {
    pub scheme: Scheme,
    pub realm: String,
    pub domain: Option<String>,
    pub nonce: String,
    pub opaque: Option<String>,
    pub stale: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub qop: Option<Qop>,
    pub charset: Option<String>,
}

impl WwwAuthenticate {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let tok = AuthTokenizer::parse(s)?;
        let params = &tok.params;
        Ok(WwwAuthenticate {
            scheme: Scheme::try_from(tok.scheme)?,
            realm: find_param(params, "realm")
                .ok_or_else(|| Error::InvalidParam("missing realm".into()))?.into(),
            domain: find_param(params, "domain").map(Into::into),
            nonce: find_param(params, "nonce")
                .ok_or_else(|| Error::InvalidParam("missing nonce".into()))?.into(),
            opaque: find_param(params, "opaque").map(Into::into),
            stale: find_param(params, "stale").map(Into::into),
            algorithm: find_param(params, "algorithm")
                .map(Algorithm::try_from).transpose()?,
            qop: find_param(params, "qop")
                .map(Qop::try_from).transpose()?,
            charset: find_param(params, "charset").map(Into::into),
        })
    }
}

impl std::fmt::Display for WwwAuthenticate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} realm=\"{}\"", self.scheme, self.realm)?;
        if let Some(d) = &self.domain { write!(f, ", domain=\"{}\"", d)?; }
        write!(f, ", nonce=\"{}\"", self.nonce)?;
        if let Some(o) = &self.opaque { write!(f, ", opaque=\"{}\"", o)?; }
        if let Some(s) = &self.stale { write!(f, ", stale={}", s)?; }
        if let Some(a) = &self.algorithm { write!(f, ", algorithm={}", a)?; }
        if let Some(q) = &self.qop { write!(f, ", qop=\"{}\"", q)?; }
        if let Some(c) = &self.charset { write!(f, ", charset={}", c)?; }
        Ok(())
    }
}

impl std::convert::From<WwwAuthenticate> for String {
    fn from(w: WwwAuthenticate) -> String { w.to_string() }
}

impl std::convert::From<WwwAuthenticate> for Header {
    fn from(w: WwwAuthenticate) -> Header {
        Header::WwwAuthenticate(crate::sip::headers::untyped::WwwAuthenticate::new(w.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for WwwAuthenticate {}
