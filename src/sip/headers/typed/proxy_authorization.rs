use super::tokenizers::AuthTokenizer;
use crate::sip::headers::auth::{Algorithm, AuthQop, Scheme};
use crate::sip::{Error, Header, Uri};

fn find_param<'a>(params: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    params.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) {
            Some(*value)
        } else {
            None
        }
    })
}

fn find_qop(params: &[(&str, &str)]) -> Result<Option<AuthQop>, Error> {
    Ok(match find_param(params, "qop") {
        Some(q) if q.eq_ignore_ascii_case("auth") => Some(AuthQop::Auth {
            cnonce: find_param(params, "cnonce")
                .ok_or_else(|| Error::InvalidParam("missing cnonce".into()))?
                .into(),
            nc: u8::from_str_radix(
                find_param(params, "nc").ok_or_else(|| Error::InvalidParam("missing nc".into()))?,
                16,
            )
            .map_err(|_| Error::ParseError("nc parse error".into()))?,
        }),
        Some(q) if q.eq_ignore_ascii_case("auth-int") => Some(AuthQop::AuthInt {
            cnonce: find_param(params, "cnonce")
                .ok_or_else(|| Error::InvalidParam("missing cnonce".into()))?
                .into(),
            nc: u8::from_str_radix(
                find_param(params, "nc").ok_or_else(|| Error::InvalidParam("missing nc".into()))?,
                16,
            )
            .map_err(|_| Error::ParseError("nc parse error".into()))?,
        }),
        Some(q) => return Err(Error::InvalidParam(format!("unknown qop: {}", q))),
        None => None,
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProxyAuthorization {
    pub scheme: Scheme,
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: Uri,
    pub response: String,
    pub algorithm: Option<Algorithm>,
    pub opaque: Option<String>,
    pub qop: Option<AuthQop>,
}

impl ProxyAuthorization {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let tok = AuthTokenizer::parse(s)?;
        let params = &tok.params;
        Ok(ProxyAuthorization {
            scheme: Scheme::try_from(tok.scheme)?,
            username: find_param(params, "username")
                .ok_or_else(|| Error::InvalidParam("missing username".into()))?
                .into(),
            realm: find_param(params, "realm")
                .ok_or_else(|| Error::InvalidParam("missing realm".into()))?
                .into(),
            nonce: find_param(params, "nonce")
                .ok_or_else(|| Error::InvalidParam("missing nonce".into()))?
                .into(),
            uri: find_param(params, "uri")
                .ok_or_else(|| Error::InvalidParam("missing uri".into()))
                .and_then(crate::sip::uri::parse_uri)?,
            response: find_param(params, "response")
                .ok_or_else(|| Error::InvalidParam("missing response".into()))?
                .into(),
            algorithm: find_param(params, "algorithm")
                .map(Algorithm::try_from)
                .transpose()?,
            opaque: find_param(params, "opaque").map(Into::into),
            qop: find_qop(params)?,
        })
    }
}

impl std::fmt::Display for ProxyAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
            self.scheme, self.username, self.realm, self.nonce, self.uri, self.response
        )?;
        if let Some(a) = &self.algorithm {
            write!(f, ", algorithm={}", a)?;
        }
        if let Some(o) = &self.opaque {
            write!(f, ", opaque=\"{}\"", o)?;
        }
        if let Some(q) = &self.qop {
            write!(f, ", {}", q)?;
        }
        Ok(())
    }
}

impl std::convert::From<ProxyAuthorization> for String {
    fn from(p: ProxyAuthorization) -> String {
        p.to_string()
    }
}

impl std::convert::From<ProxyAuthorization> for Header {
    fn from(p: ProxyAuthorization) -> Header {
        Header::ProxyAuthorization(crate::sip::headers::untyped::ProxyAuthorization::new(
            p.to_string(),
        ))
    }
}

impl<'a> super::TypedHeader<'a> for ProxyAuthorization {}
