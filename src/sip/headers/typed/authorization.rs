use super::parse_helpers::write_quoted_escaped;
use super::tokenizers::AuthTokenizer;
use crate::prelude::*;
use crate::sip::headers::auth::{Algorithm, AuthQop, Scheme};
use crate::sip::{Error, Header, Uri};

fn find_param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) {
            Some(value.as_str())
        } else {
            None
        }
    })
}

fn find_qop(params: &[(String, String)]) -> Result<Option<AuthQop>, Error> {
    Ok(match find_param(params, "qop") {
        Some(q) if q.eq_ignore_ascii_case("auth") => Some(AuthQop::Auth {
            cnonce: find_param(params, "cnonce")
                .ok_or_else(|| Error::InvalidParam("missing cnonce".into()))?
                .into(),
            nc: u32::from_str_radix(
                find_param(params, "nc").ok_or_else(|| Error::InvalidParam("missing nc".into()))?,
                16,
            )
            .map_err(|_| Error::ParseError("nc parse error".into()))?,
        }),
        Some(q) if q.eq_ignore_ascii_case("auth-int") => Some(AuthQop::AuthInt {
            cnonce: find_param(params, "cnonce")
                .ok_or_else(|| Error::InvalidParam("missing cnonce".into()))?
                .into(),
            nc: u32::from_str_radix(
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
pub struct Authorization {
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

impl Authorization {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let tok = AuthTokenizer::parse(s)?;
        let params = &tok.params;
        Ok(Authorization {
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

impl core::fmt::Display for Authorization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} username=", self.scheme)?;
        write_quoted_escaped(f, &self.username)?;
        write!(f, ", realm=")?;
        write_quoted_escaped(f, &self.realm)?;
        write!(f, ", nonce=")?;
        write_quoted_escaped(f, &self.nonce)?;
        write!(f, ", uri=\"{}\", response=\"{}\"", self.uri, self.response)?;
        if let Some(a) = &self.algorithm {
            write!(f, ", algorithm={}", a)?;
        }
        if let Some(o) = &self.opaque {
            write!(f, ", opaque=")?;
            write_quoted_escaped(f, o)?;
        }
        if let Some(q) = &self.qop {
            write!(f, ", {}", q)?;
        }
        Ok(())
    }
}

impl core::convert::From<Authorization> for String {
    fn from(a: Authorization) -> String {
        a.to_string()
    }
}

impl core::convert::From<Authorization> for Header {
    fn from(a: Authorization) -> Header {
        Header::Authorization(crate::sip::headers::untyped::Authorization::new(
            a.to_string(),
        ))
    }
}

impl<'a> super::TypedHeader<'a> for Authorization {}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_header() -> &'static str {
        r#"Digest username="alice", realm="example.com", nonce="n1", uri="sip:alice@example.com", response="abc", algorithm=MD5"#
    }

    #[test]
    fn authorization_round_trips() {
        let raw = raw_header();
        let auth = Authorization::parse(raw).unwrap();
        assert_eq!(auth.to_string(), raw);
        assert_eq!(Authorization::parse(&auth.to_string()).unwrap(), auth);
    }

    #[test]
    fn authorization_with_quoted_pairs_round_trips() {
        // issue #258: quoted-pairs used to break parsing at the closing quote.
        let raw = r#"Digest username="a\"b", realm="x\"", nonce="n", uri="sip:u@h", response="r""#;
        let auth = Authorization::parse(raw).unwrap();
        assert_eq!(auth.username, "a\"b");
        assert_eq!(auth.realm, "x\"");
        assert_eq!(auth.to_string(), raw);
    }

    #[test]
    fn authorization_rejects_control_characters_and_stray_quotes() {
        assert!(Authorization::parse(
            "Digest username=a\u{7}, realm=x, nonce=n, uri=sip:u@h, response=r"
        )
        .is_err());
        assert!(Authorization::parse(
            r#"Digest username=a"b, realm=x, nonce=n, uri=sip:u@h, response=r"#
        )
        .is_err());
    }
}
