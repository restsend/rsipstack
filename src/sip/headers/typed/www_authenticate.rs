use super::parse_helpers::write_quoted_escaped;
use super::tokenizers::AuthTokenizer;
use crate::prelude::*;
use crate::sip::headers::auth::{Algorithm, Qop, Scheme};
use crate::sip::{Error, Header};

fn find_param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) {
            Some(value.as_str())
        } else {
            None
        }
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
                .ok_or_else(|| Error::InvalidParam("missing realm".into()))?
                .into(),
            domain: find_param(params, "domain").map(Into::into),
            nonce: find_param(params, "nonce")
                .ok_or_else(|| Error::InvalidParam("missing nonce".into()))?
                .into(),
            opaque: find_param(params, "opaque").map(Into::into),
            stale: find_param(params, "stale").map(Into::into),
            algorithm: find_param(params, "algorithm")
                .map(Algorithm::try_from)
                .transpose()?,
            qop: find_param(params, "qop")
                .map(Qop::parse_challenge)
                .transpose()?,
            charset: find_param(params, "charset").map(Into::into),
        })
    }
}

impl core::fmt::Display for WwwAuthenticate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} realm=", self.scheme)?;
        write_quoted_escaped(f, &self.realm)?;
        if let Some(d) = &self.domain {
            write!(f, ", domain=")?;
            write_quoted_escaped(f, d)?;
        }
        write!(f, ", nonce=")?;
        write_quoted_escaped(f, &self.nonce)?;
        if let Some(o) = &self.opaque {
            write!(f, ", opaque=")?;
            write_quoted_escaped(f, o)?;
        }
        if let Some(s) = &self.stale {
            write!(f, ", stale={}", s)?;
        }
        if let Some(a) = &self.algorithm {
            write!(f, ", algorithm={}", a)?;
        }
        if let Some(q) = &self.qop {
            write!(f, ", qop=\"{}\"", q)?;
        }
        if let Some(c) = &self.charset {
            write!(f, ", charset={}", c)?;
        }
        Ok(())
    }
}

impl core::convert::From<WwwAuthenticate> for String {
    fn from(w: WwwAuthenticate) -> String {
        w.to_string()
    }
}

impl core::convert::From<WwwAuthenticate> for Header {
    fn from(w: WwwAuthenticate) -> Header {
        Header::WwwAuthenticate(crate::sip::headers::untyped::WwwAuthenticate::new(
            w.to_string(),
        ))
    }
}

impl<'a> super::TypedHeader<'a> for WwwAuthenticate {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_with_quoted_pairs_round_trips() {
        // issue #258: a quoted-pair inside the realm used to be rejected.
        let raw = r#"Digest realm="a\"b", nonce="n1""#;
        let challenge = WwwAuthenticate::parse(raw).unwrap();
        assert_eq!(challenge.realm, "a\"b");
        assert_eq!(challenge.nonce, "n1");
        assert_eq!(challenge.to_string(), raw);
        assert!(WwwAuthenticate::parse(&challenge.to_string()).is_ok());
    }

    #[test]
    fn challenge_with_stray_quote_in_token_value_is_rejected() {
        assert!(WwwAuthenticate::parse(r#"Digest realm=a"b, nonce="n1""#).is_err());
    }

    #[test]
    fn plain_challenge_is_unchanged() {
        let raw = r#"Digest realm="example.com", nonce="MTM3", stale=FALSE, algorithm=MD5"#;
        let challenge = WwwAuthenticate::parse(raw).unwrap();
        assert_eq!(challenge.to_string(), raw);
    }

    #[test]
    fn control_character_in_challenge_is_rejected() {
        assert!(WwwAuthenticate::parse("Digest realm=a\u{7}b, nonce=n").is_err());
    }
}
