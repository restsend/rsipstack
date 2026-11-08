use crate::prelude::*;
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum Algorithm {
    Md5,
    Md5Sess,
    #[default]
    Sha256,
    Sha256Sess,
    Sha512,
    Sha512Sess,
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Md5 => write!(f, "MD5"),
            Self::Md5Sess => write!(f, "MD5-sess"),
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha256Sess => write!(f, "SHA256-sess"),
            Self::Sha512 => write!(f, "SHA512"),
            Self::Sha512Sess => write!(f, "SHA512-sess"),
        }
    }
}

impl core::str::FromStr for Algorithm {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Algorithm::try_from(s)
    }
}

impl core::convert::TryFrom<&str> for Algorithm {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("md5") => Ok(Self::Md5),
            s if s.eq_ignore_ascii_case("md5-sess") => Ok(Self::Md5Sess),
            // RFC 7616 §5 registers the SHA family with hyphens ("SHA-256"),
            // while draft-era deployments commonly emit "SHA256"; accept both.
            s if s.eq_ignore_ascii_case("sha-256") || s.eq_ignore_ascii_case("sha256") => {
                Ok(Self::Sha256)
            }
            s if s.eq_ignore_ascii_case("sha-256-sess")
                || s.eq_ignore_ascii_case("sha256-sess") =>
            {
                Ok(Self::Sha256Sess)
            }
            s if s.eq_ignore_ascii_case("sha-512") || s.eq_ignore_ascii_case("sha512") => {
                Ok(Self::Sha512)
            }
            s if s.eq_ignore_ascii_case("sha-512-sess")
                || s.eq_ignore_ascii_case("sha512-sess") =>
            {
                Ok(Self::Sha512Sess)
            }
            s => Err(crate::sip::Error::ParseError(format!(
                "invalid Algorithm: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Qop {
    Auth,
    AuthInt,
}

impl core::fmt::Display for Qop {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::AuthInt => write!(f, "auth-int"),
        }
    }
}

impl core::str::FromStr for Qop {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Qop::try_from(s)
    }
}

impl core::convert::TryFrom<&str> for Qop {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("auth") => Ok(Self::Auth),
            s if s.eq_ignore_ascii_case("auth-int") => Ok(Self::AuthInt),
            s => Err(crate::sip::Error::ParseError(format!("invalid Qop: {}", s))),
        }
    }
}

impl Qop {
    /// Parse a challenge's `qop-options` value (RFC 2617 §3.2.2): a quoted,
    /// comma-separated list of the protections the server supports, e.g.
    /// `qop="auth,auth-int"`. The client picks one; we prefer `auth` because
    /// it is universally supported, while `auth-int` additionally requires
    /// entity-body hashing that most SIP flows cannot afford.
    pub fn parse_challenge(s: &str) -> Result<Self, crate::sip::Error> {
        let mut auth = None;
        let mut auth_int = None;
        for option in s.split(',') {
            match option.trim() {
                o if o.eq_ignore_ascii_case("auth") => auth = Some(Self::Auth),
                o if o.eq_ignore_ascii_case("auth-int") => auth_int = Some(Self::AuthInt),
                _ => {}
            }
        }
        auth.or(auth_int)
            .ok_or_else(|| crate::sip::Error::ParseError(format!("unsupported Qop options: {}", s)))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthQop {
    Auth { cnonce: String, nc: u32 },
    AuthInt { cnonce: String, nc: u32 },
}

impl core::fmt::Display for AuthQop {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `nc` is an 8-digit lowercase hex counter (RFC 2617 §3.2.2); u32 covers
        // the full 8-hex-digit range without the wrap a u8 would impose at FF.
        match self {
            Self::Auth { cnonce, nc } => {
                write!(f, "qop=auth, nc={:08x}, cnonce=\"{}\"", nc, cnonce)
            }
            Self::AuthInt { cnonce, nc } => {
                write!(f, "qop=auth-int, nc={:08x}, cnonce=\"{}\"", nc, cnonce)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum Scheme {
    #[default]
    Digest,
    Other(String),
}

impl core::fmt::Display for Scheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Digest => write!(f, "Digest"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl core::str::FromStr for Scheme {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Scheme::try_from(s)
    }
}

impl core::convert::TryFrom<&str> for Scheme {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("digest") => Ok(Self::Digest),
            s => Ok(Self::Other(s.to_string())),
        }
    }
}

impl core::convert::TryFrom<String> for Scheme {
    type Error = crate::sip::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Scheme::try_from(s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, AuthQop, Qop};
    use crate::sip::typed::{
        Authorization, ProxyAuthenticate, ProxyAuthorization, WwwAuthenticate,
    };

    #[test]
    fn authorization_qop_is_unquoted() {
        for qop in ["auth", "auth-int"] {
            // Accept both forms on input, but always emit the RFC 3261 token form.
            for input_qop in [qop.to_string(), format!("\"{}\"", qop)] {
                let input = format!(
                    r#"Digest username="alice", realm="ims.test", nonce="nonce", uri="sip:ims.test", response="0123456789abcdef0123456789abcdef", algorithm=MD5, qop={}, nc=00000001, cnonce="client-nonce""#,
                    input_qop
                );
                let auth = Authorization::parse(&input).unwrap();
                let proxy = ProxyAuthorization::parse(&input).unwrap();
                for output in [auth.to_string(), proxy.to_string()] {
                    assert!(
                        output.contains(&format!(
                            ", qop={}, nc=00000001, cnonce=\"client-nonce\"",
                            qop
                        )),
                        "{output}"
                    );
                    assert!(!output.contains("qop=\""), "{output}");
                }
                assert_eq!(Authorization::parse(&auth.to_string()).unwrap(), auth);
                assert_eq!(
                    ProxyAuthorization::parse(&proxy.to_string()).unwrap(),
                    proxy
                );
            }
        }
    }

    #[test]
    fn challenge_qop_remains_quoted() {
        for qop in ["auth", "auth-int"] {
            let input = format!(
                r#"Digest realm="ims.test", nonce="nonce", stale=true, algorithm=MD5, qop="{}""#,
                qop
            );
            let www = WwwAuthenticate::parse(&input).unwrap();
            let proxy = ProxyAuthenticate::parse(&input).unwrap();
            for output in [www.to_string(), proxy.to_string()] {
                assert!(output.contains(&format!(", qop=\"{}\"", qop)), "{output}");
                assert!(output.contains("stale=true"), "{output}");
            }
            assert_eq!(WwwAuthenticate::parse(&www.to_string()).unwrap(), www);
            assert_eq!(ProxyAuthenticate::parse(&proxy.to_string()).unwrap(), proxy);
        }
    }

    #[test]
    fn challenge_qop_list_picks_supported_option() {
        // RFC 2617 §3.2.2 allows a challenge to offer several qop options
        // (a quoted list); RFC 2617 §3.2.1 lets the client pick one.
        for list in [r#""auth,auth-int""#, r#""auth-int,auth""#] {
            let input = format!(r#"Digest realm="ims.test", nonce="nonce", qop={}"#, list);
            let www = WwwAuthenticate::parse(&input).unwrap();
            let proxy = ProxyAuthenticate::parse(&input).unwrap();
            assert_eq!(www.qop, Some(Qop::Auth), "{list}");
            assert_eq!(proxy.qop, Some(Qop::Auth), "{list}");
        }
        // A single unquoted token stays accepted too.
        let single = r#"Digest realm="ims.test", nonce="nonce", qop=auth-int"#;
        assert_eq!(
            WwwAuthenticate::parse(single).unwrap().qop,
            Some(Qop::AuthInt)
        );
        // Unsupported-only options still fail, as with a single unknown value.
        assert!(WwwAuthenticate::parse(r#"Digest realm="r", nonce="n", qop="digest""#).is_err());
    }

    #[test]
    fn algorithm_accepts_hyphenated_rfc7616_names() {
        for (raw, expected) in [
            ("SHA-256", Algorithm::Sha256),
            ("sha-256-sess", Algorithm::Sha256Sess),
            ("SHA-512", Algorithm::Sha512),
            ("sha-512-sess", Algorithm::Sha512Sess),
        ] {
            assert_eq!(Algorithm::try_from(raw).unwrap(), expected, "{raw}");
        }
        // Draft-era spellings keep parsing.
        assert_eq!(Algorithm::try_from("SHA256").unwrap(), Algorithm::Sha256);
        assert_eq!(Algorithm::try_from("MD5-sess").unwrap(), Algorithm::Md5Sess);
    }

    #[test]
    fn nc_parses_and_displays_as_eight_hex_digits() {
        // 8 hex digits span u32; nc=00000100 (256) exceeded a u8.
        let make = |nc: &str| {
            format!(
                r#"Digest username="alice", realm="ims.test", nonce="nonce", uri="sip:ims.test", response="0123456789abcdef0123456789abcdef", algorithm=MD5, qop=auth, nc={nc}, cnonce="client-nonce""#
            )
        };
        for nc in ["00000010", "00000100", "ffffffff"] {
            let auth = Authorization::parse(&make(nc)).unwrap();
            let expected = u32::from_str_radix(nc, 16).unwrap();
            assert_eq!(
                auth.qop,
                Some(AuthQop::Auth {
                    cnonce: "client-nonce".into(),
                    nc: expected
                }),
                "{nc}"
            );
            // `nc` is a hex counter (RFC 2617 §3.2.2): the emitted form must
            // round-trip instead of re-encoding the value in decimal.
            let output = auth.to_string();
            assert!(output.contains(&format!("nc={:08x}", expected)), "{output}");
            assert_eq!(Authorization::parse(&output).unwrap(), auth);
        }
    }

    #[test]
    fn response_qop_without_cnonce_or_nc_is_rejected() {
        let make = |extra: &str| {
            format!(
                r#"Digest username="alice", realm="ims.test", nonce="nonce", uri="sip:ims.test", response="0123456789abcdef0123456789abcdef", algorithm=MD5, qop=auth{}"#,
                extra
            )
        };
        assert!(
            Authorization::parse(&make(", nc=00000001")).is_err(),
            "missing cnonce"
        );
        assert!(
            Authorization::parse(&make(", cnonce=\"client-nonce\"")).is_err(),
            "missing nc"
        );
        assert!(Authorization::parse(&make(", nc=00000001, cnonce=\"client-nonce\"")).is_ok());
        // Unknown qop values are rejected rather than silently dropped.
        let unknown = r#"Digest username="alice", realm="ims.test", nonce="nonce", uri="sip:ims.test", response="0123456789abcdef0123456789abcdef", algorithm=MD5, qop=digest, nc=00000001, cnonce="client-nonce""#;
        assert!(Authorization::parse(unknown).is_err());
    }
}
