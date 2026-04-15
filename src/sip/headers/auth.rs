#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[derive(Default)]
pub enum Algorithm {
    Md5,
    Md5Sess,
    #[default]
    Sha256,
    Sha256Sess,
    Sha512,
    Sha512Sess,
}


impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::str::FromStr for Algorithm {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Algorithm::try_from(s)
    }
}

impl std::convert::TryFrom<&str> for Algorithm {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("md5") => Ok(Self::Md5),
            s if s.eq_ignore_ascii_case("md5-sess") => Ok(Self::Md5Sess),
            s if s.eq_ignore_ascii_case("sha256") => Ok(Self::Sha256),
            s if s.eq_ignore_ascii_case("sha256-sess") => Ok(Self::Sha256Sess),
            s if s.eq_ignore_ascii_case("sha512") => Ok(Self::Sha512),
            s if s.eq_ignore_ascii_case("sha512-sess") => Ok(Self::Sha512Sess),
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

impl std::fmt::Display for Qop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::AuthInt => write!(f, "auth-int"),
        }
    }
}

impl std::str::FromStr for Qop {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Qop::try_from(s)
    }
}

impl std::convert::TryFrom<&str> for Qop {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("auth") => Ok(Self::Auth),
            s if s.eq_ignore_ascii_case("auth-int") => Ok(Self::AuthInt),
            s => Err(crate::sip::Error::ParseError(format!("invalid Qop: {}", s))),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthQop {
    Auth { cnonce: String, nc: u8 },
    AuthInt { cnonce: String, nc: u8 },
}

impl std::fmt::Display for AuthQop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth { cnonce, nc } => {
                write!(f, "qop=\"auth\", nc={:08}, cnonce=\"{}\"", nc, cnonce)
            }
            Self::AuthInt { cnonce, nc } => {
                write!(f, "qop=\"auth-int\", nc={:08}, cnonce=\"{}\"", nc, cnonce)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[derive(Default)]
pub enum Scheme {
    #[default]
    Digest,
    Other(String),
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest => write!(f, "Digest"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = crate::sip::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Scheme::try_from(s)
    }
}

impl std::convert::TryFrom<&str> for Scheme {
    type Error = crate::sip::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.trim() {
            s if s.eq_ignore_ascii_case("digest") => Ok(Self::Digest),
            s => Ok(Self::Other(s.to_string())),
        }
    }
}

impl std::convert::TryFrom<String> for Scheme {
    type Error = crate::sip::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Scheme::try_from(s.as_str())
    }
}

