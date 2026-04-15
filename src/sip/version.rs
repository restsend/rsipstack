use crate::sip::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub enum Version {
    #[default]
    V2,
    V(u8, u8),
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V2 => write!(f, "SIP/2.0"),
            Self::V(maj, min) => write!(f, "SIP/{}.{}", maj, min),
        }
    }
}

impl std::str::FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let inner = if let Some(rest) = s.strip_prefix("SIP/") {
            rest
        } else {
            return Err(Error::ParseError(format!("invalid SIP version: {}", s)));
        };
        match inner {
            "2.0" => Ok(Self::V2),
            other => {
                let mut parts = other.splitn(2, '.');
                let maj = parts
                    .next()
                    .ok_or_else(|| Error::ParseError(format!("invalid version: {}", s)))?
                    .parse::<u8>()?;
                let min = parts
                    .next()
                    .map(|x| x.parse::<u8>())
                    .transpose()?
                    .unwrap_or(0);
                Ok(Self::V(maj, min))
            }
        }
    }
}

impl std::convert::TryFrom<&str> for Version {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
