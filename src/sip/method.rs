use crate::prelude::*;
use crate::sip::Error;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Method {
    Ack,
    Bye,
    Cancel,
    Info,
    Invite,
    Message,
    Notify,
    Options,
    PRack,
    Publish,
    Refer,
    Register,
    Subscribe,
    Update,
    Other(String),
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_char)
}

impl Method {
    pub fn all() -> Vec<Method> {
        vec![
            Self::Ack,
            Self::Bye,
            Self::Cancel,
            Self::Info,
            Self::Invite,
            Self::Message,
            Self::Notify,
            Self::Options,
            Self::PRack,
            Self::Publish,
            Self::Refer,
            Self::Register,
            Self::Subscribe,
            Self::Update,
        ]
    }
}

impl core::fmt::Display for Method {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Info => "INFO",
            Self::Invite => "INVITE",
            Self::Message => "MESSAGE",
            Self::Notify => "NOTIFY",
            Self::Options => "OPTIONS",
            Self::PRack => "PRACK",
            Self::Publish => "PUBLISH",
            Self::Refer => "REFER",
            Self::Register => "REGISTER",
            Self::Subscribe => "SUBSCRIBE",
            Self::Update => "UPDATE",
            Self::Other(s) => s.as_str(),
        };
        write!(f, "{}", s)
    }
}

impl core::str::FromStr for Method {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            m if m.eq_ignore_ascii_case("ACK") => Ok(Self::Ack),
            m if m.eq_ignore_ascii_case("BYE") => Ok(Self::Bye),
            m if m.eq_ignore_ascii_case("CANCEL") => Ok(Self::Cancel),
            m if m.eq_ignore_ascii_case("INFO") => Ok(Self::Info),
            m if m.eq_ignore_ascii_case("INVITE") => Ok(Self::Invite),
            m if m.eq_ignore_ascii_case("MESSAGE") => Ok(Self::Message),
            m if m.eq_ignore_ascii_case("NOTIFY") => Ok(Self::Notify),
            m if m.eq_ignore_ascii_case("OPTIONS") => Ok(Self::Options),
            m if m.eq_ignore_ascii_case("PRACK") => Ok(Self::PRack),
            m if m.eq_ignore_ascii_case("PUBLISH") => Ok(Self::Publish),
            m if m.eq_ignore_ascii_case("REFER") => Ok(Self::Refer),
            m if m.eq_ignore_ascii_case("REGISTER") => Ok(Self::Register),
            m if m.eq_ignore_ascii_case("SUBSCRIBE") => Ok(Self::Subscribe),
            m if m.eq_ignore_ascii_case("UPDATE") => Ok(Self::Update),
            m if is_token(m) => Ok(Self::Other(m.to_string())),
            m => Err(Error::ParseError(format!("invalid method: {}", m))),
        }
    }
}

impl core::convert::TryFrom<&str> for Method {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl core::convert::TryFrom<&[u8]> for Method {
    type Error = Error;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        core::str::from_utf8(b)?.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::Method;

    #[test]
    fn parses_extension_token_method_and_rejects_non_token() {
        let m: Method = "!interesting-Method0123456789_*+`.%indeed'~"
            .parse()
            .unwrap();
        assert_eq!(
            m,
            Method::Other("!interesting-Method0123456789_*+`.%indeed'~".to_string())
        );
        assert_eq!(m.to_string(), "!interesting-Method0123456789_*+`.%indeed'~");
        assert!("".parse::<Method>().is_err());
        assert!("INV ITE".parse::<Method>().is_err());
        assert!("INV@ITE".parse::<Method>().is_err());
        assert!("INV\"ITE".parse::<Method>().is_err());
    }
}
