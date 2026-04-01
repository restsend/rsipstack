use crate::sip::{Error, Header};

mod parse_helpers;
pub mod tokenizers;

pub trait TypedHeader<'a>:
    std::fmt::Debug
    + std::fmt::Display
    + std::cmp::PartialEq
    + std::cmp::Eq
    + std::clone::Clone
    + Into<String>
    + Into<Header>
{
}

pub trait Tokenize<'a> {
    fn tokenize(part: &'a str) -> Result<Self, Error>
    where
        Self: Sized;
}

pub use allow::Allow;
pub use authorization::Authorization;
pub use contact::Contact;
pub use cseq::CSeq;
pub use from::From;
pub use identity::Identity;
pub use proxy_authenticate::ProxyAuthenticate;
pub use proxy_authorization::ProxyAuthorization;
pub use record_route::RecordRoute;
pub use route::Route;
pub use to::To;
pub use via::Via;
pub use www_authenticate::WwwAuthenticate;

pub mod allow;
pub mod authorization;
pub mod contact;
pub mod cseq;
pub mod from;
pub mod identity;
pub mod proxy_authenticate;
pub mod proxy_authorization;
pub mod record_route;
pub mod route;
pub mod to;
pub mod via;
pub mod www_authenticate;
