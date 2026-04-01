pub mod error;
pub mod headers;
pub mod message;
pub mod method;
pub mod parser;
pub mod services;
pub mod status_code;
pub mod transport;
pub mod uri;
pub mod version;

pub use error::{Error, TokenizerError};
pub use headers::{Header, Headers};
pub use message::{HasHeaders, HeadersExt, Request, Response, SipMessage};
pub use method::Method;
pub use services::DigestGenerator;
pub use status_code::{StatusCode, StatusCodeKind};
pub use transport::{Port, Transport};
pub use uri::{
    parse_params, parse_uri, Auth, Domain, Host, HostWithPort, Param, Scheme, Uri, UriWithParams,
    UriWithParamsList,
};
pub use version::Version;

pub mod param {
    pub use super::uri::{
        Branch, Expires, Maddr, OtherParam, OtherParamValue, Received, Tag, Ttl, User, Q,
    };
}

pub mod typed {
    pub use super::headers::typed::{
        Allow, Authorization, CSeq, Contact, From, Identity, ProxyAuthenticate, ProxyAuthorization,
        RecordRoute, Route, To, Tokenize, TypedHeader, Via, WwwAuthenticate,
    };
    pub mod tokenizers {
        pub use crate::sip::headers::typed::tokenizers::{AuthTokenizer, CseqTokenizer};
    }
}

pub use headers::untyped::{
    Accept, AcceptEncoding, AcceptLanguage, AlertInfo, Allow, AuthenticationInfo, Authorization,
    CSeq, CallId, CallInfo, Contact, ContentDisposition, ContentEncoding, ContentLanguage,
    ContentLength, ContentType, Date, ErrorInfo, Event, Expires, From, Identity, InReplyTo,
    MaxForwards, MimeVersion, MinExpires, MinSE, Organization, PAssertedIdentity,
    PPreferredIdentity, Path, Priority, Privacy, ProxyAuthenticate, ProxyAuthorization,
    ProxyRequire, RAck, RSeq, Reason, RecordRoute, ReferTo, ReferredBy, Replaces, ReplyTo, Require,
    RetryAfter, Route, Server, SessionExpires, Subject, SubscriptionState, Supported, Timestamp,
    To, ToTypedHeader, Unsupported, UntypedHeader, UserAgent, Via, Warning, WwwAuthenticate,
};

pub mod prelude {
    pub use super::{
        headers::untyped::{ToTypedHeader, UntypedHeader},
        message::{HasHeaders, HeadersExt},
    };
}

#[macro_export]
macro_rules! sip_header_pop {
    ($headers:expr, $header:path) => {{
        let mut first = true;
        $headers.retain(|h| {
            if first && matches!(h, $header(_)) {
                first = false;
                false
            } else {
                true
            }
        });
    }};
}

#[macro_export]
macro_rules! sip_header {
    ($iter:expr, $header:path, $error:expr) => {
        $iter
            .find_map(|header| {
                if let $header(header) = header {
                    Some(header)
                } else {
                    None
                }
            })
            .ok_or($error)
    };
}

#[macro_export]
macro_rules! sip_header_opt {
    ($iter:expr, $header:path) => {
        $iter.find_map(|header| {
            if let $header(header) = header {
                Some(header)
            } else {
                None
            }
        })
    };
}

#[macro_export]
macro_rules! sip_all_headers {
    ($iter:expr, $header:path) => {
        $iter
            .filter_map(|header| {
                if let $header(header) = header {
                    Some(header)
                } else {
                    None
                }
            })
            .collect()
    };
}
