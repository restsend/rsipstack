use crate::sip::Error;

use super::typed;
use super::Header;

pub trait UntypedHeader<'a>:
    std::fmt::Debug
    + std::fmt::Display
    + std::cmp::PartialEq
    + std::cmp::Eq
    + std::clone::Clone
    + std::convert::From<String>
    + std::convert::Into<String>
    + std::convert::From<&'a str>
    + std::convert::Into<Header>
{
    fn new(value: impl Into<String>) -> Self;
    fn value(&self) -> &str;
    fn replace(&mut self, new_value: impl Into<String>);
}

pub trait ToTypedHeader<'a>:
    UntypedHeader<'a> + std::convert::TryInto<Self::Typed, Error = Error>
{
    type Typed: typed::TypedHeader<'a> + Into<Self>;

    fn typed(&self) -> Result<Self::Typed, Error> {
        self.clone().try_into()
    }
    fn into_typed(self) -> Result<Self::Typed, Error> {
        self.try_into()
    }
}

macro_rules! untyped_header {
    ($name:ident, $display:expr, $variant:path) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            pub fn value(&self) -> &str {
                &self.0
            }
            pub fn replace(&mut self, new_value: impl Into<String>) {
                self.0 = new_value.into();
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}: {}", $display, self.0)
            }
        }

        impl std::convert::From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl<'a> std::convert::From<&'a str> for $name {
            fn from(s: &'a str) -> Self {
                Self(s.to_string())
            }
        }
        impl std::convert::From<$name> for String {
            fn from(s: $name) -> String {
                s.0
            }
        }
        impl std::convert::From<$name> for Header {
            fn from(s: $name) -> Header {
                $variant(s)
            }
        }

        impl<'a> UntypedHeader<'a> for $name {
            fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            fn value(&self) -> &str {
                &self.0
            }
            fn replace(&mut self, new_value: impl Into<String>) {
                self.0 = new_value.into();
            }
        }
    };
}

untyped_header!(Accept, "Accept", Header::Accept);
untyped_header!(AcceptEncoding, "Accept-Encoding", Header::AcceptEncoding);
untyped_header!(AcceptLanguage, "Accept-Language", Header::AcceptLanguage);
untyped_header!(AlertInfo, "Alert-Info", Header::AlertInfo);
untyped_header!(Allow, "Allow", Header::Allow);
untyped_header!(
    AuthenticationInfo,
    "Authentication-Info",
    Header::AuthenticationInfo
);
untyped_header!(Authorization, "Authorization", Header::Authorization);
untyped_header!(CSeq, "CSeq", Header::CSeq);
untyped_header!(CallInfo, "Call-Info", Header::CallInfo);
untyped_header!(
    ContentDisposition,
    "Content-Disposition",
    Header::ContentDisposition
);
untyped_header!(ContentEncoding, "Content-Encoding", Header::ContentEncoding);
untyped_header!(ContentLanguage, "Content-Language", Header::ContentLanguage);
untyped_header!(ContentLength, "Content-Length", Header::ContentLength);
untyped_header!(ContentType, "Content-Type", Header::ContentType);
untyped_header!(Date, "Date", Header::Date);
untyped_header!(ErrorInfo, "Error-Info", Header::ErrorInfo);
untyped_header!(Event, "Event", Header::Event);
untyped_header!(Expires, "Expires", Header::Expires);
untyped_header!(InReplyTo, "In-Reply-To", Header::InReplyTo);
untyped_header!(MaxForwards, "Max-Forwards", Header::MaxForwards);
untyped_header!(MimeVersion, "Mime-Version", Header::MimeVersion);
untyped_header!(MinExpires, "Min-Expires", Header::MinExpires);
untyped_header!(Organization, "Organization", Header::Organization);
untyped_header!(Priority, "Priority", Header::Priority);
untyped_header!(
    ProxyAuthenticate,
    "Proxy-Authenticate",
    Header::ProxyAuthenticate
);
untyped_header!(
    ProxyAuthorization,
    "Proxy-Authorization",
    Header::ProxyAuthorization
);
untyped_header!(ProxyRequire, "Proxy-Require", Header::ProxyRequire);
untyped_header!(RecordRoute, "Record-Route", Header::RecordRoute);
untyped_header!(ReplyTo, "Reply-To", Header::ReplyTo);
untyped_header!(Require, "Require", Header::Require);
untyped_header!(RetryAfter, "Retry-After", Header::RetryAfter);
untyped_header!(Route, "Route", Header::Route);
untyped_header!(Server, "Server", Header::Server);
untyped_header!(Subject, "Subject", Header::Subject);
untyped_header!(
    SubscriptionState,
    "Subscription-State",
    Header::SubscriptionState
);
untyped_header!(Supported, "Supported", Header::Supported);
untyped_header!(Timestamp, "Timestamp", Header::Timestamp);
untyped_header!(Unsupported, "Unsupported", Header::Unsupported);
untyped_header!(UserAgent, "User-Agent", Header::UserAgent);
untyped_header!(Warning, "Warning", Header::Warning);
untyped_header!(WwwAuthenticate, "WWW-Authenticate", Header::WwwAuthenticate);
untyped_header!(Reason, "Reason", Header::Reason);
untyped_header!(ReferTo, "Refer-To", Header::ReferTo);
untyped_header!(ReferredBy, "Referred-By", Header::ReferredBy);
untyped_header!(SessionExpires, "Session-Expires", Header::SessionExpires);
untyped_header!(MinSE, "Min-SE", Header::MinSE);
untyped_header!(
    PAssertedIdentity,
    "P-Asserted-Identity",
    Header::PAssertedIdentity
);
untyped_header!(
    PPreferredIdentity,
    "P-Preferred-Identity",
    Header::PPreferredIdentity
);
untyped_header!(Replaces, "Replaces", Header::Replaces);
untyped_header!(RSeq, "RSeq", Header::RSeq);
untyped_header!(RAck, "RAck", Header::RAck);
untyped_header!(Privacy, "Privacy", Header::Privacy);
untyped_header!(Path, "Path", Header::Path);
untyped_header!(Identity, "Identity", Header::Identity);

impl std::convert::From<crate::sip::Uri> for ReferTo {
    fn from(uri: crate::sip::Uri) -> Self {
        Self(format!("<{}>", uri))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct CallId(pub String);
impl CallId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
    pub fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Call-ID: {}", self.0)
    }
}
impl std::convert::From<String> for CallId {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl<'a> std::convert::From<&'a str> for CallId {
    fn from(s: &'a str) -> Self {
        Self(s.to_string())
    }
}
impl std::convert::From<CallId> for String {
    fn from(s: CallId) -> String {
        s.0
    }
}
impl std::convert::From<CallId> for Header {
    fn from(s: CallId) -> Header {
        Header::CallId(s)
    }
}
impl<'a> UntypedHeader<'a> for CallId {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn value(&self) -> &str {
        &self.0
    }
    fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Contact(pub String);
impl Contact {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
    pub fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl std::fmt::Display for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact: {}", self.0)
    }
}
impl std::convert::From<String> for Contact {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl<'a> std::convert::From<&'a str> for Contact {
    fn from(s: &'a str) -> Self {
        Self(s.to_string())
    }
}
impl std::convert::From<Contact> for String {
    fn from(s: Contact) -> String {
        s.0
    }
}
impl std::convert::From<Contact> for Header {
    fn from(s: Contact) -> Header {
        Header::Contact(s)
    }
}
impl<'a> UntypedHeader<'a> for Contact {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn value(&self) -> &str {
        &self.0
    }
    fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct From(pub String);
impl From {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
    pub fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
    pub fn uri(&self) -> Result<crate::sip::Uri, Error> {
        self.typed().map(|t: typed::From| t.uri)
    }
}
impl std::fmt::Display for From {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "From: {}", self.0)
    }
}
impl std::convert::From<String> for From {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl<'a> std::convert::From<&'a str> for From {
    fn from(s: &'a str) -> Self {
        Self(s.to_string())
    }
}
impl std::convert::From<From> for String {
    fn from(s: From) -> String {
        s.0
    }
}
impl std::convert::From<From> for Header {
    fn from(s: From) -> Header {
        Header::From(s)
    }
}
impl<'a> UntypedHeader<'a> for From {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn value(&self) -> &str {
        &self.0
    }
    fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl From {
    pub fn tag(&self) -> Result<Option<crate::sip::param::Tag>, Error> {
        self.typed().map(|t: typed::From| t.tag().cloned())
    }
}
impl<'a> ToTypedHeader<'a> for From {
    type Typed = typed::From;
}
impl std::convert::TryInto<typed::From> for From {
    type Error = Error;
    fn try_into(self) -> Result<typed::From, Error> {
        typed::From::parse(self.0.trim())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct To(pub String);
impl To {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
    pub fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
    pub fn uri(&self) -> Result<crate::sip::Uri, Error> {
        self.typed().map(|t: typed::To| t.uri)
    }
}
impl std::fmt::Display for To {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "To: {}", self.0)
    }
}
impl std::convert::From<String> for To {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl<'a> std::convert::From<&'a str> for To {
    fn from(s: &'a str) -> Self {
        Self(s.to_string())
    }
}
impl std::convert::From<To> for String {
    fn from(s: To) -> String {
        s.0
    }
}
impl std::convert::From<To> for Header {
    fn from(s: To) -> Header {
        Header::To(s)
    }
}
impl<'a> UntypedHeader<'a> for To {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn value(&self) -> &str {
        &self.0
    }
    fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl To {
    pub fn tag(&self) -> Result<Option<crate::sip::param::Tag>, Error> {
        self.typed().map(|t: typed::To| t.tag().cloned())
    }
    pub fn mut_tag(&mut self, tag: crate::sip::param::Tag) -> Result<&mut Self, Error> {
        let mut typed_to = self.typed()?;
        typed_to
            .params
            .retain(|p| !matches!(p, crate::sip::Param::Tag(_)));
        typed_to.params.push(crate::sip::Param::Tag(tag));
        self.0 = typed_to.to_string();
        Ok(self)
    }
    pub fn with_tag(&self, tag: crate::sip::param::Tag) -> Self {
        if let Ok(mut typed_to) = self.typed() {
            typed_to
                .params
                .retain(|p| !matches!(p, crate::sip::Param::Tag(_)));
            typed_to.params.push(crate::sip::Param::Tag(tag));
            Self(typed_to.to_string())
        } else {
            self.clone()
        }
    }
}
impl<'a> ToTypedHeader<'a> for To {
    type Typed = typed::To;
}
impl std::convert::TryInto<typed::To> for To {
    type Error = Error;
    fn try_into(self) -> Result<typed::To, Error> {
        typed::To::parse(self.0.trim())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Via(pub String);
impl Via {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
    pub fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Via: {}", self.0)
    }
}
impl std::convert::From<String> for Via {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl<'a> std::convert::From<&'a str> for Via {
    fn from(s: &'a str) -> Self {
        Self(s.to_string())
    }
}
impl std::convert::From<Via> for String {
    fn from(s: Via) -> String {
        s.0
    }
}
impl std::convert::From<Via> for Header {
    fn from(s: Via) -> Header {
        Header::Via(s)
    }
}
impl<'a> UntypedHeader<'a> for Via {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn value(&self) -> &str {
        &self.0
    }
    fn replace(&mut self, new_value: impl Into<String>) {
        self.0 = new_value.into();
    }
}
impl<'a> ToTypedHeader<'a> for Via {
    type Typed = typed::Via;
}
impl std::convert::TryInto<typed::Via> for Via {
    type Error = Error;
    fn try_into(self) -> Result<typed::Via, Error> {
        typed::Via::parse(self.0.trim())
    }
}

impl<'a> ToTypedHeader<'a> for CSeq {
    type Typed = typed::CSeq;
}
impl std::convert::TryInto<typed::CSeq> for CSeq {
    type Error = Error;
    fn try_into(self) -> Result<typed::CSeq, Error> {
        typed::CSeq::parse(self.0.trim())
    }
}

impl CSeq {
    pub fn seq(&self) -> Result<u32, Error> {
        self.typed().map(|t: typed::CSeq| t.seq)
    }
    pub fn method(&self) -> Result<crate::sip::Method, Error> {
        self.typed().map(|t: typed::CSeq| t.method)
    }
    pub fn mut_seq(&mut self, seq: u32) -> Result<&mut Self, Error> {
        let typed = self.typed()?;
        self.0 = typed::CSeq {
            seq,
            method: typed.method,
        }
        .to_string();
        Ok(self)
    }
    pub fn mut_method(&mut self, method: crate::sip::Method) -> Result<&mut Self, Error> {
        let typed = self.typed()?;
        self.0 = typed::CSeq {
            seq: typed.seq,
            method,
        }
        .to_string();
        Ok(self)
    }
}

impl std::convert::From<u32> for ContentLength {
    fn from(n: u32) -> Self {
        Self(n.to_string())
    }
}

impl std::convert::From<u32> for Expires {
    fn from(n: u32) -> Self {
        Self(n.to_string())
    }
}

impl std::convert::From<u32> for MaxForwards {
    fn from(n: u32) -> Self {
        Self(n.to_string())
    }
}

impl<'a> ToTypedHeader<'a> for WwwAuthenticate {
    type Typed = typed::WwwAuthenticate;
}
impl std::convert::TryInto<typed::WwwAuthenticate> for WwwAuthenticate {
    type Error = Error;
    fn try_into(self) -> Result<typed::WwwAuthenticate, Error> {
        typed::WwwAuthenticate::parse(self.0.trim())
    }
}

impl<'a> ToTypedHeader<'a> for ProxyAuthenticate {
    type Typed = typed::ProxyAuthenticate;
}
impl std::convert::TryInto<typed::ProxyAuthenticate> for ProxyAuthenticate {
    type Error = Error;
    fn try_into(self) -> Result<typed::ProxyAuthenticate, Error> {
        typed::ProxyAuthenticate::parse(self.0.trim())
    }
}

impl<'a> ToTypedHeader<'a> for Route {
    type Typed = typed::Route;
}
impl std::convert::TryInto<typed::Route> for Route {
    type Error = Error;
    fn try_into(self) -> Result<typed::Route, Error> {
        typed::Route::parse(self.0.trim())
    }
}

impl<'a> ToTypedHeader<'a> for RecordRoute {
    type Typed = typed::RecordRoute;
}
impl std::convert::TryInto<typed::RecordRoute> for RecordRoute {
    type Error = Error;
    fn try_into(self) -> Result<typed::RecordRoute, Error> {
        typed::RecordRoute::parse(self.0.trim())
    }
}

impl<'a> ToTypedHeader<'a> for Contact {
    type Typed = typed::Contact;
}
impl std::convert::TryInto<typed::Contact> for Contact {
    type Error = Error;
    fn try_into(self) -> Result<typed::Contact, Error> {
        typed::Contact::parse(self.0.trim())
    }
}

// Typed -> Untyped conversions required by ToTypedHeader::Typed: Into<Self> bound
impl std::convert::From<typed::CSeq> for CSeq {
    fn from(c: typed::CSeq) -> Self {
        Self(c.to_string())
    }
}
impl std::convert::From<typed::WwwAuthenticate> for WwwAuthenticate {
    fn from(w: typed::WwwAuthenticate) -> Self {
        Self(w.to_string())
    }
}
impl std::convert::From<typed::ProxyAuthenticate> for ProxyAuthenticate {
    fn from(p: typed::ProxyAuthenticate) -> Self {
        Self(p.to_string())
    }
}
impl std::convert::From<typed::Route> for Route {
    fn from(r: typed::Route) -> Self {
        Self(r.to_string())
    }
}
impl std::convert::From<typed::RecordRoute> for RecordRoute {
    fn from(r: typed::RecordRoute) -> Self {
        Self(r.to_string())
    }
}
