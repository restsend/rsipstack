pub mod auth;
pub mod typed;
pub mod untyped;
pub use untyped::*;
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Header {
    Accept(Accept),
    AcceptEncoding(AcceptEncoding),
    AcceptLanguage(AcceptLanguage),
    AlertInfo(AlertInfo),
    Allow(Allow),
    AuthenticationInfo(AuthenticationInfo),
    Authorization(Authorization),
    CSeq(CSeq),
    CallId(CallId),
    CallInfo(CallInfo),
    Contact(Contact),
    ContentDisposition(ContentDisposition),
    ContentEncoding(ContentEncoding),
    ContentLanguage(ContentLanguage),
    ContentLength(ContentLength),
    ContentType(ContentType),
    Date(Date),
    ErrorInfo(ErrorInfo),
    Event(Event),
    Expires(Expires),
    From(From),
    InReplyTo(InReplyTo),
    MaxForwards(MaxForwards),
    MimeVersion(MimeVersion),
    MinExpires(MinExpires),
    Organization(Organization),
    Other(String, String),
    Priority(Priority),
    ProxyAuthenticate(ProxyAuthenticate),
    ProxyAuthorization(ProxyAuthorization),
    ProxyRequire(ProxyRequire),
    RecordRoute(RecordRoute),
    ReplyTo(ReplyTo),
    Require(Require),
    RetryAfter(RetryAfter),
    Route(Route),
    Server(Server),
    Subject(Subject),
    SubscriptionState(SubscriptionState),
    Supported(Supported),
    Timestamp(Timestamp),
    To(To),
    Unsupported(Unsupported),
    UserAgent(UserAgent),
    Via(Via),
    Warning(Warning),
    WwwAuthenticate(WwwAuthenticate),
    Reason(Reason),
    ReferTo(ReferTo),
    ReferredBy(ReferredBy),
    SessionExpires(SessionExpires),
    MinSE(MinSE),
    PAssertedIdentity(PAssertedIdentity),
    PPreferredIdentity(PPreferredIdentity),
    Replaces(Replaces),
    RSeq(RSeq),
    RAck(RAck),
    Privacy(Privacy),
    Path(Path),
    Identity(Identity),
}

impl std::fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept(inner) => write!(f, "{}", inner),
            Self::AcceptEncoding(inner) => write!(f, "{}", inner),
            Self::AcceptLanguage(inner) => write!(f, "{}", inner),
            Self::AlertInfo(inner) => write!(f, "{}", inner),
            Self::Allow(inner) => write!(f, "{}", inner),
            Self::AuthenticationInfo(inner) => write!(f, "{}", inner),
            Self::Authorization(inner) => write!(f, "{}", inner),
            Self::CSeq(inner) => write!(f, "{}", inner),
            Self::CallId(inner) => write!(f, "{}", inner),
            Self::CallInfo(inner) => write!(f, "{}", inner),
            Self::Contact(inner) => write!(f, "{}", inner),
            Self::ContentDisposition(inner) => write!(f, "{}", inner),
            Self::ContentEncoding(inner) => write!(f, "{}", inner),
            Self::ContentLanguage(inner) => write!(f, "{}", inner),
            Self::ContentLength(inner) => write!(f, "{}", inner),
            Self::ContentType(inner) => write!(f, "{}", inner),
            Self::Date(inner) => write!(f, "{}", inner),
            Self::ErrorInfo(inner) => write!(f, "{}", inner),
            Self::Event(inner) => write!(f, "{}", inner),
            Self::Expires(inner) => write!(f, "{}", inner),
            Self::From(inner) => write!(f, "{}", inner),
            Self::InReplyTo(inner) => write!(f, "{}", inner),
            Self::MaxForwards(inner) => write!(f, "{}", inner),
            Self::MimeVersion(inner) => write!(f, "{}", inner),
            Self::MinExpires(inner) => write!(f, "{}", inner),
            Self::Organization(inner) => write!(f, "{}", inner),
            Self::Other(key, value) => write!(f, "{}: {}", key, value),
            Self::Priority(inner) => write!(f, "{}", inner),
            Self::ProxyAuthenticate(inner) => write!(f, "{}", inner),
            Self::ProxyAuthorization(inner) => write!(f, "{}", inner),
            Self::ProxyRequire(inner) => write!(f, "{}", inner),
            Self::RecordRoute(inner) => write!(f, "{}", inner),
            Self::ReplyTo(inner) => write!(f, "{}", inner),
            Self::Require(inner) => write!(f, "{}", inner),
            Self::RetryAfter(inner) => write!(f, "{}", inner),
            Self::Route(inner) => write!(f, "{}", inner),
            Self::Server(inner) => write!(f, "{}", inner),
            Self::Subject(inner) => write!(f, "{}", inner),
            Self::SubscriptionState(inner) => write!(f, "{}", inner),
            Self::Supported(inner) => write!(f, "{}", inner),
            Self::Timestamp(inner) => write!(f, "{}", inner),
            Self::To(inner) => write!(f, "{}", inner),
            Self::Unsupported(inner) => write!(f, "{}", inner),
            Self::UserAgent(inner) => write!(f, "{}", inner),
            Self::Via(inner) => write!(f, "{}", inner),
            Self::Warning(inner) => write!(f, "{}", inner),
            Self::WwwAuthenticate(inner) => write!(f, "{}", inner),
            Self::Reason(inner) => write!(f, "{}", inner),
            Self::ReferTo(inner) => write!(f, "{}", inner),
            Self::ReferredBy(inner) => write!(f, "{}", inner),
            Self::SessionExpires(inner) => write!(f, "{}", inner),
            Self::MinSE(inner) => write!(f, "{}", inner),
            Self::PAssertedIdentity(inner) => write!(f, "{}", inner),
            Self::PPreferredIdentity(inner) => write!(f, "{}", inner),
            Self::Replaces(inner) => write!(f, "{}", inner),
            Self::RSeq(inner) => write!(f, "{}", inner),
            Self::RAck(inner) => write!(f, "{}", inner),
            Self::Privacy(inner) => write!(f, "{}", inner),
            Self::Path(inner) => write!(f, "{}", inner),
            Self::Identity(inner) => write!(f, "{}", inner),
        }
    }
}

impl Header {
    pub fn name(&self) -> &str {
        match self {
            Self::Accept(_) => "Accept",
            Self::AcceptEncoding(_) => "Accept-Encoding",
            Self::AcceptLanguage(_) => "Accept-Language",
            Self::AlertInfo(_) => "Alert-Info",
            Self::Allow(_) => "Allow",
            Self::AuthenticationInfo(_) => "Authentication-Info",
            Self::Authorization(_) => "Authorization",
            Self::CSeq(_) => "CSeq",
            Self::CallId(_) => "Call-ID",
            Self::CallInfo(_) => "Call-Info",
            Self::Contact(_) => "Contact",
            Self::ContentDisposition(_) => "Content-Disposition",
            Self::ContentEncoding(_) => "Content-Encoding",
            Self::ContentLanguage(_) => "Content-Language",
            Self::ContentLength(_) => "Content-Length",
            Self::ContentType(_) => "Content-Type",
            Self::Date(_) => "Date",
            Self::ErrorInfo(_) => "Error-Info",
            Self::Event(_) => "Event",
            Self::Expires(_) => "Expires",
            Self::From(_) => "From",
            Self::InReplyTo(_) => "In-Reply-To",
            Self::MaxForwards(_) => "Max-Forwards",
            Self::MimeVersion(_) => "Mime-Version",
            Self::MinExpires(_) => "Min-Expires",
            Self::Organization(_) => "Organization",
            Self::Other(key, _) => key.as_str(),
            Self::Priority(_) => "Priority",
            Self::ProxyAuthenticate(_) => "Proxy-Authenticate",
            Self::ProxyAuthorization(_) => "Proxy-Authorization",
            Self::ProxyRequire(_) => "Proxy-Require",
            Self::RecordRoute(_) => "Record-Route",
            Self::ReplyTo(_) => "Reply-To",
            Self::Require(_) => "Require",
            Self::RetryAfter(_) => "Retry-After",
            Self::Route(_) => "Route",
            Self::Server(_) => "Server",
            Self::Subject(_) => "Subject",
            Self::SubscriptionState(_) => "Subscription-State",
            Self::Supported(_) => "Supported",
            Self::Timestamp(_) => "Timestamp",
            Self::To(_) => "To",
            Self::Unsupported(_) => "Unsupported",
            Self::UserAgent(_) => "User-Agent",
            Self::Via(_) => "Via",
            Self::Warning(_) => "Warning",
            Self::WwwAuthenticate(_) => "WWW-Authenticate",
            Self::Reason(_) => "Reason",
            Self::ReferTo(_) => "Refer-To",
            Self::ReferredBy(_) => "Referred-By",
            Self::SessionExpires(_) => "Session-Expires",
            Self::MinSE(_) => "Min-SE",
            Self::PAssertedIdentity(_) => "P-Asserted-Identity",
            Self::PPreferredIdentity(_) => "P-Preferred-Identity",
            Self::Replaces(_) => "Replaces",
            Self::RSeq(_) => "RSeq",
            Self::RAck(_) => "RAck",
            Self::Privacy(_) => "Privacy",
            Self::Path(_) => "Path",
            Self::Identity(_) => "Identity",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::Accept(h) => h.value(),
            Self::AcceptEncoding(h) => h.value(),
            Self::AcceptLanguage(h) => h.value(),
            Self::AlertInfo(h) => h.value(),
            Self::Allow(h) => h.value(),
            Self::AuthenticationInfo(h) => h.value(),
            Self::Authorization(h) => h.value(),
            Self::CSeq(h) => h.value(),
            Self::CallId(h) => h.value(),
            Self::CallInfo(h) => h.value(),
            Self::Contact(h) => h.value(),
            Self::ContentDisposition(h) => h.value(),
            Self::ContentEncoding(h) => h.value(),
            Self::ContentLanguage(h) => h.value(),
            Self::ContentLength(h) => h.value(),
            Self::ContentType(h) => h.value(),
            Self::Date(h) => h.value(),
            Self::ErrorInfo(h) => h.value(),
            Self::Event(h) => h.value(),
            Self::Expires(h) => h.value(),
            Self::From(h) => h.value(),
            Self::InReplyTo(h) => h.value(),
            Self::MaxForwards(h) => h.value(),
            Self::MimeVersion(h) => h.value(),
            Self::MinExpires(h) => h.value(),
            Self::Organization(h) => h.value(),
            Self::Other(_, v) => v.as_str(),
            Self::Priority(h) => h.value(),
            Self::ProxyAuthenticate(h) => h.value(),
            Self::ProxyAuthorization(h) => h.value(),
            Self::ProxyRequire(h) => h.value(),
            Self::RecordRoute(h) => h.value(),
            Self::ReplyTo(h) => h.value(),
            Self::Require(h) => h.value(),
            Self::RetryAfter(h) => h.value(),
            Self::Route(h) => h.value(),
            Self::Server(h) => h.value(),
            Self::Subject(h) => h.value(),
            Self::SubscriptionState(h) => h.value(),
            Self::Supported(h) => h.value(),
            Self::Timestamp(h) => h.value(),
            Self::To(h) => h.value(),
            Self::Unsupported(h) => h.value(),
            Self::UserAgent(h) => h.value(),
            Self::Via(h) => h.value(),
            Self::Warning(h) => h.value(),
            Self::WwwAuthenticate(h) => h.value(),
            Self::Reason(h) => h.value(),
            Self::ReferTo(h) => h.value(),
            Self::ReferredBy(h) => h.value(),
            Self::SessionExpires(h) => h.value(),
            Self::MinSE(h) => h.value(),
            Self::PAssertedIdentity(h) => h.value(),
            Self::PPreferredIdentity(h) => h.value(),
            Self::Replaces(h) => h.value(),
            Self::RSeq(h) => h.value(),
            Self::RAck(h) => h.value(),
            Self::Privacy(h) => h.value(),
            Self::Path(h) => h.value(),
            Self::Identity(h) => h.value(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Headers(pub Vec<Header>);

impl Headers {
    pub fn push(&mut self, h: Header) {
        self.0.push(h)
    }

    pub fn push_front(&mut self, h: Header) {
        self.0.insert(0, h)
    }

    pub fn unique_push(&mut self, h: Header) {
        self.0
            .retain(|s| std::mem::discriminant(s) != std::mem::discriminant(&h));
        self.push(h);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.0.iter()
    }

    pub fn extend(&mut self, i: Vec<Header>) {
        self.0.extend(i)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Header> {
        self.0.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn retain<F: FnMut(&Header) -> bool>(&mut self, f: F) {
        self.0.retain(f)
    }

    pub fn get<T, F: Fn(&Header) -> Option<&T>>(&self, f: F) -> Option<&T> {
        self.0.iter().find_map(f)
    }

    pub fn get_all<T, F: Fn(&Header) -> Option<&T>>(&self, f: F) -> Vec<&T> {
        self.0.iter().filter_map(f).collect()
    }

    pub fn pop_first<T, F: Fn(&Header) -> Option<T>>(&mut self, f: F) -> Option<T> {
        let pos = self.0.iter().position(|h| f(h).is_some())?;
        f(&self.0.remove(pos))
    }

    pub fn remove_first<F: Fn(&Header) -> bool>(&mut self, pred: F) -> bool {
        if let Some(pos) = self.0.iter().position(pred) {
            self.0.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn remove_all<F: Fn(&Header) -> bool>(&mut self, pred: F) {
        self.0.retain(|h| !pred(h))
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::convert::From<Header> for Headers {
    fn from(h: Header) -> Self {
        Self(vec![h])
    }
}

impl std::convert::From<Vec<Header>> for Headers {
    fn from(v: Vec<Header>) -> Self {
        Self(v)
    }
}

impl std::convert::From<Headers> for Vec<Header> {
    fn from(h: Headers) -> Vec<Header> {
        h.0
    }
}

impl std::fmt::Display for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "");
        }
        write!(
            f,
            "{}\r\n",
            self.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("\r\n")
        )
    }
}

pub fn make_header(name: &str, value: String) -> Header {
    match name {
        n if n.eq_ignore_ascii_case("Accept") => Header::Accept(Accept::new(value)),
        n if n.eq_ignore_ascii_case("Accept-Encoding") => {
            Header::AcceptEncoding(AcceptEncoding::new(value))
        }
        n if n.eq_ignore_ascii_case("Accept-Language") => {
            Header::AcceptLanguage(AcceptLanguage::new(value))
        }
        n if n.eq_ignore_ascii_case("Alert-Info") => Header::AlertInfo(AlertInfo::new(value)),
        n if n.eq_ignore_ascii_case("Allow") => Header::Allow(Allow::new(value)),
        n if n.eq_ignore_ascii_case("Authentication-Info") => {
            Header::AuthenticationInfo(AuthenticationInfo::new(value))
        }
        n if n.eq_ignore_ascii_case("Authorization") => {
            Header::Authorization(Authorization::new(value))
        }
        n if n.eq_ignore_ascii_case("CSeq") => Header::CSeq(CSeq::new(value)),
        n if n.eq_ignore_ascii_case("Call-ID") || n.eq_ignore_ascii_case("i") => {
            Header::CallId(CallId::new(value))
        }
        n if n.eq_ignore_ascii_case("Call-Info") => Header::CallInfo(CallInfo::new(value)),
        n if n.eq_ignore_ascii_case("Contact") || n.eq_ignore_ascii_case("m") => {
            Header::Contact(Contact::new(value))
        }
        n if n.eq_ignore_ascii_case("Content-Disposition") => {
            Header::ContentDisposition(ContentDisposition::new(value))
        }
        n if n.eq_ignore_ascii_case("Content-Encoding") || n.eq_ignore_ascii_case("e") => {
            Header::ContentEncoding(ContentEncoding::new(value))
        }
        n if n.eq_ignore_ascii_case("Content-Language") => {
            Header::ContentLanguage(ContentLanguage::new(value))
        }
        n if n.eq_ignore_ascii_case("Content-Length") || n.eq_ignore_ascii_case("l") => {
            Header::ContentLength(ContentLength::new(value))
        }
        n if n.eq_ignore_ascii_case("Content-Type") || n.eq_ignore_ascii_case("c") => {
            Header::ContentType(ContentType::new(value))
        }
        n if n.eq_ignore_ascii_case("Date") => Header::Date(Date::new(value)),
        n if n.eq_ignore_ascii_case("Error-Info") => Header::ErrorInfo(ErrorInfo::new(value)),
        n if n.eq_ignore_ascii_case("Event") || n.eq_ignore_ascii_case("o") => {
            Header::Event(Event::new(value))
        }
        n if n.eq_ignore_ascii_case("Expires") => Header::Expires(Expires::new(value)),
        n if n.eq_ignore_ascii_case("From") || n.eq_ignore_ascii_case("f") => {
            Header::From(From::new(value))
        }
        n if n.eq_ignore_ascii_case("In-Reply-To") => Header::InReplyTo(InReplyTo::new(value)),
        n if n.eq_ignore_ascii_case("Max-Forwards") => Header::MaxForwards(MaxForwards::new(value)),
        n if n.eq_ignore_ascii_case("Mime-Version") => Header::MimeVersion(MimeVersion::new(value)),
        n if n.eq_ignore_ascii_case("Min-Expires") => Header::MinExpires(MinExpires::new(value)),
        n if n.eq_ignore_ascii_case("Organization") => {
            Header::Organization(Organization::new(value))
        }
        n if n.eq_ignore_ascii_case("Priority") => Header::Priority(Priority::new(value)),
        n if n.eq_ignore_ascii_case("Proxy-Authenticate") => {
            Header::ProxyAuthenticate(ProxyAuthenticate::new(value))
        }
        n if n.eq_ignore_ascii_case("Proxy-Authorization") => {
            Header::ProxyAuthorization(ProxyAuthorization::new(value))
        }
        n if n.eq_ignore_ascii_case("Proxy-Require") => {
            Header::ProxyRequire(ProxyRequire::new(value))
        }
        n if n.eq_ignore_ascii_case("Record-Route") => Header::RecordRoute(RecordRoute::new(value)),
        n if n.eq_ignore_ascii_case("Reply-To") => Header::ReplyTo(ReplyTo::new(value)),
        n if n.eq_ignore_ascii_case("Require") => Header::Require(Require::new(value)),
        n if n.eq_ignore_ascii_case("Retry-After") => Header::RetryAfter(RetryAfter::new(value)),
        n if n.eq_ignore_ascii_case("Route") => Header::Route(Route::new(value)),
        n if n.eq_ignore_ascii_case("Server") => Header::Server(Server::new(value)),
        n if n.eq_ignore_ascii_case("Subject") || n.eq_ignore_ascii_case("s") => {
            Header::Subject(Subject::new(value))
        }
        n if n.eq_ignore_ascii_case("Subscription-State") => {
            Header::SubscriptionState(SubscriptionState::new(value))
        }
        n if n.eq_ignore_ascii_case("Supported") || n.eq_ignore_ascii_case("k") => {
            Header::Supported(Supported::new(value))
        }
        n if n.eq_ignore_ascii_case("Timestamp") => Header::Timestamp(Timestamp::new(value)),
        n if n.eq_ignore_ascii_case("To") || n.eq_ignore_ascii_case("t") => {
            Header::To(To::new(value))
        }
        n if n.eq_ignore_ascii_case("Unsupported") => Header::Unsupported(Unsupported::new(value)),
        n if n.eq_ignore_ascii_case("User-Agent") => Header::UserAgent(UserAgent::new(value)),
        n if n.eq_ignore_ascii_case("Via") || n.eq_ignore_ascii_case("v") => {
            Header::Via(Via::new(value))
        }
        n if n.eq_ignore_ascii_case("Warning") => Header::Warning(Warning::new(value)),
        n if n.eq_ignore_ascii_case("WWW-Authenticate") => {
            Header::WwwAuthenticate(WwwAuthenticate::new(value))
        }
        n if n.eq_ignore_ascii_case("Reason") => Header::Reason(Reason::new(value)),
        n if n.eq_ignore_ascii_case("Refer-To") || n.eq_ignore_ascii_case("r") => {
            Header::ReferTo(ReferTo::new(value))
        }
        n if n.eq_ignore_ascii_case("Referred-By") || n.eq_ignore_ascii_case("b") => {
            Header::ReferredBy(ReferredBy::new(value))
        }
        n if n.eq_ignore_ascii_case("Session-Expires") || n.eq_ignore_ascii_case("x") => {
            Header::SessionExpires(SessionExpires::new(value))
        }
        n if n.eq_ignore_ascii_case("Min-SE") => Header::MinSE(MinSE::new(value)),
        n if n.eq_ignore_ascii_case("P-Asserted-Identity") => {
            Header::PAssertedIdentity(PAssertedIdentity::new(value))
        }
        n if n.eq_ignore_ascii_case("P-Preferred-Identity") => {
            Header::PPreferredIdentity(PPreferredIdentity::new(value))
        }
        n if n.eq_ignore_ascii_case("Replaces") => Header::Replaces(Replaces::new(value)),
        n if n.eq_ignore_ascii_case("RSeq") => Header::RSeq(RSeq::new(value)),
        n if n.eq_ignore_ascii_case("RAck") => Header::RAck(RAck::new(value)),
        n if n.eq_ignore_ascii_case("Privacy") => Header::Privacy(Privacy::new(value)),
        n if n.eq_ignore_ascii_case("Path") => Header::Path(Path::new(value)),
        n if n.eq_ignore_ascii_case("Identity") => Header::Identity(Identity::new(value)),
        other => Header::Other(other.to_string(), value),
    }
}
