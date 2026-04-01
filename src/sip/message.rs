use crate::sip::{
    headers::untyped::*,
    headers::{Header, Headers},
    uri::Branch,
    Error, Method, StatusCode, Uri, Version,
};

pub trait HasHeaders {
    fn headers(&self) -> &Headers;
    fn headers_mut(&mut self) -> &mut Headers;
}

macro_rules! header_get {
    ($iter:expr, $variant:path, $err:expr) => {
        $iter
            .find_map(|h| {
                if let $variant(inner) = h {
                    Some(inner)
                } else {
                    None
                }
            })
            .ok_or_else(|| $err)
    };
}

macro_rules! header_get_mut {
    ($iter:expr, $variant:path, $err:expr) => {
        $iter
            .find_map(|h| {
                if let $variant(inner) = h {
                    Some(inner)
                } else {
                    None
                }
            })
            .ok_or_else(|| $err)
    };
}

macro_rules! header_opt {
    ($iter:expr, $variant:path) => {
        $iter.find_map(|h| {
            if let $variant(inner) = h {
                Some(inner)
            } else {
                None
            }
        })
    };
}

macro_rules! all_headers {
    ($iter:expr, $variant:path) => {
        $iter
            .filter_map(|h| {
                if let $variant(inner) = h {
                    Some(inner)
                } else {
                    None
                }
            })
            .collect()
    };
}

pub trait HeadersExt: HasHeaders {
    fn to_header(&self) -> Result<&To, Error> {
        header_get!(
            self.headers().iter(),
            Header::To,
            Error::MissingHeader("To".into())
        )
    }
    fn to_header_mut(&mut self) -> Result<&mut To, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::To,
            Error::MissingHeader("To".into())
        )
    }
    fn from_header(&self) -> Result<&From, Error> {
        header_get!(
            self.headers().iter(),
            Header::From,
            Error::MissingHeader("From".into())
        )
    }
    fn from_header_mut(&mut self) -> Result<&mut From, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::From,
            Error::MissingHeader("From".into())
        )
    }
    fn via_header(&self) -> Result<&Via, Error> {
        header_get!(
            self.headers().iter(),
            Header::Via,
            Error::MissingHeader("Via".into())
        )
    }
    fn via_header_mut(&mut self) -> Result<&mut Via, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::Via,
            Error::MissingHeader("Via".into())
        )
    }
    fn call_id_header(&self) -> Result<&CallId, Error> {
        header_get!(
            self.headers().iter(),
            Header::CallId,
            Error::MissingHeader("Call-ID".into())
        )
    }
    fn call_id_header_mut(&mut self) -> Result<&mut CallId, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::CallId,
            Error::MissingHeader("Call-ID".into())
        )
    }
    fn cseq_header(&self) -> Result<&CSeq, Error> {
        header_get!(
            self.headers().iter(),
            Header::CSeq,
            Error::MissingHeader("CSeq".into())
        )
    }
    fn cseq_header_mut(&mut self) -> Result<&mut CSeq, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::CSeq,
            Error::MissingHeader("CSeq".into())
        )
    }
    fn max_forwards_header(&self) -> Result<&MaxForwards, Error> {
        header_get!(
            self.headers().iter(),
            Header::MaxForwards,
            Error::MissingHeader("Max-Forwards".into())
        )
    }
    fn max_forwards_header_mut(&mut self) -> Result<&mut MaxForwards, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::MaxForwards,
            Error::MissingHeader("Max-Forwards".into())
        )
    }
    fn contact_header(&self) -> Result<&Contact, Error> {
        header_get!(
            self.headers().iter(),
            Header::Contact,
            Error::MissingHeader("Contact".into())
        )
    }
    fn contact_header_mut(&mut self) -> Result<&mut Contact, Error> {
        header_get_mut!(
            self.headers_mut().iter_mut(),
            Header::Contact,
            Error::MissingHeader("Contact".into())
        )
    }
    fn contact_headers(&self) -> Vec<&Contact> {
        all_headers!(self.headers().iter(), Header::Contact)
    }
    fn typed_contact_headers(&self) -> Result<Vec<crate::sip::typed::Contact>, Error> {
        let mut contacts = Vec::new();
        for contact in self.contact_headers() {
            contacts.extend(crate::sip::typed::Contact::parse_header_list(
                contact.value(),
            )?);
        }
        Ok(contacts)
    }
    fn record_route_headers(&self) -> Vec<&RecordRoute> {
        all_headers!(self.headers().iter(), Header::RecordRoute)
    }
    fn record_route_header(&self) -> Option<&RecordRoute> {
        header_opt!(self.headers().iter(), Header::RecordRoute)
    }
    fn typed_record_route_headers(&self) -> Result<Vec<crate::sip::typed::RecordRoute>, Error> {
        let mut rrs = Vec::new();
        for rr in self.record_route_headers() {
            rrs.extend(crate::sip::typed::RecordRoute::parse_header_list(
                rr.value(),
            )?);
        }
        Ok(rrs)
    }
    fn route_headers(&self) -> Vec<&Route> {
        all_headers!(self.headers().iter(), Header::Route)
    }
    fn route_header(&self) -> Option<&Route> {
        header_opt!(self.headers().iter(), Header::Route)
    }
    fn typed_route_headers(&self) -> Result<Vec<crate::sip::typed::Route>, Error> {
        let mut routes = Vec::new();
        for r in self.route_headers() {
            routes.extend(crate::sip::typed::Route::parse_header_list(r.value())?);
        }
        Ok(routes)
    }
    fn user_agent_header(&self) -> Option<&UserAgent> {
        header_opt!(self.headers().iter(), Header::UserAgent)
    }
    fn authorization_header(&self) -> Option<&Authorization> {
        header_opt!(self.headers().iter(), Header::Authorization)
    }
    fn www_authenticate_header(&self) -> Option<&WwwAuthenticate> {
        header_opt!(self.headers().iter(), Header::WwwAuthenticate)
    }
    fn expires_header(&self) -> Option<&Expires> {
        header_opt!(self.headers().iter(), Header::Expires)
    }
    fn min_expires_header(&self) -> Option<&MinExpires> {
        header_opt!(self.headers().iter(), Header::MinExpires)
    }
    fn reason_header(&self) -> Option<&crate::sip::headers::untyped::Reason> {
        header_opt!(self.headers().iter(), Header::Reason)
    }
    fn refer_to_header(&self) -> Option<&crate::sip::headers::untyped::ReferTo> {
        header_opt!(self.headers().iter(), Header::ReferTo)
    }
    fn referred_by_header(&self) -> Option<&crate::sip::headers::untyped::ReferredBy> {
        header_opt!(self.headers().iter(), Header::ReferredBy)
    }
    fn session_expires_header(&self) -> Option<&crate::sip::headers::untyped::SessionExpires> {
        header_opt!(self.headers().iter(), Header::SessionExpires)
    }
    fn p_asserted_identity_header(
        &self,
    ) -> Option<&crate::sip::headers::untyped::PAssertedIdentity> {
        header_opt!(self.headers().iter(), Header::PAssertedIdentity)
    }
    fn replaces_header(&self) -> Option<&crate::sip::headers::untyped::Replaces> {
        header_opt!(self.headers().iter(), Header::Replaces)
    }
    fn privacy_header(&self) -> Option<&crate::sip::headers::untyped::Privacy> {
        header_opt!(self.headers().iter(), Header::Privacy)
    }
    fn path_headers(&self) -> Vec<&crate::sip::headers::untyped::Path> {
        all_headers!(self.headers().iter(), Header::Path)
    }
    fn rseq_value(&self) -> Option<u32> {
        self.headers().iter().find_map(|h| {
            if let Header::RSeq(r) = h {
                r.value().trim().parse().ok()
            } else {
                None
            }
        })
    }
    fn rack_value(&self) -> Option<(u32, u32, Method)> {
        self.headers().iter().find_map(|h| {
            if let Header::RAck(r) = h {
                let v = r.value();
                let mut parts = v.split_whitespace();
                let rseq = parts.next()?.parse::<u32>().ok()?;
                let cseq = parts.next()?.parse::<u32>().ok()?;
                let method = parts.next()?.parse::<Method>().ok()?;
                Some((rseq, cseq, method))
            } else {
                None
            }
        })
    }
    fn header_value(&self, name: &str) -> Option<String> {
        self.headers().iter().find_map(|h| {
            if h.name().eq_ignore_ascii_case(name) {
                Some(h.value().trim().to_string())
            } else {
                None
            }
        })
    }
    fn header_contains_token(&self, name: &str, token: &str) -> bool {
        self.headers().iter().any(|header| match header {
            Header::Supported(value) if name.eq_ignore_ascii_case("Supported") => value
                .value()
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(token)),
            Header::Require(value) if name.eq_ignore_ascii_case("Require") => value
                .value()
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(token)),
            _ => false,
        })
    }
    fn transaction_id(&self) -> Result<Option<Branch>, Error> {
        use crate::sip::headers::untyped::ToTypedHeader;
        Ok(self.via_header()?.clone().typed()?.branch().cloned())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Request {
    pub fn method(&self) -> &Method {
        &self.method
    }
    pub fn uri(&self) -> &Uri {
        &self.uri
    }
    pub fn destination(&self) -> Uri {
        for route in self.route_headers() {
            if let Ok(mut routes) = crate::sip::typed::Route::parse_header_list(route.value()) {
                if let Some(route) = routes.drain(..).next() {
                    return route.uri;
                }
            }
        }
        self.uri.clone()
    }
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }
}

impl HasHeaders for Request {
    fn headers(&self) -> &Headers {
        &self.headers
    }
    fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }
}

impl HeadersExt for Request {}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}\r\n{}\r\n{}",
            self.method,
            self.uri,
            self.version,
            self.headers,
            String::from_utf8_lossy(&self.body)
        )
    }
}

impl std::convert::TryFrom<Vec<u8>> for Request {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        match crate::sip::parser::parse_message(&bytes)? {
            SipMessage::Request(r) => Ok(r),
            SipMessage::Response(_) => {
                Err(Error::Unexpected("expected Request, got Response".into()))
            }
        }
    }
}

impl std::convert::TryFrom<&[u8]> for Request {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        match crate::sip::parser::parse_message(bytes)? {
            SipMessage::Request(r) => Ok(r),
            SipMessage::Response(_) => {
                Err(Error::Unexpected("expected Request, got Response".into()))
            }
        }
    }
}

impl std::convert::TryFrom<&str> for Request {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::TryFrom<String> for Request {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::From<Request> for String {
    fn from(r: Request) -> String {
        r.to_string()
    }
}

impl std::convert::From<Request> for Vec<u8> {
    fn from(r: Request) -> Vec<u8> {
        r.to_string().into_bytes()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    pub status_code: StatusCode,
    pub version: Version,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    pub fn status_code(&self) -> &StatusCode {
        &self.status_code
    }
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }
}

impl HasHeaders for Response {
    fn headers(&self) -> &Headers {
        &self.headers
    }
    fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }
}

impl HeadersExt for Response {}

impl Default for Response {
    fn default() -> Self {
        Response {
            status_code: StatusCode::OK,
            version: Version::V2,
            headers: Headers::default(),
            body: Vec::new(),
        }
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}\r\n{}\r\n{}",
            self.version,
            self.status_code.code(),
            self.status_code.text(),
            self.headers,
            String::from_utf8_lossy(&self.body)
        )
    }
}

impl std::convert::TryFrom<Vec<u8>> for Response {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        match crate::sip::parser::parse_message(&bytes)? {
            SipMessage::Response(r) => Ok(r),
            SipMessage::Request(_) => {
                Err(Error::Unexpected("expected Response, got Request".into()))
            }
        }
    }
}

impl std::convert::TryFrom<&[u8]> for Response {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        match crate::sip::parser::parse_message(bytes)? {
            SipMessage::Response(r) => Ok(r),
            SipMessage::Request(_) => {
                Err(Error::Unexpected("expected Response, got Request".into()))
            }
        }
    }
}

impl std::convert::TryFrom<&str> for Response {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::TryFrom<String> for Response {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::From<Response> for String {
    fn from(r: Response) -> String {
        r.to_string()
    }
}

impl std::convert::From<Response> for Vec<u8> {
    fn from(r: Response) -> Vec<u8> {
        r.to_string().into_bytes()
    }
}

impl std::convert::TryFrom<bytes::Bytes> for SipMessage {
    type Error = Error;
    fn try_from(bytes: bytes::Bytes) -> Result<Self, Error> {
        crate::sip::parser::parse_message(&bytes)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SipMessage {
    Request(Request),
    Response(Response),
}

impl SipMessage {
    pub fn is_request(&self) -> bool {
        matches!(self, SipMessage::Request(_))
    }
    pub fn is_response(&self) -> bool {
        matches!(self, SipMessage::Response(_))
    }
}

impl HasHeaders for SipMessage {
    fn headers(&self) -> &Headers {
        match self {
            SipMessage::Request(r) => r.headers(),
            SipMessage::Response(r) => r.headers(),
        }
    }
    fn headers_mut(&mut self) -> &mut Headers {
        match self {
            SipMessage::Request(r) => r.headers_mut(),
            SipMessage::Response(r) => r.headers_mut(),
        }
    }
}

impl HeadersExt for SipMessage {}

impl std::fmt::Display for SipMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SipMessage::Request(r) => write!(f, "{}", r),
            SipMessage::Response(r) => write!(f, "{}", r),
        }
    }
}

impl std::convert::TryFrom<Vec<u8>> for SipMessage {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        crate::sip::parser::parse_message(&bytes)
    }
}

impl std::convert::TryFrom<&[u8]> for SipMessage {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        crate::sip::parser::parse_message(bytes)
    }
}

impl std::convert::TryFrom<&str> for SipMessage {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::TryFrom<String> for SipMessage {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}

impl std::convert::From<Request> for SipMessage {
    fn from(r: Request) -> SipMessage {
        SipMessage::Request(r)
    }
}

impl std::convert::From<Response> for SipMessage {
    fn from(r: Response) -> SipMessage {
        SipMessage::Response(r)
    }
}

impl std::convert::TryFrom<SipMessage> for Request {
    type Error = Error;
    fn try_from(m: SipMessage) -> Result<Self, Error> {
        match m {
            SipMessage::Request(r) => Ok(r),
            SipMessage::Response(_) => Err(Error::Unexpected("expected Request".into())),
        }
    }
}

impl std::convert::TryFrom<SipMessage> for Response {
    type Error = Error;
    fn try_from(m: SipMessage) -> Result<Self, Error> {
        match m {
            SipMessage::Response(r) => Ok(r),
            SipMessage::Request(_) => Err(Error::Unexpected("expected Response".into())),
        }
    }
}

impl std::convert::From<SipMessage> for String {
    fn from(m: SipMessage) -> String {
        m.to_string()
    }
}

impl std::convert::From<SipMessage> for Vec<u8> {
    fn from(m: SipMessage) -> Vec<u8> {
        m.to_string().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{HasHeaders, HeadersExt, Request, Response, SipMessage};
    use crate::sip::{Header, Method};

    fn invite_request() -> &'static str {
        concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bK776asdhds\r\n",
            "Max-Forwards: 70\r\n",
            "To: Bob <sip:bob@restsend.com>\r\n",
            "From: Alice <sip:alice@restsend.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@ua.restsend.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:alice@ua.restsend.com>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
    }

    fn register_request() -> &'static str {
        concat!(
            "REGISTER sip:registrar.restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com:5060;branch=z9hG4bKnashds8\r\n",
            "Max-Forwards: 70\r\n",
            "To: Bob <sip:bob@restsend.com>\r\n",
            "From: Bob <sip:bob@restsend.com>;tag=456248\r\n",
            "Call-ID: 843817637684230@998sdasdh09\r\n",
            "CSeq: 1826 REGISTER\r\n",
            "Contact: <sip:bob@192.0.2.4>\r\n",
            "Expires: 7200\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
    }

    fn ok_response() -> &'static str {
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP proxy1.restsend.com;branch=z9hG4bK4b43c2ff8.1;received=192.0.2.3\r\n",
            "Via: SIP/2.0/UDP proxy2.restsend.com;branch=z9hG4bK77ef4c2312983.1;received=192.0.2.2\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n",
            "To: Bob <sip:bob@restsend.com>;tag=a6c85cf\r\n",
            "From: Alice <sip:alice@restsend.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@ua.restsend.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:bob@192.0.2.4>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: 131\r\n",
            "\r\n",
            "v=0\r\no=bob 2890844527 2890844527 IN IP4 192.0.2.4\r\ns=-\r\nc=IN IP4 192.0.2.4\r\nt=0 0\r\nm=audio 3456 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000"
        )
    }

    #[test]
    fn parse_invite_request() {
        let req: Request = invite_request().try_into().unwrap();
        assert_eq!(req.method, Method::Invite);
        assert_eq!(req.uri.to_string(), "sip:bob@restsend.com");
        assert_eq!(
            req.from_header().unwrap().value(),
            "Alice <sip:alice@restsend.com>;tag=1928301774"
        );
        assert_eq!(
            req.to_header().unwrap().value(),
            "Bob <sip:bob@restsend.com>"
        );
        assert_eq!(
            req.call_id_header().unwrap().value(),
            "a84b4c76e66710@ua.restsend.com"
        );
    }

    #[test]
    fn parse_register_request() {
        let req: Request = register_request().try_into().unwrap();
        assert_eq!(req.method, Method::Register);
        let contacts = req.typed_contact_headers().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.to_string(), "sip:bob@192.0.2.4");
    }

    #[test]
    fn parse_ok_response() {
        let resp: Response = ok_response().try_into().unwrap();
        assert_eq!(resp.status_code.code(), 200);
        assert_eq!(resp.body, b"v=0\r\no=bob 2890844527 2890844527 IN IP4 192.0.2.4\r\ns=-\r\nc=IN IP4 192.0.2.4\r\nt=0 0\r\nm=audio 3456 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000");
    }

    #[test]
    fn response_has_multiple_via_headers() {
        let resp: Response = ok_response().try_into().unwrap();
        let vias: Vec<_> = resp
            .headers()
            .iter()
            .filter(|h| matches!(h, Header::Via(_)))
            .collect();
        assert_eq!(vias.len(), 3);
    }

    #[test]
    fn headers_push_front() {
        let mut req: Request = invite_request().try_into().unwrap();
        let orig_first = req.headers.iter().next().unwrap().name().to_string();
        req.headers
            .push_front(Header::MaxForwards(crate::sip::MaxForwards::new("10")));
        assert_eq!(req.headers.iter().next().unwrap().name(), "Max-Forwards");
        assert_eq!(req.headers.iter().nth(1).unwrap().name(), orig_first);
    }

    #[test]
    fn new_headers_reason_roundtrip() {
        let msg: SipMessage = concat!(
            "BYE sip:alice@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bK776asdhds\r\n",
            "From: <sip:bob@restsend.com>;tag=a6c85cf\r\n",
            "To: <sip:alice@restsend.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@ua.restsend.com\r\n",
            "CSeq: 231 BYE\r\n",
            "Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        let reason = msg.reason_header().unwrap();
        assert!(reason.value().contains("200"));
        assert!(reason.value().contains("Call completed elsewhere"));
    }

    #[test]
    fn new_headers_refer_to_roundtrip() {
        let msg: SipMessage = concat!(
            "REFER sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKkjshdyff\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "From: <sip:alice@restsend.com>;tag=xyz\r\n",
            "Call-ID: 12345600@ua.restsend.com\r\n",
            "CSeq: 1 REFER\r\n",
            "Refer-To: <sip:carol@restsend.com>\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        assert!(msg.refer_to_header().is_some());
        assert_eq!(
            msg.refer_to_header().unwrap().value(),
            "<sip:carol@restsend.com>"
        );
    }

    #[test]
    fn new_headers_session_expires_roundtrip() {
        let msg: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: test@ua.restsend.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Session-Expires: 1800;refresher=uac\r\n",
            "Min-SE: 90\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        let se = msg.session_expires_header().unwrap();
        assert!(se.value().contains("1800"));
        let min_se = msg.headers().iter().find_map(|h| {
            if let Header::MinSE(m) = h {
                Some(m)
            } else {
                None
            }
        });
        assert!(min_se.is_some());
        assert_eq!(min_se.unwrap().value(), "90");
    }

    #[test]
    fn new_headers_p_asserted_identity() {
        let msg: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:anonymous@anonymous.invalid>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: pai-test@ua.restsend.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "P-Asserted-Identity: <sip:alice@restsend.com>\r\n",
            "Privacy: id\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        assert!(msg.p_asserted_identity_header().is_some());
        assert_eq!(
            msg.p_asserted_identity_header().unwrap().value(),
            "<sip:alice@restsend.com>"
        );
        assert!(msg.privacy_header().is_some());
    }

    #[test]
    fn new_headers_replaces() {
        let msg: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: transfer-test@ua.restsend.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Replaces: original-call-id@ua.restsend.com;to-tag=orig-to;from-tag=orig-from\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        let replaces = msg.replaces_header().unwrap();
        assert!(replaces.value().contains("original-call-id"));
    }

    #[test]
    fn new_headers_rseq_rack() {
        let prack: SipMessage = concat!(
            "PRACK sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>;tag=xyz\r\n",
            "Call-ID: prack-test@ua.restsend.com\r\n",
            "CSeq: 2 PRACK\r\n",
            "RAck: 776656 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();

        let rack = prack.rack_value().unwrap();
        assert_eq!(rack.0, 776656);
        assert_eq!(rack.1, 1);
        assert_eq!(rack.2, Method::Invite);

        let provisional: SipMessage = concat!(
            "SIP/2.0 183 Session Progress\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>;tag=xyz\r\n",
            "Call-ID: prack-test@ua.restsend.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "RSeq: 776656\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();

        assert_eq!(provisional.rseq_value(), Some(776656));
    }

    #[test]
    fn new_headers_path_header() {
        let msg: SipMessage = concat!(
            "REGISTER sip:registrar.restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP edge.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:alice@restsend.com>\r\n",
            "Call-ID: path-test@edge.restsend.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Path: <sip:edge.restsend.com;lr>\r\n",
            "Contact: <sip:alice@192.0.2.5:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        let paths = msg.path_headers();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].value().contains("edge.restsend.com"));
    }

    #[test]
    fn header_value_helper_case_insensitive() {
        let req: Request = invite_request().try_into().unwrap();
        let val = req.header_value("content-type");
        assert!(val.is_some());
        assert!(val.unwrap().contains("application/sdp"));
    }

    #[test]
    fn header_contains_token_helper() {
        let msg: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: test@pc33\r\n",
            "CSeq: 1 INVITE\r\n",
            "Supported: timer, 100rel, replaces\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        assert!(msg.header_contains_token("supported", "timer"));
        assert!(msg.header_contains_token("supported", "100rel"));
        assert!(!msg.header_contains_token("supported", "gruu"));
        assert!(!msg.header_contains_token("content-type", "application/sdp"));
    }

    #[test]
    fn destination_from_request_without_route() {
        let req: Request = invite_request().try_into().unwrap();
        let dest = req.destination();
        assert_eq!(dest.to_string(), "sip:bob@restsend.com");
    }

    #[test]
    fn destination_from_request_with_route() {
        let req: Request = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "Route: <sip:proxy.restsend.com;lr>\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: routed@pc33\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        let dest = req.destination();
        assert_eq!(dest.to_string(), "sip:proxy.restsend.com;lr");
    }

    #[test]
    fn compact_form_headers_are_parsed() {
        let message: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "v: SIP/2.0/UDP restsend.com:5060;branch=z9hG4bK-1\r\n",
            "f: <sip:alice@restsend.com>;tag=123\r\n",
            "t: <sip:bob@restsend.com>\r\n",
            "i: call-id-1\r\n",
            "m: <sip:alice@restsend.com>\r\n",
            "e: gzip\r\n",
            "l: 0\r\n",
            "c: application/sdp\r\n",
            "s: hello\r\n",
            "k: timer\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();

        assert!(message.via_header().is_ok());
        assert!(message.from_header().is_ok());
        assert!(message.to_header().is_ok());
        assert!(message.call_id_header().is_ok());
        assert!(message.contact_header().is_ok());
        assert!(message
            .headers()
            .iter()
            .any(|header| matches!(header, Header::ContentEncoding(_))));
        assert!(message
            .headers()
            .iter()
            .any(|header| matches!(header, Header::ContentLength(_))));
        assert!(message
            .headers()
            .iter()
            .any(|header| matches!(header, Header::ContentType(_))));
        assert!(message
            .headers()
            .iter()
            .any(|header| matches!(header, Header::Subject(_))));
        assert!(message
            .headers()
            .iter()
            .any(|header| matches!(header, Header::Supported(_))));
    }

    #[test]
    fn compact_form_refer_to_alias_r() {
        let msg: SipMessage = concat!(
            "REFER sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: refer-compact@host\r\n",
            "CSeq: 1 REFER\r\n",
            "r: <sip:carol@restsend.com>\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        assert!(msg.refer_to_header().is_some());
    }

    #[test]
    fn compact_form_session_expires_alias_x() {
        let msg: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP ua.restsend.com;branch=z9hG4bKtest\r\n",
            "From: <sip:alice@restsend.com>;tag=abc\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: se-compact@host\r\n",
            "CSeq: 1 INVITE\r\n",
            "x: 1800\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();
        assert!(msg.session_expires_header().is_some());
        assert_eq!(msg.session_expires_header().unwrap().value(), "1800");
    }
}
