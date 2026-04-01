use crate::sip::Error;

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub enum StatusCode {
    Trying,
    Ringing,
    CallIsBeingForwarded,
    Queued,
    SessionProgress,
    EarlyDialogTerminated,
    OK,
    Accepted,
    NoNotification,
    MultipleChoices,
    MovedPermanently,
    MovedTemporarily,
    UseProxy,
    AlternativeService,
    BadRequest,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    ProxyAuthenticationRequired,
    RequestTimeout,
    Conflict,
    Gone,
    LengthRequired,
    ConditionalRequestFailed,
    RequestEntityTooLarge,
    RequestUriTooLong,
    UnsupportedMediaType,
    UnsupportedUriScheme,
    UnknownResourcePriority,
    BadExtension,
    ExtensionRequired,
    SessionIntervalTooSmall,
    IntervalTooBrief,
    BadLocationInformation,
    UseIdentityHeader,
    ProvideReferrerIdentity,
    AnonymityDisallowed,
    BadIdentityInfo,
    UnsupportedCertificate,
    InvalidIdentityHeader,
    FirstHopLacksOutboundSupport,
    MaxBreadthExceeded,
    BadInfoPackage,
    ConsentNeeded,
    TemporarilyUnavailable,
    CallTransactionDoesNotExist,
    LoopDetected,
    TooManyHops,
    AddressIncomplete,
    Ambiguous,
    BusyHere,
    RequestTerminated,
    NotAcceptableHere,
    BadEvent,
    RequestPending,
    Undecipherable,
    SecurityAgreementRequired,
    ServerInternalError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    ServerTimeOut,
    VersionNotSupported,
    MessageTooLarge,
    PreconditionFailure,
    BusyEverywhere,
    Decline,
    DoesNotExistAnywhere,
    NotAcceptableGlobal,
    Unwanted,
    Other(u16, String),
}

impl StatusCode {
    pub fn code(&self) -> u16 {
        match self {
            Self::Trying => 100,
            Self::Ringing => 180,
            Self::CallIsBeingForwarded => 181,
            Self::Queued => 182,
            Self::SessionProgress => 183,
            Self::EarlyDialogTerminated => 199,
            Self::OK => 200,
            Self::Accepted => 202,
            Self::NoNotification => 204,
            Self::MultipleChoices => 300,
            Self::MovedPermanently => 301,
            Self::MovedTemporarily => 302,
            Self::UseProxy => 305,
            Self::AlternativeService => 380,
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::PaymentRequired => 402,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::NotAcceptable => 406,
            Self::ProxyAuthenticationRequired => 407,
            Self::RequestTimeout => 408,
            Self::Conflict => 409,
            Self::Gone => 410,
            Self::LengthRequired => 411,
            Self::ConditionalRequestFailed => 412,
            Self::RequestEntityTooLarge => 413,
            Self::RequestUriTooLong => 414,
            Self::UnsupportedMediaType => 415,
            Self::UnsupportedUriScheme => 416,
            Self::UnknownResourcePriority => 417,
            Self::BadExtension => 420,
            Self::ExtensionRequired => 421,
            Self::SessionIntervalTooSmall => 422,
            Self::IntervalTooBrief => 423,
            Self::BadLocationInformation => 424,
            Self::UseIdentityHeader => 428,
            Self::ProvideReferrerIdentity => 429,
            Self::AnonymityDisallowed => 433,
            Self::BadIdentityInfo => 436,
            Self::UnsupportedCertificate => 437,
            Self::InvalidIdentityHeader => 438,
            Self::FirstHopLacksOutboundSupport => 439,
            Self::MaxBreadthExceeded => 440,
            Self::BadInfoPackage => 469,
            Self::ConsentNeeded => 470,
            Self::TemporarilyUnavailable => 480,
            Self::CallTransactionDoesNotExist => 481,
            Self::LoopDetected => 482,
            Self::TooManyHops => 483,
            Self::AddressIncomplete => 484,
            Self::Ambiguous => 485,
            Self::BusyHere => 486,
            Self::RequestTerminated => 487,
            Self::NotAcceptableHere => 488,
            Self::BadEvent => 489,
            Self::RequestPending => 491,
            Self::Undecipherable => 493,
            Self::SecurityAgreementRequired => 494,
            Self::ServerInternalError => 500,
            Self::NotImplemented => 501,
            Self::BadGateway => 502,
            Self::ServiceUnavailable => 503,
            Self::ServerTimeOut => 504,
            Self::VersionNotSupported => 505,
            Self::MessageTooLarge => 513,
            Self::PreconditionFailure => 580,
            Self::BusyEverywhere => 600,
            Self::Decline => 603,
            Self::DoesNotExistAnywhere => 604,
            Self::NotAcceptableGlobal => 606,
            Self::Unwanted => 607,
            Self::Other(code, _) => *code,
        }
    }

    pub fn kind(&self) -> StatusCodeKind {
        let code = self.code();
        match code {
            100..=199 => StatusCodeKind::Provisional,
            200..=299 => StatusCodeKind::Successful,
            300..=399 => StatusCodeKind::Redirection,
            400..=499 => StatusCodeKind::RequestFailure,
            500..=599 => StatusCodeKind::ServerFailure,
            600..=699 => StatusCodeKind::GlobalFailure,
            _ => StatusCodeKind::Other,
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Self::Trying => "Trying",
            Self::Ringing => "Ringing",
            Self::CallIsBeingForwarded => "Call Is Being Forwarded",
            Self::Queued => "Queued",
            Self::SessionProgress => "Session Progress",
            Self::EarlyDialogTerminated => "Early Dialog Terminated",
            Self::OK => "OK",
            Self::Accepted => "Accepted",
            Self::NoNotification => "No Notification",
            Self::MultipleChoices => "Multiple Choices",
            Self::MovedPermanently => "Moved Permanently",
            Self::MovedTemporarily => "Moved Temporarily",
            Self::UseProxy => "Use Proxy",
            Self::AlternativeService => "Alternative Service",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::PaymentRequired => "Payment Required",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::NotAcceptable => "Not Acceptable",
            Self::ProxyAuthenticationRequired => "Proxy Authentication Required",
            Self::RequestTimeout => "Request Timeout",
            Self::Conflict => "Conflict",
            Self::Gone => "Gone",
            Self::LengthRequired => "Length Required",
            Self::ConditionalRequestFailed => "Conditional Request Failed",
            Self::RequestEntityTooLarge => "Request Entity Too Large",
            Self::RequestUriTooLong => "Request-URI Too Long",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::UnsupportedUriScheme => "Unsupported URI Scheme",
            Self::UnknownResourcePriority => "Unknown Resource-Priority",
            Self::BadExtension => "Bad Extension",
            Self::ExtensionRequired => "Extension Required",
            Self::SessionIntervalTooSmall => "Session Interval Too Small",
            Self::IntervalTooBrief => "Interval Too Brief",
            Self::BadLocationInformation => "Bad Location Information",
            Self::UseIdentityHeader => "Use Identity Header",
            Self::ProvideReferrerIdentity => "Provide Referrer Identity",
            Self::AnonymityDisallowed => "Anonymity Disallowed",
            Self::BadIdentityInfo => "Bad Identity-Info",
            Self::UnsupportedCertificate => "Unsupported Certificate",
            Self::InvalidIdentityHeader => "Invalid Identity Header",
            Self::FirstHopLacksOutboundSupport => "First Hop Lacks Outbound Support",
            Self::MaxBreadthExceeded => "Max-Breadth Exceeded",
            Self::BadInfoPackage => "Bad Info Package",
            Self::ConsentNeeded => "Consent Needed",
            Self::TemporarilyUnavailable => "Temporarily Unavailable",
            Self::CallTransactionDoesNotExist => "Call/Transaction Does Not Exist",
            Self::LoopDetected => "Loop Detected",
            Self::TooManyHops => "Too Many Hops",
            Self::AddressIncomplete => "Address Incomplete",
            Self::Ambiguous => "Ambiguous",
            Self::BusyHere => "Busy Here",
            Self::RequestTerminated => "Request Terminated",
            Self::NotAcceptableHere => "Not Acceptable Here",
            Self::BadEvent => "Bad Event",
            Self::RequestPending => "Request Pending",
            Self::Undecipherable => "Undecipherable",
            Self::SecurityAgreementRequired => "Security Agreement Required",
            Self::ServerInternalError => "Server Internal Error",
            Self::NotImplemented => "Not Implemented",
            Self::BadGateway => "Bad Gateway",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::ServerTimeOut => "Server Time-out",
            Self::VersionNotSupported => "Version Not Supported",
            Self::MessageTooLarge => "Message Too Large",
            Self::PreconditionFailure => "Precondition Failure",
            Self::BusyEverywhere => "Busy Everywhere",
            Self::Decline => "Decline",
            Self::DoesNotExistAnywhere => "Does Not Exist Anywhere",
            Self::NotAcceptableGlobal => "Not Acceptable",
            Self::Unwanted => "Unwanted",
            Self::Other(_, reason) => reason.as_str(),
        }
    }

    fn from_code(code: u16, reason: &str) -> Self {
        match code {
            100 => Self::Trying,
            180 => Self::Ringing,
            181 => Self::CallIsBeingForwarded,
            182 => Self::Queued,
            183 => Self::SessionProgress,
            199 => Self::EarlyDialogTerminated,
            200 => Self::OK,
            202 => Self::Accepted,
            204 => Self::NoNotification,
            300 => Self::MultipleChoices,
            301 => Self::MovedPermanently,
            302 => Self::MovedTemporarily,
            305 => Self::UseProxy,
            380 => Self::AlternativeService,
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            402 => Self::PaymentRequired,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            406 => Self::NotAcceptable,
            407 => Self::ProxyAuthenticationRequired,
            408 => Self::RequestTimeout,
            409 => Self::Conflict,
            410 => Self::Gone,
            411 => Self::LengthRequired,
            412 => Self::ConditionalRequestFailed,
            413 => Self::RequestEntityTooLarge,
            414 => Self::RequestUriTooLong,
            415 => Self::UnsupportedMediaType,
            416 => Self::UnsupportedUriScheme,
            417 => Self::UnknownResourcePriority,
            420 => Self::BadExtension,
            421 => Self::ExtensionRequired,
            422 => Self::SessionIntervalTooSmall,
            423 => Self::IntervalTooBrief,
            424 => Self::BadLocationInformation,
            428 => Self::UseIdentityHeader,
            429 => Self::ProvideReferrerIdentity,
            433 => Self::AnonymityDisallowed,
            436 => Self::BadIdentityInfo,
            437 => Self::UnsupportedCertificate,
            438 => Self::InvalidIdentityHeader,
            439 => Self::FirstHopLacksOutboundSupport,
            440 => Self::MaxBreadthExceeded,
            469 => Self::BadInfoPackage,
            470 => Self::ConsentNeeded,
            480 => Self::TemporarilyUnavailable,
            481 => Self::CallTransactionDoesNotExist,
            482 => Self::LoopDetected,
            483 => Self::TooManyHops,
            484 => Self::AddressIncomplete,
            485 => Self::Ambiguous,
            486 => Self::BusyHere,
            487 => Self::RequestTerminated,
            488 => Self::NotAcceptableHere,
            489 => Self::BadEvent,
            491 => Self::RequestPending,
            493 => Self::Undecipherable,
            494 => Self::SecurityAgreementRequired,
            500 => Self::ServerInternalError,
            501 => Self::NotImplemented,
            502 => Self::BadGateway,
            503 => Self::ServiceUnavailable,
            504 => Self::ServerTimeOut,
            505 => Self::VersionNotSupported,
            513 => Self::MessageTooLarge,
            580 => Self::PreconditionFailure,
            600 => Self::BusyEverywhere,
            603 => Self::Decline,
            604 => Self::DoesNotExistAnywhere,
            606 => Self::NotAcceptableGlobal,
            607 => Self::Unwanted,
            c => Self::Other(c, reason.to_string()),
        }
    }
}

impl Default for StatusCode {
    fn default() -> Self {
        Self::OK
    }
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        Self::from_code(code, "Other")
    }
}

impl From<StatusCode> for u16 {
    fn from(s: StatusCode) -> u16 {
        s.code()
    }
}

impl std::convert::TryFrom<(u16, &str)> for StatusCode {
    type Error = Error;
    fn try_from((code, reason): (u16, &str)) -> Result<Self, Self::Error> {
        Ok(Self::from_code(code, reason))
    }
}

impl std::convert::TryFrom<(&str, &str)> for StatusCode {
    type Error = Error;
    fn try_from((code_str, reason): (&str, &str)) -> Result<Self, Self::Error> {
        let code: u16 = code_str.trim().parse()?;
        Ok(Self::from_code(code, reason))
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code(), self.text())
    }
}

#[cfg(test)]
mod tests {
    use super::StatusCode;

    #[test]
    fn accepted_status_code_is_202() {
        assert_eq!(StatusCode::Accepted.code(), 202);
        assert_eq!(
            StatusCode::try_from((202_u16, "Accepted")).unwrap(),
            StatusCode::Accepted
        );
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone, Copy)]
pub enum StatusCodeKind {
    Provisional,
    Successful,
    Redirection,
    RequestFailure,
    ServerFailure,
    GlobalFailure,
    Other,
}
