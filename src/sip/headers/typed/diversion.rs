use super::parse_helpers::{param_value, parse_display_uri_params_str, split_comma_entries};
use crate::prelude::*;
use crate::sip::{uri::Param, Error, Header, Uri};

/// `reason` diversion-param values (RFC 5806 §4).
///
/// The wire value of [`DiversionReason::UserBusy`] is `user-busy`; the bare
/// `busy` form seen in the wild is accepted when parsing and canonicalized on
/// output. Non-standard values are preserved verbatim in
/// [`DiversionReason::Other`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DiversionReason {
    Unknown,
    UserBusy,
    NoAnswer,
    Redirected,
    Unconditional,
    TimeOfDay,
    Deflection,
    FollowMe,
    OutOfService,
    Away,
    Other(String),
}

impl DiversionReason {
    pub fn parse(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase();
        match lower.as_str() {
            "unknown" => Self::Unknown,
            "user-busy" | "busy" => Self::UserBusy,
            "no-answer" => Self::NoAnswer,
            "redirected" => Self::Redirected,
            "unconditional" => Self::Unconditional,
            "time-of-day" => Self::TimeOfDay,
            "deflection" => Self::Deflection,
            "follow-me" => Self::FollowMe,
            "out-of-service" => Self::OutOfService,
            "away" => Self::Away,
            _ => Self::Other(lower),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown => "unknown",
            Self::UserBusy => "user-busy",
            Self::NoAnswer => "no-answer",
            Self::Redirected => "redirected",
            Self::Unconditional => "unconditional",
            Self::TimeOfDay => "time-of-day",
            Self::Deflection => "deflection",
            Self::FollowMe => "follow-me",
            Self::OutOfService => "out-of-service",
            Self::Away => "away",
            Self::Other(v) => v.as_str(),
        }
    }
}

impl core::fmt::Display for DiversionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single diversion entry of the Diversion header (RFC 5806).
///
/// ```text
/// Diversion: <sip: diverted@example.com;reason=no-answer;counter=1;privacy=off>
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DiversionEntry {
    /// The diverting party (the party towards which the call was diverted at
    /// this hop — i.e. the original destination before retargeting).
    pub uri: Uri,
    pub reason: Option<DiversionReason>,
    /// `counter` — number of redirections this address has already gone
    /// through, counted from 1.
    pub counter: Option<u32>,
    /// `privacy` — `full` / `off` (kept as string for forward compatibility).
    pub privacy: Option<String>,
    /// Any other (future) diversion params, kept verbatim.
    pub ext: Vec<Param>,
}

/// Typed Diversion header: one or more diversion entries (RFC 5806).
///
/// Entries may arrive comma-joined inside a single header line or spread over
/// multiple header lines; [`crate::sip::prelude::HeadersExt::diversion_headers`]
/// exposes every header line and [`Self::parse`] splits comma-joined entries.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Diversion {
    pub entries: Vec<DiversionEntry>,
}

impl DiversionEntry {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (_, uri, params) = parse_display_uri_params_str(s)?;
        let counter = param_value(&params, "counter").and_then(|v| v.parse::<u32>().ok());
        let mut entry = DiversionEntry {
            uri,
            reason: param_value(&params, "reason").map(|v| DiversionReason::parse(&v)),
            counter,
            privacy: param_value(&params, "privacy"),
            ext: Vec::new(),
        };
        for p in params {
            if let Param::Other(n, _) = &p {
                let name = n.value();
                if name.eq_ignore_ascii_case("reason")
                    || name.eq_ignore_ascii_case("counter")
                    || name.eq_ignore_ascii_case("privacy")
                {
                    continue;
                }
            }
            entry.ext.push(p);
        }
        Ok(entry)
    }

    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.uri = uri;
        self
    }

    pub fn with_reason(mut self, reason: DiversionReason) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_counter(mut self, counter: u32) -> Self {
        self.counter = Some(counter);
        self
    }

    pub fn with_privacy(mut self, privacy: impl Into<String>) -> Self {
        self.privacy = Some(privacy.into());
        self
    }
}

impl Diversion {
    /// Parse a (possibly comma-joined) Diversion header value.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let entries = split_comma_entries(s)
            .into_iter()
            .map(|v| DiversionEntry::parse(&v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    /// Build from entries.
    pub fn from_entries(entries: Vec<DiversionEntry>) -> Self {
        Self { entries }
    }
}

impl core::fmt::Display for DiversionEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{}>", self.uri)?;
        if let Some(reason) = &self.reason {
            write!(f, ";reason={}", reason)?;
        }
        if let Some(counter) = &self.counter {
            write!(f, ";counter={}", counter)?;
        }
        if let Some(privacy) = &self.privacy {
            write!(f, ";privacy={}", privacy)?;
        }
        for p in &self.ext {
            write!(f, "{}", p)?;
        }
        Ok(())
    }
}

impl core::fmt::Display for Diversion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let items = self
            .entries
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", items)
    }
}

impl core::convert::From<Diversion> for String {
    fn from(h: Diversion) -> String {
        h.to_string()
    }
}

impl core::convert::From<Diversion> for Header {
    fn from(h: Diversion) -> Header {
        Header::Diversion(crate::sip::headers::Diversion::new(h.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for Diversion {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_entry() {
        let h = Diversion::parse("<sip:diverted@bcn.example.com>").unwrap();
        assert_eq!(h.entries.len(), 1);
        assert_eq!(h.entries[0].uri.to_string(), "sip:diverted@bcn.example.com");
        assert!(h.entries[0].reason.is_none());
        assert!(h.entries[0].counter.is_none());
        assert!(h.entries[0].privacy.is_none());
        assert!(h.entries[0].ext.is_empty());
    }

    #[test]
    fn parse_with_params() {
        let h = Diversion::parse(
            "<sip:22334459@bcn.example.com>;reason=no-answer;counter=1;privacy=full",
        )
        .unwrap();
        let e = &h.entries[0];
        assert_eq!(e.reason.as_ref(), Some(&DiversionReason::NoAnswer));
        assert_eq!(e.counter, Some(1));
        assert_eq!(e.privacy.as_deref(), Some("full"));
    }

    #[test]
    fn parse_comma_joined_entries() {
        let h = Diversion::parse(
            "<sip:first@example.com>;reason=unconditional;counter=1,\
             <sip:second@example.com>;reason=user-busy;counter=2",
        )
        .unwrap();
        assert_eq!(h.entries.len(), 2);
        assert_eq!(
            h.entries[0].reason.as_ref(),
            Some(&DiversionReason::Unconditional)
        );
        assert_eq!(
            h.entries[1].reason.as_ref(),
            Some(&DiversionReason::UserBusy)
        );
        assert_eq!(h.entries[1].counter, Some(2));
    }

    #[test]
    fn legacy_busy_canonicalized() {
        let h = Diversion::parse("<sip:a@example.com>;reason=busy").unwrap();
        assert_eq!(
            h.entries[0].reason.as_ref(),
            Some(&DiversionReason::UserBusy)
        );
        assert!(h.to_string().contains("reason=user-busy"));
    }

    #[test]
    fn unknown_reason_preserved() {
        let h = Diversion::parse("<sip:a@example.com>;reason=deflection-cfvl").unwrap();
        assert_eq!(
            h.entries[0].reason.as_ref(),
            Some(&DiversionReason::Other("deflection-cfvl".into()))
        );
        assert!(h.to_string().contains("reason=deflection-cfvl"));
    }

    #[test]
    fn all_standard_reasons() {
        for (wire, expected) in [
            ("unknown", DiversionReason::Unknown),
            ("user-busy", DiversionReason::UserBusy),
            ("no-answer", DiversionReason::NoAnswer),
            ("redirected", DiversionReason::Redirected),
            ("unconditional", DiversionReason::Unconditional),
            ("time-of-day", DiversionReason::TimeOfDay),
            ("deflection", DiversionReason::Deflection),
            ("follow-me", DiversionReason::FollowMe),
            ("out-of-service", DiversionReason::OutOfService),
            ("away", DiversionReason::Away),
        ] {
            let h = Diversion::parse(&format!("<sip:a@example.com>;reason={}", wire)).unwrap();
            assert_eq!(h.entries[0].reason, Some(expected));
        }
    }

    #[test]
    fn ext_params_preserved() {
        let h = Diversion::parse("<sip:a@example.com>;reason=no-answer;foo=bar").unwrap();
        assert_eq!(h.entries[0].ext.len(), 1);
        assert!(h.to_string().contains("foo=bar"));
    }

    #[test]
    fn display_roundtrip() {
        let s = "<sip:first@example.com>;reason=unconditional;counter=1;privacy=off,\
                 <sip:second@example.com>;reason=no-answer;counter=2;privacy=full";
        let h = Diversion::parse(s).unwrap();
        let h2 = Diversion::parse(&h.to_string()).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn tel_uri_entry() {
        let h = Diversion::parse("<tel:+15551234567>;reason=user-busy").unwrap();
        assert_eq!(h.entries[0].uri.to_string(), "tel:+15551234567");
        assert_eq!(h.entries[0].reason, Some(DiversionReason::UserBusy));
    }

    #[test]
    fn builder_helpers() {
        use crate::sip::uri::parse_uri;
        let e = DiversionEntry::parse("<sip:bob@example.com>")
            .unwrap()
            .with_reason(DiversionReason::NoAnswer)
            .with_counter(1)
            .with_privacy("off");
        assert_eq!(
            e.to_string(),
            "<sip:bob@example.com>;reason=no-answer;counter=1;privacy=off"
        );
        // uri parse path used by tests for completeness
        assert!(parse_uri("sip:bob@example.com").is_ok());
    }
}
