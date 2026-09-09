use super::parse_helpers::parse_display_uri_params_str;
use crate::sip::{uri::Param, Error, Header, Uri};

/// A single `hi-entry` of the History-Info header (RFC 7044 §5).
///
/// The Reason and Privacy "parameters" are not hi-params: they are carried in
/// the URI-headers component of `hi-targeted-to-uri`
/// (e.g. `<sip:x@y?Reason=SIP%3Bcause%3D486>;index=1.1`), which is preserved
/// by [`Uri`]'s `headers` field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HistoryInfoEntry {
    pub uri: Uri,
    /// Mandatory `index` hi-param (`1`, `1.1`, `1.2.1`, ...).
    pub index: String,
    /// `rc=<index>` — retarget within the same target user (alias).
    pub rc: Option<String>,
    /// `mp=<index>` — mapped to a different user.
    pub mp: Option<String>,
    /// `np=<index>` — no change of Request-URI (loose-route forward).
    pub np: Option<String>,
    /// Any other (future) hi-extension params, kept verbatim.
    pub ext: Vec<Param>,
}

/// Typed History-Info header: one or more hi-entries (RFC 7044).
///
/// Entries may arrive comma-joined inside a single header line or spread over
/// multiple header lines; [`crate::sip::prelude::HeadersExt::history_info_headers`]
/// exposes every header line and [`Self::parse`] splits comma-joined entries.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HistoryInfo {
    pub entries: Vec<HistoryInfoEntry>,
}

fn split_hi_entries(s: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut angle_depth = 0usize;
    let mut in_quotes = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '<' if !in_quotes => {
                angle_depth += 1;
                current.push(ch);
            }
            '>' if !in_quotes => {
                angle_depth = angle_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if !in_quotes && angle_depth == 0 => {
                let v = current.trim().to_string();
                if !v.is_empty() {
                    values.push(v);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let v = current.trim().to_string();
    if !v.is_empty() {
        values.push(v);
    }
    values
}

fn param_value(params: &[Param], key: &str) -> Option<String> {
    params.iter().find_map(|p| match p {
        Param::Other(n, v) if n.value().eq_ignore_ascii_case(key) => {
            v.as_ref().map(|t| t.value().to_string())
        }
        _ => None,
    })
}

impl HistoryInfoEntry {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (_, uri, params) = parse_display_uri_params_str(s)?;
        let mut entry = HistoryInfoEntry {
            uri,
            index: param_value(&params, "index").ok_or_else(|| {
                Error::ParseError(format!("History-Info entry missing index: {s}"))
            })?,
            rc: param_value(&params, "rc"),
            mp: param_value(&params, "mp"),
            np: param_value(&params, "np"),
            ext: Vec::new(),
        };
        for p in params {
            if let Param::Other(n, _) = &p {
                let name = n.value();
                if name.eq_ignore_ascii_case("index")
                    || name.eq_ignore_ascii_case("rc")
                    || name.eq_ignore_ascii_case("mp")
                    || name.eq_ignore_ascii_case("np")
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
}

impl HistoryInfo {
    /// Parse a (possibly comma-joined) History-Info header value.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let entries = split_hi_entries(s)
            .into_iter()
            .map(|v| HistoryInfoEntry::parse(&v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    /// Build from entries.
    pub fn from_entries(entries: Vec<HistoryInfoEntry>) -> Self {
        Self { entries }
    }

    /// Sort entries by their hierarchical index (preorder of the retargeting
    /// tree), as required when forwarding (RFC 7044 §9.2).
    pub fn sort(&mut self) {
        self.entries
            .sort_by(|a, b| compare_index(&a.index, &b.index));
    }
}

/// Lexicographic comparison of dot-separated index values (numeric per level),
/// e.g. `1.2` < `1.10`, `1.2.1` > `1.2`.
fn compare_index(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| p.trim().parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (av, bv) = (parse(a), parse(b));
    for (x, y) in av.iter().zip(bv.iter()) {
        match x.cmp(y) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    av.len().cmp(&bv.len())
}

impl std::fmt::Display for HistoryInfoEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>;index={}", self.uri, self.index)?;
        if let Some(rc) = &self.rc {
            write!(f, ";rc={}", rc)?;
        }
        if let Some(mp) = &self.mp {
            write!(f, ";mp={}", mp)?;
        }
        if let Some(np) = &self.np {
            write!(f, ";np={}", np)?;
        }
        for p in &self.ext {
            write!(f, "{}", p)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for HistoryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let items = self
            .entries
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", items)
    }
}

impl std::convert::From<HistoryInfo> for String {
    fn from(h: HistoryInfo) -> String {
        h.to_string()
    }
}

impl std::convert::From<HistoryInfo> for Header {
    fn from(h: HistoryInfo) -> Header {
        Header::HistoryInfo(crate::sip::headers::HistoryInfo::new(h.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for HistoryInfo {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_entry() {
        let h = HistoryInfo::parse("<sip:bob@biloxi.example.com>;index=1").unwrap();
        assert_eq!(h.entries.len(), 1);
        assert_eq!(h.entries[0].index, "1");
        assert_eq!(h.entries[0].uri.to_string(), "sip:bob@biloxi.example.com");
        assert!(h.entries[0].rc.is_none());
        assert!(h.entries[0].ext.is_empty());
    }

    #[test]
    fn parse_comma_joined_with_rc_mp_params() {
        let h = HistoryInfo::parse(
            "<sip:UserA@ims.example.com?Reason=SIP%3Bcause%3D302>;index=1.1,\
             <sip:UserB@example.com?Privacy=history&Reason=SIP%3Bcause%3D486>;index=1.2;mp=1.1,\
             <sip:45432@192.168.0.3>;index=1.3;rc=1.2",
        )
        .unwrap();
        assert_eq!(h.entries.len(), 3);
        // Reason/Privacy live in the URI-headers component, not hi-params.
        assert_eq!(h.entries[0].uri.headers.len(), 1);
        assert_eq!(h.entries[0].uri.headers[0].0, "Reason");
        assert_eq!(h.entries[1].mp.as_deref(), Some("1.1"));
        assert_eq!(h.entries[2].rc.as_deref(), Some("1.2"));
        assert!(h.entries[2].mp.is_none());
    }

    #[test]
    fn parse_np_param() {
        let h = HistoryInfo::parse("<sip:bob@example.com>;np=1;index=1.1").unwrap();
        assert_eq!(h.entries[0].np.as_deref(), Some("1"));
        assert_eq!(h.entries[0].index, "1.1");
    }

    #[test]
    fn missing_index_is_error() {
        assert!(HistoryInfo::parse("<sip:bob@example.com>").is_err());
    }

    #[test]
    fn display_roundtrip() {
        let s = "<sip:UserA@ims.example.com?Reason=SIP%3Bcause%3D302>;index=1.1,\
                 <sip:UserB@example.com>;index=1.2;mp=1.1";
        let h = HistoryInfo::parse(s).unwrap();
        let h2 = HistoryInfo::parse(&h.to_string()).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn unknown_ext_params_preserved() {
        let h = HistoryInfo::parse("<sip:a@example.com>;index=1;foo=bar").unwrap();
        assert_eq!(h.entries[0].ext.len(), 1);
        assert!(h.to_string().contains("foo=bar"));
    }

    #[test]
    fn index_sorting() {
        let mut h = HistoryInfo::parse(
            "<sip:c@example.com>;index=1.10,<sip:a@example.com>;index=1,<sip:b@example.com>;index=1.2",
        )
        .unwrap();
        h.sort();
        assert_eq!(h.entries[0].index, "1");
        assert_eq!(h.entries[1].index, "1.2");
        assert_eq!(h.entries[2].index, "1.10");
    }

    #[test]
    fn tel_uri_entry() {
        let h = HistoryInfo::parse("<tel:+15551234567>;index=1.1").unwrap();
        assert_eq!(h.entries[0].index, "1.1");
    }
}
