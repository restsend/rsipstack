//! SIP event-package / companion body parsers (lenient dialects), ported
//! from restsend-call: REFER targets, PIDF, dialog-info (BLF),
//! simple-message-summary (MWI) and INFO-carried DTMF. Pure `no_std` + alloc.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Decode `%XX` escapes (invalid escapes pass through).
///
/// Byte-wise on purpose: the input comes from untrusted SIP headers, and
/// slicing `raw` as a `str` could panic on a `%` followed by multi-byte
/// UTF-8 (`"%€"`).
pub fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// ASCII-case-insensitive byte offset of `needle` in `s`.
///
/// XML helpers must search without lowercasing a copy of the input:
/// `str::to_lowercase` can change byte lengths (`İ` grows), which would
/// shift every offset derived from the copy away from the original.
fn find_ascii_ci(s: &str, needle: &str) -> Option<usize> {
    let (h, n) = (s.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferToTarget {
    pub uri: String,
    /// Decoded RFC 3891 Replaces value (`call-id;to-tag=…;from-tag=…`).
    pub replaces: Option<String>,
}

/// Parse `<sip:1003@pbx?Replaces=…>` (display-name noise before `<` tolerated).
pub fn parse_refer_to(value: &str) -> ReferToTarget {
    let s = value.trim();
    let inner = if let Some(lt) = s.find('<') {
        let rest = &s[lt + 1..];
        match rest.find('>') {
            Some(gt) => rest[..gt].trim().to_string(),
            None => rest.trim().to_string(),
        }
    } else {
        s.to_string()
    };
    let (uri_part, query) = match inner.split_once('?') {
        Some((u, q)) => (u.trim().to_string(), q.to_string()),
        None => (inner, String::new()),
    };
    let replaces = query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        k.eq_ignore_ascii_case("replaces")
            .then(|| percent_decode(v.trim()))
    });
    ReferToTarget {
        uri: uri_part,
        replaces: replaces.filter(|r| !r.is_empty()),
    }
}

/// First `<note>…</note>` text of a PIDF body.
pub fn pidf_note(body: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(body).ok()?;
    let start = s.find("<note")?;
    let open_end = s[start..].find('>')? + start + 1;
    let close = s[open_end..].find("</note>")? + open_end;
    let text = s[open_end..close].trim();
    (!text.is_empty()).then(|| String::from(text))
}

/// First `<basic>…</basic>` value of a PIDF body (`open` / `closed`).
pub fn pidf_basic(body: &[u8]) -> Option<String> {
    xml_tag_text(&String::from_utf8_lossy(body), "basic").filter(|t| !t.is_empty())
}

#[derive(Debug, Clone, PartialEq)]
pub struct DialogInfoState {
    pub state: String,
    pub direction: Option<String>,
    pub remote_uri: Option<String>,
    pub remote_name: Option<String>,
}

/// Lenient RFC 4235 `dialog-info` parse; no `<dialog>` element = idle.
pub fn parse_dialog_info(body: &[u8]) -> Option<DialogInfoState> {
    let s = String::from_utf8_lossy(body).into_owned();
    let Some(dstart) = find_dialog_element(&s) else {
        return find_ascii_ci(&s, "dialog-info").map(|_| DialogInfoState {
            state: String::from("idle"),
            direction: None,
            remote_uri: None,
            remote_name: None,
        });
    };
    let dend = s[dstart..]
        .find("</dialog>")
        .map(|i| i + dstart)
        .unwrap_or(s.len());
    let block = &s[dstart..dend];

    let raw_state = xml_tag_text(block, "state").unwrap_or_default();
    let state = match raw_state.to_lowercase().as_str() {
        "" | "terminated" => String::from("idle"),
        "early" | "trying" | "call-processing" | "progress" | "proceeding" => String::from("early"),
        "confirmed" => String::from("confirmed"),
        other => String::from(other),
    };
    let open_tag_end = block.find('>').unwrap_or(block.len());
    let direction = xml_attr(&block[..open_tag_end], "direction");

    let remote = find_ascii_ci(block, "<remote").map(|i| {
        let rest = &block[i..];
        let id_start = find_ascii_ci(rest, "<identity").unwrap_or(0);
        let id_end = find_ascii_ci(&rest[id_start..], "</identity>")
            .map(|j| j + id_start + "</identity>".len())
            .unwrap_or(rest.len());
        let id_elem = &rest[id_start..id_end];
        (
            xml_attr(id_elem, "uri")
                .or_else(|| xml_tag_text(id_elem, "identity"))
                .filter(|t| !t.is_empty()),
            xml_tag_text(id_elem, "identity").filter(|t| !t.is_empty()),
        )
    });
    let (remote_uri, remote_name) = remote.unwrap_or((None, None));

    Some(DialogInfoState {
        state,
        direction,
        remote_uri,
        remote_name,
    })
}

/// `<dialog` as an ELEMENT (not the `dialog-info` root tag).
fn find_dialog_element(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = find_ascii_ci(&s[from..], "<dialog") {
        let abs = from + i;
        match s[abs + 7..].chars().next() {
            Some(c) if c.is_whitespace() || c == '>' => return Some(abs),
            _ => from = abs + 7,
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageSummary {
    pub messages_waiting: bool,
    pub new_messages: i32,
    pub old_messages: i32,
    pub account: Option<String>,
}

/// Lenient RFC 3842 `simple-message-summary` parse.
pub fn parse_message_summary(body: &[u8]) -> Option<MessageSummary> {
    let s = core::str::from_utf8(body).ok()?;
    let mut waiting: Option<bool> = None;
    let mut account: Option<String> = None;
    let (mut new_msgs, mut old_msgs) = (0i32, 0i32);
    for line in s.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        match key.as_str() {
            "messages-waiting" => waiting = Some(value.eq_ignore_ascii_case("yes")),
            "message-account" => account = Some(String::from(value)).filter(|v| !v.is_empty()),
            "voice-message" => {
                let mut it = value.split('(').next().unwrap_or(value).split('/');
                new_msgs = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
                old_msgs = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
            }
            _ => {}
        }
    }
    if waiting.is_none() && account.is_none() && new_msgs == 0 && old_msgs == 0 {
        return None;
    }
    Some(MessageSummary {
        messages_waiting: waiting.unwrap_or(new_msgs > 0),
        new_messages: new_msgs,
        old_messages: old_msgs,
        account,
    })
}

/// Parse `application/dtmf-relay` / `application/dtmf`; RFC 4733 event code.
pub fn parse_info_dtmf(content_type: Option<&str>, body: &[u8]) -> Option<u8> {
    let ct = content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct != "application/dtmf-relay" && ct != "application/dtmf" {
        return None;
    }
    let text = core::str::from_utf8(body).ok()?;
    for line in text.lines() {
        for part in line.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                if key.eq_ignore_ascii_case("signal") || key.eq_ignore_ascii_case("digit") {
                    return dtmf_char_code(value.trim());
                }
            }
        }
    }
    let trimmed = text.trim();
    (trimmed.len() == 1)
        .then(|| dtmf_char_code(trimmed))
        .flatten()
}

/// DTMF character (`0-9`, `*`, `#`, `A-D`) → RFC 4733 event code.
pub fn dtmf_char_code(s: &str) -> Option<u8> {
    let c = s.chars().next()?;
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        'A'..='D' | 'a'..='d' => Some(c.to_ascii_uppercase() as u8 - b'A' + 12),
        _ => None,
    }
}

/// Inner text of the first `<tag …>…</tag>` (case-insensitive, attributes ok).
fn xml_tag_text(s: &str, tag: &str) -> Option<String> {
    let open = find_ascii_ci(s, &alloc::format!("<{tag}"))?;
    let gt = open + s[open..].find('>')?;
    if s.as_bytes()[gt - 1] == b'/' {
        return Some(String::new());
    }
    let close = find_ascii_ci(&s[gt..], &alloc::format!("</{tag}>"))? + gt;
    Some(String::from(s[gt + 1..close].trim()))
}

/// `attr="value"` (or single quotes) from a fragment.
fn xml_attr(fragment: &str, attr: &str) -> Option<String> {
    let needle = alloc::format!("{attr}=");
    let start = find_ascii_ci(fragment, &needle)? + needle.len();
    let quote = fragment.as_bytes().get(start).copied()?;
    let (q, skip) = match quote {
        b'"' | b'\'' => (quote as char, 1),
        _ => (' ', 0),
    };
    let rest = &fragment[start + skip..];
    let end = if skip == 1 {
        rest.find(q)?
    } else {
        rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/')?
    };
    Some(String::from(rest[..end].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("abc"), "abc");
        assert_eq!(percent_decode("a%40b"), "a@b");
        assert_eq!(percent_decode("a%2Fb%3bc"), "a/b;c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn refer_to_with_replaces_query() {
        let t = parse_refer_to("<sip:1003@pbx?Replaces=call-id%40pbx%3Bto-tag%3Dx%3Bfrom-tag%3Dy>");
        assert_eq!(t.uri, "sip:1003@pbx");
        assert_eq!(
            t.replaces.as_deref(),
            Some("call-id@pbx;to-tag=x;from-tag=y")
        );
    }

    #[test]
    fn refer_to_plain_and_noisy() {
        let t = parse_refer_to("<sip:1003@pbx>");
        assert_eq!(t.uri, "sip:1003@pbx");
        assert_eq!(t.replaces, None);
        let t = parse_refer_to("Agent <sip:1003@pbx>;x=y");
        assert_eq!(t.uri, "sip:1003@pbx");
        assert_eq!(parse_refer_to("sip:1004@pbx").uri, "sip:1004@pbx");
    }

    #[test]
    fn pidf_note_and_basic() {
        let body = br#"<?xml version="1.0"?><presence><tuple id="a"><status><basic>open</basic></status></tuple><note>ready</note></presence>"#;
        assert_eq!(pidf_note(body).as_deref(), Some("ready"));
        assert_eq!(pidf_basic(body).as_deref(), Some("open"));
        assert_eq!(pidf_note(b"<presence/>"), None);
    }

    #[test]
    fn dialog_info_confirmed_with_identity() {
        let body = br#"<?xml version="1.0"?><dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="1" state="full"><dialog id="a" call-id="c" direction="initiator"><state>confirmed</state><remote><target uri="sip:b@pbx"/><identity uri="sip:1002@pbx">Bob</identity></remote></dialog></dialog-info>"#;
        let d = parse_dialog_info(body).unwrap();
        assert_eq!(d.state, "confirmed");
        assert_eq!(d.direction.as_deref(), Some("initiator"));
        assert_eq!(d.remote_uri.as_deref(), Some("sip:1002@pbx"));
        assert_eq!(d.remote_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn dialog_info_empty_is_idle() {
        let body = br#"<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="2" state="full"></dialog-info>"#;
        assert_eq!(parse_dialog_info(body).unwrap().state, "idle");
        assert!(parse_dialog_info(b"<other/>").is_none());
    }

    #[test]
    fn dialog_info_vendor_states_normalize() {
        let body = br#"<dialog-info><dialog><state>proceeding</state></dialog></dialog-info>"#;
        assert_eq!(parse_dialog_info(body).unwrap().state, "early");
        let body = br#"<dialog-info><dialog><state>terminated</state></dialog></dialog-info>"#;
        assert_eq!(parse_dialog_info(body).unwrap().state, "idle");
    }

    #[test]
    fn message_summary_parses() {
        let body = b"Messages-Waiting: yes\r\nMessage-Account: sip:1001@pbx\r\nVoice-Message: 2/1 (2/1)\r\n";
        let m = parse_message_summary(body).unwrap();
        assert!(m.messages_waiting);
        assert_eq!(m.new_messages, 2);
        assert_eq!(m.old_messages, 1);
        assert_eq!(m.account.as_deref(), Some("sip:1001@pbx"));
        let m = parse_message_summary(b"Voice-Message: 3/4 (5/6)\r\n").unwrap();
        assert_eq!((m.new_messages, m.old_messages), (3, 4));
        assert!(parse_message_summary(b"nothing: here\r\n").is_none());
    }

    #[test]
    fn info_dtmf_dialects() {
        assert_eq!(
            parse_info_dtmf(
                Some("application/dtmf-relay"),
                b"Signal=5\r\nDuration=160\r\n"
            ),
            Some(5)
        );
        assert_eq!(
            parse_info_dtmf(Some("application/dtmf-relay"), b"Signal=#\nDuration=100"),
            Some(11)
        );
        assert_eq!(
            parse_info_dtmf(Some("application/dtmf"), b"Digit=8"),
            Some(8)
        );
        assert_eq!(parse_info_dtmf(Some("application/dtmf"), b"A"), Some(12));
        assert_eq!(parse_info_dtmf(Some("text/plain"), b"Signal=5"), None);
        assert_eq!(parse_info_dtmf(None, b"Signal=5"), None);
    }

    #[test]
    fn dtmf_char_code_table() {
        assert_eq!(dtmf_char_code("0"), Some(0));
        assert_eq!(dtmf_char_code("9"), Some(9));
        assert_eq!(dtmf_char_code("*"), Some(10));
        assert_eq!(dtmf_char_code("#"), Some(11));
        assert_eq!(dtmf_char_code("d"), Some(15));
        assert_eq!(dtmf_char_code("x"), None);
    }

    #[test]
    fn xml_tag_text_edge_shapes() {
        assert_eq!(
            xml_tag_text("<BASIC>closed</BASIC>", "basic").as_deref(),
            Some("closed")
        );
        assert_eq!(xml_tag_text("<basic/>", "basic").as_deref(), Some(""));
        assert_eq!(
            xml_tag_text(r#"<state code="1">early</state>"#, "state").as_deref(),
            Some("early")
        );
    }

    #[test]
    fn percent_decode_never_panics_on_multibyte() {
        // A `%` followed by multi-byte UTF-8 must pass through untouched,
        // not panic on a non-char-boundary `str` slice.
        assert_eq!(percent_decode("%€"), "%€");
        assert_eq!(percent_decode("100%Ä"), "100%Ä");
        // Valid escapes still decode, including into multi-byte output.
        assert_eq!(percent_decode("%E2%82%AC"), "€");
        assert_eq!(percent_decode("a%C3%A9b"), "aéb");
    }

    #[test]
    fn xml_helpers_ignore_case_without_lowercasing_offsets() {
        // `İ` grows when lowercased; offset math on the lowercased copy
        // used to return garbage ("n</b").
        assert_eq!(
            pidf_basic("İİİ<basic>open</basic>".as_bytes()).as_deref(),
            Some("open")
        );
        assert_eq!(
            pidf_note("İ<note>ready</note>".as_bytes()).as_deref(),
            Some("ready")
        );
    }

    #[test]
    fn dialog_info_tolerates_non_ascii_before_elements() {
        let body = "İ<dialog-info><dialog direction=\"initiator\"><state>confirmed</state><remote><identity uri=\"sip:1002@pbx\">Bob</identity></remote></dialog></dialog-info>".as_bytes();
        let d = parse_dialog_info(body).expect("must parse");
        assert_eq!(d.state, "confirmed");
        assert_eq!(d.direction.as_deref(), Some("initiator"));
        assert_eq!(d.remote_uri.as_deref(), Some("sip:1002@pbx"));
        assert_eq!(d.remote_name.as_deref(), Some("Bob"));
    }
}
