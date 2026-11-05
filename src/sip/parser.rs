use crate::prelude::*;
use crate::sip::{
    headers::{make_header, Headers},
    message::{Request, Response, SipMessage},
    uri::parse_uri,
    Error, HasHeaders, Header, Method, StatusCode, Uri, Version,
};
use memchr::{memchr, memmem};
/// Parse one complete message-oriented packet. Without Content-Length, all
/// remaining octets are the body (RFC 3261 §18.3). Stream transports must frame
/// their input using Content-Length before calling this function.
///
/// Invalid framing is rejected, including duplicate Content-Length headers
/// (RFC 4475 §3.3.9). Datagram transports answer such requests with 400 from
/// their parsed header block, while stream framing closes the connection.
pub fn parse_message(data: &[u8]) -> Result<SipMessage, Error> {
    let (mut message, body_start) = parse_message_head(data)?;
    let available = data.len() - body_start;
    let length = content_length(message.headers())?.unwrap_or(available);
    if length > available {
        return Err(Error::ParseError("SIP message: truncated body".into()));
    }
    let body = data[body_start..body_start + length].to_vec();
    match &mut message {
        SipMessage::Request(r) => r.body = body,
        SipMessage::Response(r) => r.body = body,
    }
    Ok(message)
}

/// Shared by datagram parsing and stream framing; absence is distinct from zero.
pub(crate) fn content_length(headers: &Headers) -> Result<Option<usize>, Error> {
    let mut length = None;
    for header in headers.iter() {
        if let Header::ContentLength(value) = header {
            if length.is_some() {
                return Err(Error::ParseError(
                    "SIP message: duplicate Content-Length".into(),
                ));
            }
            let value = value.value().trim();
            // RFC 3261 §25.1: 1*DIGIT, not a signed Rust integer.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::ParseError(
                    "SIP message: invalid Content-Length".into(),
                ));
            }
            length = Some(value.parse::<usize>()?);
        }
    }
    Ok(length)
}

/// Parse only the start line and headers, never an incomplete body. UDP may use
/// these headers to answer a framing error; they must not reach the application.
pub(crate) fn parse_message_head(data: &[u8]) -> Result<(SipMessage, usize), Error> {
    let sep = find_double_crlf(data)
        .ok_or_else(|| Error::ParseError("SIP message: missing \\r\\n\\r\\n separator".into()))?;

    let header_section = &data[..sep];
    let body_start = sep + 4;

    let mut lines = split_crlf_lines(header_section);
    let start_line = lines
        .next()
        .ok_or_else(|| Error::ParseError("SIP message: empty start line".into()))?;

    let mut headers = Headers::default();
    let mut pending: Option<(String, String)> = None;

    for line in lines {
        if line.is_empty() {
            break;
        }

        if line.as_bytes()[0] == b' ' || line.as_bytes()[0] == b'\t' {
            if let Some((_, ref mut val)) = pending {
                if val.len() > 4096 {
                    tracing::warn!(
                        len = val.len(),
                        "parser: folded header value exceeds 4 KiB — likely misframed stream"
                    );
                }
                val.push(' ');
                val.push_str(line.trim());
            }
            continue;
        }

        if let Some((name, val)) = pending.take() {
            headers.push(make_header(&name, val));
        }

        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let val = line[colon + 1..].trim().to_string();
            pending = Some((name, val));
        }
    }

    if let Some((name, val)) = pending {
        headers.push(make_header(&name, val));
    }

    let start_str = core::str::from_utf8(start_line.as_bytes())
        .map_err(|_| Error::ParseError("SIP start line: invalid UTF-8".into()))?;

    let message = if start_str.starts_with("SIP/") {
        parse_response_line(start_str, headers, vec![])?
    } else {
        parse_request_line(start_str, headers, vec![])?
    };
    validate_message_headers(&message)?;
    Ok((message, body_start))
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
}

fn validate_via_header(s: &str) -> Result<(), Error> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::ParseError("Via: empty header".into()));
    }
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut entries = Vec::new();
    for ch in s.chars() {
        if escaped {
            escaped = false;
            current.push(ch);
            continue;
        }
        if (in_quotes || paren_depth > 0) && ch == '\\' {
            escaped = true;
            current.push(ch);
            continue;
        }
        match ch {
            '"' if paren_depth == 0 => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '(' if !in_quotes => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' if !in_quotes => {
                if paren_depth == 0 {
                    return Err(Error::ParseError("Via: unmatched ')'".into()));
                }
                paren_depth -= 1;
                current.push(ch);
            }
            ',' if !in_quotes && paren_depth == 0 => {
                let entry = current.trim();
                if entry.is_empty() {
                    return Err(Error::ParseError("Via: empty entry".into()));
                }
                entries.push(entry.to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_quotes || paren_depth != 0 {
        return Err(Error::ParseError(
            "Via: unbalanced quotes or comment".into(),
        ));
    }
    let entry = current.trim();
    if entry.is_empty() {
        return Err(Error::ParseError("Via: empty entry".into()));
    }
    entries.push(entry.to_string());

    for entry in entries {
        let mut slashes = entry.splitn(3, '/');
        let proto = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing protocol".into()))?
            .trim();
        let ver = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing version".into()))?
            .trim();
        if !proto.eq_ignore_ascii_case("SIP") || ver != "2.0" {
            return Err(Error::ParseError("Via: invalid protocol/version".into()));
        }
        let rest = slashes
            .next()
            .ok_or_else(|| Error::ParseError("Via: missing transport+host".into()))?
            .trim();
        let (transport_str, addr_and_params) = rest
            .split_once(|c: char| c.is_whitespace())
            .ok_or_else(|| Error::ParseError("Via: missing host after transport".into()))?;
        if !is_token(transport_str.trim()) {
            return Err(Error::ParseError("Via: invalid transport token".into()));
        }
        let addr_and_params = addr_and_params.trim();
        let (addr_str, params_str) = match addr_and_params.split_once(';') {
            Some((a, p)) => (a.trim(), Some(p)),
            None => (addr_and_params, None),
        };
        crate::sip::uri::HostWithPort::try_from(addr_str)?;
        if let Some(p) = params_str {
            if p.trim().is_empty() {
                return Err(Error::ParseError("Via: empty parameter".into()));
            }
            crate::sip::uri::parse_params(p)?;
        }
    }
    Ok(())
}

fn validate_message_headers(message: &SipMessage) -> Result<(), Error> {
    let request_method = match message {
        SipMessage::Request(req) => Some(&req.method),
        SipMessage::Response(_) => None,
    };
    for header in message.headers().iter() {
        match header {
            Header::Via(v) => validate_via_header(v.value())?,
            Header::From(f) => {
                crate::sip::headers::typed::From::parse(f.value())?;
            }
            Header::To(t) => {
                crate::sip::headers::typed::To::parse(t.value())?;
            }
            Header::Contact(c) => {
                crate::sip::headers::typed::Contact::parse_header_list(c.value())?;
            }
            Header::CSeq(c) => {
                let cseq = crate::sip::headers::typed::CSeq::parse(c.value())?;
                if let Some(req_method) = request_method {
                    if &cseq.method != req_method {
                        return Err(Error::ParseError(
                            "SIP message: CSeq method does not match Request-Line".into(),
                        ));
                    }
                }
            }
            Header::MaxForwards(m) => {
                m.value()
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| Error::ParseError("Max-Forwards: invalid value".into()))?;
            }
            Header::Expires(e) => {
                e.value()
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| Error::ParseError("Expires: invalid value".into()))?;
            }
            Header::RetryAfter(r) => {
                let delta = r.value().split([';', '(']).next().unwrap_or("").trim();
                delta
                    .parse::<u32>()
                    .map_err(|_| Error::ParseError("Retry-After: invalid value".into()))?;
            }
            Header::Date(d) => {
                if !d.value().trim().ends_with(" GMT") {
                    return Err(Error::ParseError("Date: must end with GMT".into()));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_request_line(line: &str, headers: Headers, body: Vec<u8>) -> Result<SipMessage, Error> {
    let mut parts = line.splitn(3, [' ', '\t']);
    let method_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing method".into()))?;
    let uri_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing URI".into()))?;
    let version_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing version".into()))?;

    if uri_str.is_empty()
        || uri_str.starts_with('<')
        || uri_str.ends_with('>')
        || uri_str.chars().any(char::is_whitespace)
    {
        return Err(Error::ParseError(
            "Request-Line: invalid Request-URI".into(),
        ));
    }
    if !version_str.eq_ignore_ascii_case("SIP/2.0") {
        return Err(Error::ParseError(
            "Request-Line: unsupported version".into(),
        ));
    }

    let method: Method = method_str.parse()?;
    let uri: Uri = parse_uri(uri_str)?;
    if !uri.headers.is_empty() || uri.scheme.is_none() {
        return Err(Error::ParseError(
            "Request-Line: invalid Request-URI".into(),
        ));
    }
    let version: Version = version_str.parse()?;

    Ok(SipMessage::Request(Request {
        method,
        uri,
        version,
        headers,
        body,
    }))
}

fn parse_response_line(line: &str, headers: Headers, body: Vec<u8>) -> Result<SipMessage, Error> {
    let mut parts = line.splitn(3, [' ', '\t']);
    let version_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Status-Line: missing version".into()))?;
    let code_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Status-Line: missing status code".into()))?;
    let reason = parts.next().unwrap_or("").trim();

    if !version_str.eq_ignore_ascii_case("SIP/2.0") {
        return Err(Error::ParseError("Status-Line: unsupported version".into()));
    }

    let version: Version = version_str.parse()?;
    let code: u16 = code_str
        .parse()
        .map_err(|_| Error::ParseError(format!("Status-Line: invalid code {:?}", code_str)))?;
    let status_code = StatusCode::try_from((code, reason))?;
    let wire_reason = wire_reason(&status_code, reason);

    Ok(SipMessage::Response(Response {
        status_code,
        wire_reason,
        version,
        headers,
        body,
    }))
}

/// The Status-Line phrase when it is not the standard text for a known code.
/// An unknown code already keeps its phrase in [`StatusCode::Other`].
fn wire_reason(status_code: &StatusCode, reason: &str) -> Option<String> {
    if reason.is_empty()
        || matches!(status_code, StatusCode::Other(..))
        || reason.eq_ignore_ascii_case(status_code.text())
    {
        return None;
    }
    Some(reason.to_string())
}

fn find_double_crlf(data: &[u8]) -> Option<usize> {
    memmem::find(data, b"\r\n\r\n")
}

fn split_crlf_lines(data: &[u8]) -> impl Iterator<Item = &str> {
    SplitCrLf { data, pos: 0 }
}

struct SplitCrLf<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for SplitCrLf<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        let rest = &self.data[start..];

        // Find '\n' with memchr, then check the preceding '\r'.
        let (end, next_pos) = if let Some(lf) = memchr(b'\n', rest) {
            let line_end = if lf > 0 && rest[lf - 1] == b'\r' {
                start + lf - 1
            } else {
                start + lf
            };
            (line_end, start + lf + 1)
        } else {
            (self.data.len(), self.data.len())
        };

        self.pos = next_pos;
        let slice = &self.data[start..end];
        core::str::from_utf8(slice).ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::sip::SipMessage;
    #[test]
    fn parser_keeps_body_with_colons_intact() {
        let message: SipMessage = concat!(
            "INVITE sip:bob@restsend.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP restsend.com:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:alice@restsend.com>;tag=123\r\n",
            "To: <sip:bob@restsend.com>\r\n",
            "Call-ID: call-id-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: 26\r\n",
            "\r\n",
            "a=rtcp:4000 IN IP4 1.2.3.4"
        )
        .try_into()
        .unwrap();

        match message {
            SipMessage::Request(request) => {
                assert_eq!(
                    String::from_utf8(request.body).unwrap(),
                    "a=rtcp:4000 IN IP4 1.2.3.4"
                );
            }
            SipMessage::Response(_) => panic!("expected request"),
        }
    }

    fn parse_request_line(request_line: &str) -> Result<SipMessage, crate::sip::Error> {
        let method = request_line.split_whitespace().next().unwrap_or("BYE");
        let raw = format!(
            "{request_line}\r\nVia: SIP/2.0/UDP a.example:5060;branch=z9hG4bK-1\r\n\
             From: <sip:a@a.example>;tag=1\r\nTo: <sip:b@b.example>;tag=2\r\n\
             Call-ID: c1\r\nCSeq: 2 {method}\r\nContent-Length: 0\r\n\r\n"
        );
        SipMessage::try_from(raw.as_str())
    }

    #[test]
    fn a_request_without_a_request_uri_host_is_rejected() {
        for line in [
            "BYE  SIP/2.0",
            "BYE \t SIP/2.0",
            "BYE sip: SIP/2.0",
            "BYE sip:bob@ SIP/2.0",
            "INVITE  SIP/2.0",
        ] {
            assert!(parse_request_line(line).is_err(), "{line:?} was accepted");
        }
        for line in [
            "BYE sip:bob@127.0.0.1:5060 SIP/2.0",
            "BYE sip:bob@b.example;transport=udp SIP/2.0",
            "INVITE sip:[::1]:5060 SIP/2.0",
            "INVITE tel:+15551234567 SIP/2.0",
        ] {
            assert!(parse_request_line(line).is_ok(), "{line:?} was rejected");
        }
    }

    fn response(status_line: &str) -> crate::sip::Response {
        let raw = format!(
            "{status_line}\r\nVia: SIP/2.0/UDP a.example:5060;branch=z9hG4bK-1\r\n\
             From: <sip:a@a.example>;tag=1\r\nTo: <sip:b@b.example>;tag=2\r\n\
             Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        );
        match SipMessage::try_from(raw.as_str()).unwrap() {
            SipMessage::Response(r) => r,
            SipMessage::Request(_) => panic!("expected response"),
        }
    }

    #[test]
    fn a_custom_reason_phrase_is_kept_beside_the_standard_code() {
        let r = response("SIP/2.0 403 Caller Origination Number is Invalid");
        assert_eq!(r.status_code, crate::sip::StatusCode::Forbidden);
        assert_eq!(
            r.wire_reason.as_deref(),
            Some("Caller Origination Number is Invalid")
        );
        // The wire form is unchanged: the standard phrase is still written.
        assert!(r.to_string().starts_with("SIP/2.0 403 Forbidden\r\n"));
        assert!(r.to_bytes().starts_with(b"SIP/2.0 403 Forbidden\r\n"));
        // Surrounding whitespace is trimmed.
        let r = response("SIP/2.0 503 \tOverloaded Try Later  ");
        assert_eq!(r.wire_reason.as_deref(), Some("Overloaded Try Later"));
    }

    #[test]
    fn the_standard_phrase_or_none_keeps_no_wire_reason() {
        assert_eq!(response("SIP/2.0 403 Forbidden").wire_reason, None);
        assert_eq!(response("SIP/2.0 486 busy here").wire_reason, None);
        assert_eq!(response("SIP/2.0 404").wire_reason, None);
        assert_eq!(response("SIP/2.0 404 ").wire_reason, None);
        // An unknown code keeps its phrase in StatusCode::Other instead.
        let r = response("SIP/2.0 499 Odd Thing");
        assert_eq!(r.wire_reason, None);
        assert_eq!(r.status_code.text(), "Odd Thing");
        assert_eq!(crate::sip::Response::default().wire_reason, None);
    }

    #[test]
    fn rejects_rfc4475_malformed_request_lines_and_headers() {
        // Angle-bracketed Request-URI (ltgtruri), trailing/embedded whitespace (trws, lwsruri),
        // header parameters in Request-URI (escruri), or unsupported version (badvers).
        for bad_line in [
            "INVITE <sip:bob@example.com> SIP/2.0",
            "OPTIONS sip:bob@example.com SIP/2.0 ",
            "INVITE sip:bob@example.com?Route=sip:proxy.example.com SIP/2.0",
            "INVITE sip:bob@example.com SIP/7.0",
        ] {
            assert!(
                parse_request_line(bad_line).is_err(),
                "{bad_line:?} was accepted"
            );
        }

        // Mismatched CSeq method (mismatch01/mismatch02).
        let mismatch = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP a.example:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:a@a.example>;tag=1\r\n",
            "To: <sip:b@b.example>\r\n",
            "Call-ID: c1\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        assert!(SipMessage::try_from(mismatch).is_err());

        // Out-of-range Max-Forwards / Expires (scalar02) and non-GMT Date (baddate).
        let bad_max_forwards = concat!(
            "OPTIONS sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP a.example:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:a@a.example>;tag=1\r\n",
            "To: <sip:b@b.example>\r\n",
            "Call-ID: c1\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Max-Forwards: 300\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        assert!(SipMessage::try_from(bad_max_forwards).is_err());

        let bad_date = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP a.example:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:a@a.example>;tag=1\r\n",
            "To: <sip:b@b.example>\r\n",
            "Call-ID: c1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Date: Fri, 01 Jan 2010 16:00:00 EST\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        assert!(SipMessage::try_from(bad_date).is_err());
    }
}
