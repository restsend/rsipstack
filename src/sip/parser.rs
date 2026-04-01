use crate::sip::{
    headers::{make_header, Headers},
    message::{Request, Response, SipMessage},
    uri::parse_uri,
    Error, Method, StatusCode, Uri, Version,
};
pub fn parse_message(data: &[u8]) -> Result<SipMessage, Error> {
    let sep = find_double_crlf(data)
        .ok_or_else(|| Error::ParseError("SIP message: missing \\r\\n\\r\\n separator".into()))?;

    let header_section = &data[..sep];
    let body_start = sep + 4;

    let mut lines = split_crlf_lines(header_section);
    let start_line = lines
        .next()
        .ok_or_else(|| Error::ParseError("SIP message: empty start line".into()))?;

    let mut headers = Headers::default();
    let mut content_length: usize = 0;
    let mut pending: Option<(String, String)> = None;

    for line in lines {
        if line.is_empty() {
            break;
        }

        if line.as_bytes()[0] == b' ' || line.as_bytes()[0] == b'\t' {
            if let Some((_, ref mut val)) = pending {
                val.push(' ');
                val.push_str(line.trim());
            }
            continue;
        }

        if let Some((name, val)) = pending.take() {
            if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
                content_length = val.trim().parse().unwrap_or(0);
            }
            headers.push(make_header(&name, val));
        }

        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let val = line[colon + 1..].trim().to_string();
            pending = Some((name, val));
        }
    }

    if let Some((name, val)) = pending {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
            content_length = val.trim().parse().unwrap_or(0);
        }
        headers.push(make_header(&name, val));
    }

    let body: Vec<u8> = if body_start < data.len() {
        let available = data.len() - body_start;
        let take = available.min(content_length);
        data[body_start..body_start + take].to_vec()
    } else {
        vec![]
    };

    let start_str = std::str::from_utf8(start_line.as_bytes())
        .map_err(|_| Error::ParseError("SIP start line: invalid UTF-8".into()))?;

    if start_str.starts_with("SIP/") {
        parse_response_line(start_str, headers, body)
    } else {
        parse_request_line(start_str, headers, body)
    }
}

fn parse_request_line(line: &str, headers: Headers, body: Vec<u8>) -> Result<SipMessage, Error> {
    let mut parts = line.splitn(3, |c: char| c == ' ' || c == '\t');
    let method_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing method".into()))?;
    let uri_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing URI".into()))?;
    let version_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Request-Line: missing version".into()))?
        .trim();

    let method: Method = method_str.parse()?;
    let uri: Uri = parse_uri(uri_str.trim())?;
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
    let mut parts = line.splitn(3, |c: char| c == ' ' || c == '\t');
    let version_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Status-Line: missing version".into()))?;
    let code_str = parts
        .next()
        .ok_or_else(|| Error::ParseError("Status-Line: missing status code".into()))?;
    let reason = parts.next().unwrap_or("").trim();

    let version: Version = version_str.parse()?;
    let code: u16 = code_str
        .parse()
        .map_err(|_| Error::ParseError(format!("Status-Line: invalid code {:?}", code_str)))?;
    let status_code = StatusCode::try_from((code, reason))?;

    Ok(SipMessage::Response(Response {
        status_code,
        version,
        headers,
        body,
    }))
}

fn find_double_crlf(data: &[u8]) -> Option<usize> {
    let needle = b"\r\n\r\n";
    data.windows(4).position(|w| w == needle)
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

        let (end, next_pos) = if let Some(p) = rest.windows(2).position(|w| w == b"\r\n") {
            (start + p, start + p + 2)
        } else {
            (self.data.len(), self.data.len())
        };

        self.pos = next_pos;
        let slice = &self.data[start..end];
        std::str::from_utf8(slice).ok()
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
            "Content-Length: 27\r\n",
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
}
