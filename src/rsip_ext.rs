use crate::transport::{SipAddr, SipConnection};
use crate::{Error, Result};
use nom::{
    branch::alt,
    bytes::complete::{is_not, take_until},
    character::complete::{char, multispace0},
    combinator::{map, opt, rest},
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult, Parser,
};
use rsip::prelude::ToTypedHeader;
use rsip::{
    message::HasHeaders,
    prelude::{HeadersExt, UntypedHeader},
    Method,
};
use std::borrow::Cow;
use std::str::FromStr;

pub trait RsipResponseExt {
    fn reason_phrase(&self) -> Option<&str>;
    fn via_received(&self) -> Option<rsip::HostWithPort>;
    fn content_type(&self) -> Option<rsip::headers::ContentType>;
    fn typed_contact_headers(&self) -> Result<Vec<rsip::typed::Contact>>;
    fn contact_uri(&self) -> Result<rsip::Uri>;
    fn remote_uri(&self, destination: Option<&SipAddr>) -> Result<rsip::Uri>;
}

impl RsipResponseExt for rsip::Response {
    fn reason_phrase(&self) -> Option<&str> {
        let headers = self.headers();
        for header in headers.iter() {
            if let rsip::Header::Other(name, value) = header {
                if name.eq_ignore_ascii_case("reason") {
                    return Some(value);
                }
            }
            if let rsip::Header::ErrorInfo(reason) = header {
                return Some(reason.value());
            }
        }
        None
    }
    /// Parse the received address from the Via header
    ///
    /// This function extracts the received address from the Via header
    /// and returns it as a HostWithPort struct.
    fn via_received(&self) -> Option<rsip::HostWithPort> {
        let via = self.via_header().ok()?;
        SipConnection::parse_target_from_via(via)
            .map(|(_, host_with_port)| host_with_port)
            .ok()
    }
    fn content_type(&self) -> Option<rsip::headers::ContentType> {
        let headers = self.headers();
        for header in headers.iter() {
            if let rsip::Header::ContentType(content_type) = header {
                return Some(content_type.clone());
            }
        }
        None
    }

    fn typed_contact_headers(&self) -> Result<Vec<rsip::typed::Contact>> {
        let contact = match self.contact_header() {
            Ok(contact) => contact,
            Err(rsip::Error::MissingHeader(_)) => return Ok(Vec::new()),
            Err(e) => return Err(Error::from(e)),
        };
        parse_typed_contact_header_list(contact.value())
    }

    fn contact_uri(&self) -> Result<rsip::Uri> {
        if let Some(contact) = self.typed_contact_headers()?.first() {
            Ok(contact.uri.clone())
        } else {
            Err(Error::Error("missing Contact header".to_string()))
        }
    }

    fn remote_uri(&self, destination: Option<&SipAddr>) -> Result<rsip::Uri> {
        // update remote uri
        let mut contact_uri = self.contact_uri()?;

        for param in contact_uri.params.iter() {
            if let rsip::Param::Other(name, _) = param {
                if !name.to_string().eq_ignore_ascii_case("ob") {
                    continue;
                }
                contact_uri.params.clear();
                if let Some(dest) = destination {
                    contact_uri.host_with_port = dest.addr.clone();
                    dest.r#type
                        .as_ref()
                        .map(|t| contact_uri.params.push(rsip::Param::Transport(t.clone())));
                }
                break;
            }
        }
        Ok(contact_uri)
    }
}

pub trait RsipHeadersExt {
    fn push_front(&mut self, header: rsip::Header);
}

impl RsipHeadersExt for rsip::Headers {
    fn push_front(&mut self, header: rsip::Header) {
        let mut headers = self.iter().cloned().collect::<Vec<_>>();
        headers.insert(0, header);
        *self = headers.into();
    }
}

#[macro_export]
macro_rules! header_pop {
    ($iter:expr, $header:path) => {
        let mut first = true;
        $iter.retain(|h| {
            if first && matches!(h, $header(_)) {
                first = false;
                false
            } else {
                true
            }
        });
    };
}

pub fn extract_uri_from_contact(line: &str) -> Result<rsip::Uri> {
    if let Ok(uri) = rsip::headers::Contact::from(line).uri() {
        return Ok(uri);
    }

    let tokenizer = CustomContactTokenizer::from_str(line)?;
    let mut uri = rsip::Uri::try_from(tokenizer.uri()).map_err(Error::from)?;
    uri.params.retain(|p| {
        if let rsip::Param::Transport(rsip::Transport::Udp) = p {
            false
        } else {
            true
        }
    });
    apply_tokenizer_params(&mut uri, &tokenizer);
    return Ok(uri);
}

pub fn parse_typed_contact_header_list(line: &str) -> Result<Vec<rsip::typed::Contact>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(Error::Error("empty Contact header".to_string()));
    }

    let values = split_contact_header_values(trimmed)?;
    let mut contacts = Vec::with_capacity(values.len());
    for value in values {
        contacts.push(parse_typed_contact(value.as_str())?);
    }

    Ok(contacts)
}

pub fn parse_typed_contact(line: &str) -> Result<rsip::typed::Contact> {
    if let Ok(contact) = rsip::headers::Contact::from(line).typed() {
        return Ok(contact);
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(Error::Error("empty Contact header".to_string()));
    }

    let (display_name, uri_part, header_params_part) = if let Some(start) = trimmed.find('<') {
        let end = trimmed[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or_else(|| Error::Error("invalid Contact header: missing '>'".to_string()))?;
        let display = trimmed[..start].trim();
        let display_name = if display.is_empty() {
            None
        } else {
            Some(display.trim_matches('"').to_string())
        };
        let uri = &trimmed[start + 1..end];
        let params = trimmed[end + 1..].trim();
        (display_name, uri, params)
    } else {
        let (uri, params) = split_uri_and_header_params(trimmed);
        (None, uri, params)
    };

    let mut uri = extract_uri_from_contact(uri_part)?;
    uri.headers.clear();

    let params = parse_contact_header_params(header_params_part)?;

    Ok(rsip::typed::Contact {
        display_name,
        uri,
        params,
    })
}

pub fn split_contact_header_values(line: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut angle_depth = 0usize;

    for ch in line.chars() {
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
                let value = current.trim();
                if !value.is_empty() {
                    values.push(value.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let value = current.trim();
    if !value.is_empty() {
        values.push(value.to_string());
    }

    if values.is_empty() {
        return Err(Error::Error("empty Contact header".to_string()));
    }

    Ok(values)
}

fn split_uri_and_header_params(input: &str) -> (&str, &str) {
    let path = input.split_once('?').map_or(input, |(path, _)| path);
    if let Some(idx) = path.find(';') {
        (&input[..idx], &input[idx..])
    } else {
        (input, "")
    }
}

fn parse_contact_header_params(input: &str) -> Result<Vec<rsip::Param>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let params = separated_list0(char(';'), custom_contact_param)
        .parse(trimmed.trim_start_matches(';'))
        .map_err(|_| Error::Error(format!("invalid Contact header params: {}", input)))?
        .1;

    params
        .into_iter()
        .filter(|param| !param.name.is_empty())
        .map(|param| rsip::Param::try_from((param.name, param.value)).map_err(Error::from))
        .collect()
}

fn apply_tokenizer_params(uri: &mut rsip::Uri, tokenizer: &CustomContactTokenizer) {
    for (name, value) in tokenizer.params.iter().map(|p| (p.name, p.value)) {
        if name.eq_ignore_ascii_case("transport") {
            continue;
        }
        let mut updated = false;
        for param in uri.params.iter_mut() {
            if let rsip::Param::Other(key, existing_value) = param {
                if key.value().eq_ignore_ascii_case(name) {
                    *existing_value =
                        value.map(|v| rsip::param::OtherParamValue::new(v.to_string()));
                    updated = true;
                    break;
                }
            }
        }
        if !updated {
            uri.params.push(rsip::Param::Other(
                rsip::param::OtherParam::new(name),
                value.map(|v| rsip::param::OtherParamValue::new(v.to_string())),
            ));
        }
    }
}

pub fn destination_from_request(request: &rsip::Request) -> Option<Cow<'_, rsip::Uri>> {
    request
        .headers
        .iter()
        .find_map(|header| match header {
            rsip::Header::Route(route) => route
                .typed()
                .ok()
                .and_then(|r| r.uris().first().map(|u| Cow::Owned(u.uri.clone()))),
            _ => None,
        })
        .or_else(|| Some(Cow::Borrowed(&request.uri)))
}

fn split_header_line(raw: &str) -> Option<(&str, &str)> {
    raw.split_once(':')
        .map(|(name, value)| (name.trim(), value.trim()))
}

pub fn header_value_case_insensitive(headers: &rsip::Headers, name: &str) -> Option<String> {
    headers.iter().find_map(|header| {
        let raw = header.to_string();
        let (header_name, header_value) = split_header_line(&raw)?;
        if header_name.eq_ignore_ascii_case(name) {
            Some(header_value.to_string())
        } else {
            None
        }
    })
}

pub fn header_tokens_case_insensitive(headers: &rsip::Headers, name: &str) -> Vec<String> {
    header_value_case_insensitive(headers, name)
        .map(|value| {
            value
                .split(',')
                .map(|token| token.trim())
                .filter(|token| !token.is_empty())
                .map(|token| token.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn header_contains_token(headers: &rsip::Headers, name: &str, token: &str) -> bool {
    header_tokens_case_insensitive(headers, name)
        .into_iter()
        .any(|value| value.eq_ignore_ascii_case(token))
}

pub fn parse_rseq_header(headers: &rsip::Headers) -> Option<u32> {
    header_value_case_insensitive(headers, "RSeq")
        .and_then(|value| value.split_whitespace().next().map(str::to_string))
        .and_then(|token| token.parse::<u32>().ok())
}

pub fn parse_rack_header(headers: &rsip::Headers) -> Option<(u32, u32, Method)> {
    let value = header_value_case_insensitive(headers, "RAck")?;
    let mut items = value.split_whitespace();
    let rseq = items.next()?.parse::<u32>().ok()?;
    let cseq = items.next()?.parse::<u32>().ok()?;
    let method_str = items.next()?;
    let method = Method::from_str(method_str).ok()?;
    Some((rseq, cseq, method))
}

#[derive(Debug)]
pub(crate) struct CustomContactTokenizer<'a> {
    uri: &'a str,
    params: Vec<CustomContactParamToken<'a>>,
}

#[derive(Debug)]
struct CustomContactParamToken<'a> {
    name: &'a str,
    value: Option<&'a str>,
}

impl<'a> CustomContactTokenizer<'a> {
    pub(crate) fn from_str(input: &'a str) -> super::Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::Error("empty contact header".into()));
        }

        match custom_contact_tokenize(trimmed) {
            Ok((_rem, tokenizer)) => Ok(tokenizer),
            Err(_) => Ok(Self::from_plain(trimmed)),
        }
    }

    fn from_plain(uri: &'a str) -> Self {
        Self {
            uri,
            params: custom_contact_parse_params(uri),
        }
    }

    pub(crate) fn uri(&self) -> &'a str {
        self.uri
    }
}

fn custom_contact_tokenize<'a>(input: &'a str) -> IResult<&'a str, CustomContactTokenizer<'a>> {
    alt((
        custom_contact_with_brackets,
        custom_contact_without_brackets,
    ))
    .parse(input)
}

fn custom_contact_with_brackets<'a>(
    input: &'a str,
) -> IResult<&'a str, CustomContactTokenizer<'a>> {
    let (input, _) = multispace0(input)?;
    let (input, _) = opt(take_until("<")).parse(input)?;
    let (input, _) = char('<').parse(input)?;
    let (input, uri) = take_until(">").parse(input)?;
    let (input, _) = char('>').parse(input)?;

    let uri = uri.trim();
    let params = custom_contact_parse_params(uri);

    Ok((input, CustomContactTokenizer { uri, params }))
}

fn custom_contact_without_brackets<'a>(
    input: &'a str,
) -> IResult<&'a str, CustomContactTokenizer<'a>> {
    let (input, uri) = map(rest, |s: &str| s.trim()).parse(input)?;
    let params = custom_contact_parse_params(uri);
    Ok((input, CustomContactTokenizer { uri, params }))
}

fn custom_contact_parse_params<'a>(uri: &'a str) -> Vec<CustomContactParamToken<'a>> {
    let path = uri.split_once('?').map_or(uri, |(path, _)| path);
    if let Some(idx) = path.find(';') {
        let params_str = &path[idx + 1..];
        if params_str.is_empty() {
            return Vec::new();
        }

        match separated_list0(char(';'), custom_contact_param).parse(params_str) {
            Ok((_, params)) => params.into_iter().filter(|p| !p.name.is_empty()).collect(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

fn custom_contact_param<'a>(input: &'a str) -> IResult<&'a str, CustomContactParamToken<'a>> {
    let (input, _) = multispace0(input)?;
    let (input, name) = map(is_not("=; \t\r\n?"), |v: &str| v.trim()).parse(input)?;
    let (input, value) = opt(preceded(
        char('='),
        alt((
            delimited(char('"'), take_until("\""), char('"')),
            map(is_not("; \t\r\n?"), |v: &str| v.trim()),
        )),
    ))
    .parse(input)?;

    Ok((input, CustomContactParamToken { name, value }))
}

#[test]
fn test_rsip_headers_ext() {
    use rsip::{Header, Headers};
    let mut headers: Headers = vec![
        Header::Via("SIP/2.0/TCP".into()),
        Header::Via("SIP/2.0/UDP".into()),
        Header::Via("SIP/2.0/WSS".into()),
    ]
    .into();
    let via = Header::Via("SIP/2.0/TLS".into());
    headers.push_front(via);
    assert_eq!(headers.iter().count(), 4);

    header_pop!(headers, Header::Via);
    assert_eq!(headers.iter().count(), 3);

    assert_eq!(
        headers.iter().collect::<Vec<_>>(),
        vec![
            &Header::Via("SIP/2.0/TCP".into()),
            &Header::Via("SIP/2.0/UDP".into()),
            &Header::Via("SIP/2.0/WSS".into())
        ]
    );
}

#[test]
fn test_parse_typed_contact_headers_from_masked_kamailio_response() {
    use rsip::Response;

    let response: Response = concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:13050;branch=z9hG4bK-test;rport=60326;received=198.51.100.20\r\n",
        "From: <sip:1001@example.com>;tag=from-tag\r\n",
        "To: <sip:1001@example.com>;tag=to-tag\r\n",
        "CSeq: 1 REGISTER\r\n",
        "Call-ID: test-call-id@example.com\r\n",
        "Contact: <sip:1001@198.51.100.20:56734;transport=udp>;expires=573;+sip.instance=\"<urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>\", <sip:1001@192.0.2.10:13050>;expires=3600\r\n",
        "Content-Length: 0\r\n",
        "\r\n"
    )
    .try_into()
    .expect("failed to parse response");

    let contacts = response
        .typed_contact_headers()
        .expect("failed to parse typed Contact headers");

    assert_eq!(contacts.len(), 2);
    assert_eq!(contacts[0].uri.to_string(), "sip:1001@198.51.100.20:56734");
    assert_eq!(contacts[1].uri.to_string(), "sip:1001@192.0.2.10:13050");
    assert_eq!(
        contacts[0].expires().map(|expires| expires.value()),
        Some("573")
    );
    assert_eq!(
        contacts[1].expires().map(|expires| expires.value()),
        Some("3600")
    );
    assert!(contacts[0].params.iter().any(|param| matches!(
        param,
        rsip::Param::Other(name, Some(value))
            if name.value().eq_ignore_ascii_case("+sip.instance")
                && value.value() == "<urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>"
    )));
}
