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

    fn remote_uri(&self, destination: Option<&SipAddr>) -> Result<rsip::Uri> {
        let contact = self.contact_header()?;
        // update remote uri
        let mut contact_uri = if let Ok(typed_contact) = contact.typed() {
            typed_contact.uri
        } else {
            let mut uri = extract_uri_from_contact(contact.value())?;
            uri.headers.clear();
            uri
        };

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
