use crate::prelude::*;
use crate::sip::{uri::Param, Error, Header, Uri};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Contact {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

impl Contact {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        if s == "*" {
            return Ok(Contact {
                display_name: None,
                uri: Uri {
                    scheme: Some(crate::sip::uri::Scheme::Other(String::from("*"))),
                    auth: None,
                    host_with_port: crate::sip::uri::HostWithPort {
                        host: crate::sip::uri::Host::Domain(crate::sip::uri::Domain(String::new())),
                        port: None,
                    },
                    params: vec![],
                    headers: vec![],
                },
                params: vec![],
            });
        }

        let trimmed = s.trim();
        let has_angle_brackets;
        let (display_name, uri_part, header_params_part) = if let Some(start) =
            super::parse_helpers::find_unquoted_lt(trimmed)?
        {
            has_angle_brackets = true;
            let end = trimmed[start..]
                .find('>')
                .map(|offset| start + offset)
                .ok_or_else(|| Error::ParseError("invalid Contact header: missing '>'".into()))?;
            let display_name = super::parse_helpers::validate_display_name(&trimmed[..start])?;
            let uri = &trimmed[start + 1..end];
            if uri.is_empty() || uri.chars().any(char::is_whitespace) {
                return Err(Error::ParseError("invalid Contact URI in <>".into()));
            }
            let params = trimmed[end + 1..].trim();
            (display_name, uri, params)
        } else {
            has_angle_brackets = false;
            let (uri, params) = split_uri_and_header_params(trimmed);
            (None, uri, params)
        };

        let mut uri = crate::sip::parse_uri(uri_part)?;
        if !has_angle_brackets && (!uri.headers.is_empty() || uri.scheme.is_none()) {
            return Err(Error::ParseError("invalid unbracketed Contact URI".into()));
        }
        uri.params.retain(|param| {
            !matches!(
                param,
                crate::sip::uri::Param::Transport(crate::sip::Transport::Udp)
            )
        });
        uri.headers.clear();
        let params = parse_contact_header_params(header_params_part)?;
        Ok(Contact {
            display_name,
            uri,
            params,
        })
    }

    pub fn parse_header_list(line: &str) -> Result<Vec<Self>, Error> {
        let values = split_contact_header_values(line)?;
        values
            .into_iter()
            .map(|value| Self::parse(&value))
            .collect()
    }

    pub fn expires(&self) -> Option<u32> {
        self.params.iter().find_map(|p| match p {
            Param::Expires(e) => e.0.parse().ok(),
            _ => None,
        })
    }

    pub fn q(&self) -> Option<f32> {
        self.params.iter().find_map(|p| match p {
            Param::Q(q) => q.0.parse().ok(),
            _ => None,
        })
    }
}

impl core::fmt::Display for Contact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(crate::sip::uri::Scheme::Other(ref s)) = self.uri.scheme {
            if s == "*" {
                return write!(f, "*");
            }
        }
        match &self.display_name {
            Some(name) => write!(f, "\"{}\" <{}>", name, self.uri)?,
            None => write!(f, "<{}>", self.uri)?,
        }
        for p in &self.params {
            write!(f, "{}", p)?;
        }
        Ok(())
    }
}

impl core::convert::From<Uri> for Contact {
    fn from(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: vec![],
        }
    }
}

impl core::convert::From<Contact> for String {
    fn from(c: Contact) -> String {
        c.to_string()
    }
}

impl core::convert::From<Contact> for Header {
    fn from(c: Contact) -> Header {
        Header::Contact(crate::sip::headers::untyped::Contact::new(c.to_string()))
    }
}

impl core::convert::From<Contact> for crate::sip::headers::untyped::Contact {
    fn from(c: Contact) -> crate::sip::headers::untyped::Contact {
        crate::sip::headers::untyped::Contact::new(c.to_string())
    }
}

impl<'a> super::TypedHeader<'a> for Contact {}

fn split_contact_header_values(line: &str) -> Result<Vec<String>, Error> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(Error::ParseError("empty Contact header".into()));
    }

    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth = 0usize;

    for ch in trimmed.chars() {
        if escaped {
            escaped = false;
            current.push(ch);
            continue;
        }
        if in_quotes && ch == '\\' {
            escaped = true;
            current.push(ch);
            continue;
        }
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
                if value.is_empty() {
                    return Err(Error::ParseError("empty Contact header entry".into()));
                }
                values.push(value.to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if in_quotes || angle_depth != 0 {
        return Err(Error::ParseError("unbalanced Contact header".into()));
    }

    let value = current.trim();
    if value.is_empty() {
        return Err(Error::ParseError("empty Contact header entry".into()));
    }
    values.push(value.to_string());

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

fn parse_contact_header_params(input: &str) -> Result<Vec<Param>, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let rest = trimmed
        .strip_prefix(';')
        .ok_or_else(|| Error::ParseError("invalid Contact header parameters".into()))?;
    if rest.trim().is_empty() {
        return Err(Error::ParseError("empty Contact parameter".into()));
    }
    crate::sip::parse_params(rest)
}

#[cfg(test)]
mod tests {
    use super::Contact;
    use crate::sip::{HeadersExt, Param, Response};

    #[test]
    fn contact_header_list_parses_masked_kamailio_response() {
        let response: Response = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:13050;branch=z9hG4bK-test;rport=60326;received=198.51.100.20\r\n",
            "From: <sip:1001@restsend.com>;tag=from-tag\r\n",
            "To: <sip:1001@restsend.com>;tag=to-tag\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Call-ID: test-call-id@restsend.com\r\n",
            "Contact: <sip:1001@198.51.100.20:56734;transport=udp>;expires=573;+sip.instance=\"<urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>\", <sip:1001@192.0.2.10:13050>;expires=3600\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();

        let contacts = response.typed_contact_headers().unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].uri.to_string(), "sip:1001@198.51.100.20:56734");
        assert_eq!(contacts[1].uri.to_string(), "sip:1001@192.0.2.10:13050");
        assert_eq!(contacts[0].expires(), Some(573));
        assert_eq!(contacts[1].expires(), Some(3600));
        assert!(contacts[0].params.iter().any(|param| matches!(param, Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("+sip.instance") && value.value() == "\"<urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>\"")));
    }

    #[test]
    fn record_style_contact_without_brackets_splits_header_params() {
        let contact = Contact::parse("sip:alice@restsend.com;expires=120").unwrap();
        assert_eq!(contact.uri.to_string(), "sip:alice@restsend.com");
        assert_eq!(contact.expires(), Some(120));
    }

    #[test]
    fn rejects_malformed_name_addr_contact_and_via() {
        use crate::sip::headers::typed::{From, To, Via};

        // Unbalanced quotes (quotbal), unquoted non-token display name (baddn),
        // whitespace inside <...> (badaspec), missing semicolon after > (regbadct),
        // and empty parameters (badinv01).
        assert!(To::parse("\"Mr. J. <sip:j@example.com>").is_err());
        assert!(From::parse("Bob, Smith <sip:bob@example.com>;tag=1").is_err());
        assert!(To::parse("Bob < sip:bob@example.com>").is_err());
        assert!(Contact::parse("<sip:bob@example.com>expires=3600").is_err());
        assert!(Contact::parse("<sip:bob@example.com>;;;;").is_err());
        assert!(Via::parse("SIP/7.0/UDP example.com;branch=z9hG4bK1").is_err());
    }
}
