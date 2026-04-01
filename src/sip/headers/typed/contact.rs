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
        let (display_name, uri_part, header_params_part) = if let Some(start) = trimmed.find('<') {
            let end = trimmed[start..]
                .find('>')
                .map(|offset| start + offset)
                .ok_or_else(|| Error::ParseError("invalid Contact header: missing '>'".into()))?;
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

        let mut uri = crate::sip::parse_uri(uri_part)?;
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

impl std::fmt::Display for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::convert::From<Uri> for Contact {
    fn from(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: vec![],
        }
    }
}

impl std::convert::From<Contact> for String {
    fn from(c: Contact) -> String {
        c.to_string()
    }
}

impl std::convert::From<Contact> for Header {
    fn from(c: Contact) -> Header {
        Header::Contact(crate::sip::headers::untyped::Contact::new(c.to_string()))
    }
}

impl std::convert::From<Contact> for crate::sip::headers::untyped::Contact {
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
    let mut angle_depth = 0usize;

    for ch in trimmed.chars() {
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
        return Err(Error::ParseError("empty Contact header".into()));
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

fn parse_contact_header_params(input: &str) -> Result<Vec<Param>, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    crate::sip::parse_params(trimmed.trim_start_matches(';'))
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
}
