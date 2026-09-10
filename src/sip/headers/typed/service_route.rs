use super::parse_helpers::parse_display_uri_params_str;
use crate::sip::{uri::Param, uri::ParamsExt, Error, Header, Uri};

/// Typed `Service-Route` header (RFC 3608).
///
/// A registrar returns one or more `Service-Route` headers in a REGISTER
/// `200 OK` to tell the user agent which proxies to traverse for subsequent
/// requests within the registration. In IMS these entries form the originating
/// route set advertised by the S-CSCF; the UA preloads them as `Route` headers
/// on later requests such as the initial INVITE.
///
/// The grammar mirrors `Route`/`Record-Route`: a comma-separated list of
/// name-addr values, each with optional URI and header parameters.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServiceRoute {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

fn split_service_route_values(s: &str) -> Vec<String> {
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

impl ServiceRoute {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (display_name, uri, params) = parse_display_uri_params_str(s)?;
        Ok(ServiceRoute {
            display_name,
            uri,
            params,
        })
    }

    /// Parse a single `Service-Route` header value that may contain several
    /// comma-separated entries into one `ServiceRoute` per entry.
    pub fn parse_header_list(s: &str) -> Result<Vec<Self>, Error> {
        split_service_route_values(s)
            .into_iter()
            .map(|v| Self::parse(&v))
            .collect()
    }

    pub fn has_lr(&self) -> bool {
        self.uri.has_lr()
    }
}

impl std::fmt::Display for ServiceRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::convert::From<Uri> for ServiceRoute {
    fn from(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: vec![],
        }
    }
}

impl std::convert::From<ServiceRoute> for String {
    fn from(r: ServiceRoute) -> String {
        r.to_string()
    }
}

impl std::convert::From<ServiceRoute> for Header {
    fn from(r: ServiceRoute) -> Header {
        Header::ServiceRoute(crate::sip::headers::untyped::ServiceRoute::new(
            r.to_string(),
        ))
    }
}

impl<'a> super::TypedHeader<'a> for ServiceRoute {}

#[cfg(test)]
mod tests {
    use super::ServiceRoute;

    #[test]
    fn service_route_single_lr() {
        let sr = ServiceRoute::parse("<sip:scscf.home.net;lr>").unwrap();
        assert_eq!(sr.uri.to_string(), "sip:scscf.home.net;lr");
        assert!(sr.has_lr());
    }

    #[test]
    fn service_route_display_roundtrip() {
        let s = "<sip:scscf.home.net;lr>";
        let sr = ServiceRoute::parse(s).unwrap();
        assert_eq!(sr.to_string(), s);
    }

    #[test]
    fn service_route_multi_uri() {
        // 3GPP TS 24.229 style: S-CSCF followed by P-CSCF in the route set.
        let routes =
            ServiceRoute::parse_header_list("<sip:scscf.home.net;lr>, <sip:pcscf.visited.net;lr>")
                .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].uri.to_string(), "sip:scscf.home.net;lr");
        assert_eq!(routes[1].uri.to_string(), "sip:pcscf.visited.net;lr");
        assert!(routes[0].has_lr());
        assert!(routes[1].has_lr());
    }

    #[test]
    fn service_route_to_header_and_back() {
        let sr = ServiceRoute::parse("<sip:scscf.home.net;lr>").unwrap();
        let header: crate::sip::Header = sr.clone().into();
        // The untyped header value drops the surrounding header name but keeps
        // the name-addr, so re-parsing yields the same typed value.
        let reparsed = ServiceRoute::parse(header.value()).unwrap();
        assert_eq!(sr, reparsed);
    }
}
