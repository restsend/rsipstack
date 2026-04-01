use crate::sip::{Error, Header, Uri, uri::Param};
use super::parse_helpers::parse_display_uri_params_str;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RecordRoute {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

fn split_rr_values(s: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut angle_depth = 0usize;
    let mut in_quotes = false;
    for ch in s.chars() {
        match ch {
            '"' => { in_quotes = !in_quotes; current.push(ch); }
            '<' if !in_quotes => { angle_depth += 1; current.push(ch); }
            '>' if !in_quotes => { angle_depth = angle_depth.saturating_sub(1); current.push(ch); }
            ',' if !in_quotes && angle_depth == 0 => {
                let v = current.trim().to_string();
                if !v.is_empty() { values.push(v); }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let v = current.trim().to_string();
    if !v.is_empty() { values.push(v); }
    values
}

impl RecordRoute {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (display_name, uri, params) = parse_display_uri_params_str(s)?;
        Ok(RecordRoute { display_name, uri, params })
    }

    pub fn parse_header_list(s: &str) -> Result<Vec<Self>, Error> {
        split_rr_values(s)
            .into_iter()
            .map(|v| Self::parse(&v))
            .collect()
    }

    pub fn has_lr(&self) -> bool {
        self.uri.params.iter().any(|p| matches!(p, Param::Lr))
    }
}

impl std::fmt::Display for RecordRoute {
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

impl std::convert::From<Uri> for RecordRoute {
    fn from(uri: Uri) -> Self {
        Self { display_name: None, uri, params: vec![] }
    }
}

impl std::convert::From<RecordRoute> for String {
    fn from(r: RecordRoute) -> String { r.to_string() }
}

impl std::convert::From<RecordRoute> for Header {
    fn from(r: RecordRoute) -> Header {
        Header::RecordRoute(crate::sip::headers::untyped::RecordRoute::new(r.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for RecordRoute {}

#[cfg(test)]
mod tests {
    use super::RecordRoute;
    use crate::sip::Param;

    #[test]
    fn record_route_keeps_uri_param_values_with_colons() {
        let route = RecordRoute::parse("<sip:82.202.218.130;lr=on;ftag=d4nwJ0jF;du=sip:95.143.188.49:5060;did=893.d6d1>").unwrap();
        assert_eq!(route.uri.to_string(), "sip:82.202.218.130;lr=on;ftag=d4nwJ0jF;du=sip:95.143.188.49:5060;did=893.d6d1");
        assert!(route.uri.params.iter().any(|param| matches!(param, Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("du") && value.value() == "sip:95.143.188.49:5060")));
        assert!(route.uri.params.iter().any(|param| matches!(param, Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("did") && value.value() == "893.d6d1")));
    }

    #[test]
    fn record_route_lr_flag() {
        let rr = RecordRoute::parse("<sip:proxy.restsend.com;lr>").unwrap();
        assert!(rr.has_lr());
        assert_eq!(rr.to_string(), "<sip:proxy.restsend.com;lr>");
    }

    #[test]
    fn record_route_multi_entry() {
        let entries = RecordRoute::parse_header_list(
            "<sip:proxy1.restsend.com;lr>, <sip:proxy2.restsend.com;lr>"
        ).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].has_lr());
        assert!(entries[1].has_lr());
        assert_eq!(entries[0].uri.to_string(), "sip:proxy1.restsend.com;lr");
    }

    #[test]
    fn record_route_with_transport() {
        use crate::sip::Transport;
        let rr = RecordRoute::parse("<sip:proxy.restsend.com;transport=tcp;lr>").unwrap();
        assert!(rr.has_lr());
        assert!(rr.uri.params.iter().any(|p| matches!(p, Param::Transport(Transport::Tcp))));
    }
}

