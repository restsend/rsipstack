use super::parse_helpers::parse_display_uri_params_str;
use crate::sip::{uri::Param, Error, Header, Uri};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Route {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

fn split_route_values(s: &str) -> Vec<String> {
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

impl Route {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (display_name, uri, params) = parse_display_uri_params_str(s)?;
        Ok(Route {
            display_name,
            uri,
            params,
        })
    }

    pub fn parse_header_list(s: &str) -> Result<Vec<Self>, Error> {
        split_route_values(s)
            .into_iter()
            .map(|v| Self::parse(&v))
            .collect()
    }

    pub fn has_lr(&self) -> bool {
        self.uri.params.iter().any(|p| matches!(p, Param::Lr))
    }

    pub fn has_ob(&self) -> bool {
        self.uri.params.iter().any(|p| matches!(p, Param::Ob))
    }
}

impl std::fmt::Display for Route {
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

impl std::convert::From<Uri> for Route {
    fn from(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: vec![],
        }
    }
}

impl std::convert::From<Route> for String {
    fn from(r: Route) -> String {
        r.to_string()
    }
}

impl std::convert::From<Route> for Header {
    fn from(r: Route) -> Header {
        Header::Route(crate::sip::headers::untyped::Route::new(r.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for Route {}

#[cfg(test)]
mod tests {
    use super::Route;
    use crate::sip::uri::Param;

    #[test]
    fn route_single_lr() {
        let r = Route::parse("<sip:proxy.restsend.com;lr>").unwrap();
        assert_eq!(r.uri.to_string(), "sip:proxy.restsend.com;lr");
        assert!(r.has_lr());
        assert!(!r.has_ob());
    }

    #[test]
    fn route_single_ob() {
        let r = Route::parse("<sip:proxy.restsend.com;ob>").unwrap();
        assert!(r.has_ob());
        assert!(!r.has_lr());
    }

    #[test]
    fn route_lr_and_ob() {
        let r = Route::parse("<sip:proxy.restsend.com;lr;ob>").unwrap();
        assert!(r.has_lr());
        assert!(r.has_ob());
    }

    #[test]
    fn route_multi_uri() {
        let routes =
            Route::parse_header_list("<sip:proxy1.restsend.com;lr>, <sip:proxy2.restsend.com;lr>")
                .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].uri.to_string(), "sip:proxy1.restsend.com;lr");
        assert_eq!(routes[1].uri.to_string(), "sip:proxy2.restsend.com;lr");
        assert!(routes[0].has_lr());
        assert!(routes[1].has_lr());
    }

    #[test]
    fn route_multi_uri_three() {
        let routes = Route::parse_header_list(
            "<sip:a.restsend.com;lr>, <sip:b.restsend.com;ob>, <sip:c.restsend.com;lr;ob>",
        )
        .unwrap();
        assert_eq!(routes.len(), 3);
        assert!(routes[0].has_lr());
        assert!(routes[1].has_ob());
        assert!(routes[2].has_lr() && routes[2].has_ob());
    }

    #[test]
    fn route_colon_in_uri_param_preserved() {
        let r = Route::parse("<sip:82.202.218.130;lr;du=sip:95.143.188.49:5060>").unwrap();
        assert!(r.has_lr());
        let du = r.uri.params.iter().find_map(|p| {
            if let Param::Other(n, Some(v)) = p {
                if n.value().eq_ignore_ascii_case("du") {
                    return Some(v.value());
                }
            }
            None
        });
        assert_eq!(du, Some("sip:95.143.188.49:5060"));
    }

    #[test]
    fn route_display_roundtrip() {
        let s = "<sip:proxy.restsend.com;lr>";
        let r = Route::parse(s).unwrap();
        assert_eq!(r.to_string(), s);
    }

    #[test]
    fn route_with_transport_param() {
        use crate::sip::Transport;
        let r = Route::parse("<sip:proxy.restsend.com;transport=tcp;lr>").unwrap();
        assert!(r.has_lr());
        assert!(r
            .uri
            .params
            .iter()
            .any(|p| matches!(p, Param::Transport(Transport::Tcp))));
    }
}
