use crate::sip::{Error, Header};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Identity {
    pub token: String,
    pub alg: String,
    pub info: String,
    pub ppt: Option<String>,
    pub extra_params: Vec<(String, Option<String>)>,
}

impl Identity {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let parts = split_identity_params(s);

        let mut iter = parts.into_iter();
        let token = iter
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::ParseError("Identity: missing token".into()))?;

        let mut alg: Option<String> = None;
        let mut info: Option<String> = None;
        let mut ppt: Option<String> = None;
        let mut extra_params: Vec<(String, Option<String>)> = Vec::new();

        for part in iter {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(eq) = part.find('=') {
                let name = part[..eq].trim();
                let value = part[eq + 1..].trim();
                match name {
                    n if n.eq_ignore_ascii_case("alg") => {
                        alg = Some(value.to_string());
                    }
                    n if n.eq_ignore_ascii_case("ppt") => {
                        ppt = Some(value.to_string());
                    }
                    n if n.eq_ignore_ascii_case("info") => {
                        // Strip enclosing angle brackets if present
                        let url = if value.starts_with('<') && value.ends_with('>') {
                            value[1..value.len() - 1].to_string()
                        } else {
                            value.to_string()
                        };
                        info = Some(url);
                    }
                    _ => {
                        extra_params.push((name.to_string(), Some(value.to_string())));
                    }
                }
            } else {
                extra_params.push((part.to_string(), None));
            }
        }

        let alg = alg.ok_or_else(|| Error::ParseError("Identity: missing alg param".into()))?;
        let info = info.ok_or_else(|| Error::ParseError("Identity: missing info param".into()))?;

        Ok(Identity {
            token,
            alg,
            info,
            ppt,
            extra_params,
        })
    }
}

/// Split the Identity header value on `;` while respecting `<...>` angle brackets.
fn split_identity_params(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for ch in s.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ';' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let last = current.trim().to_string();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity: {}", self.token)?;
        write!(f, ";alg={}", self.alg)?;
        if let Some(ppt) = &self.ppt {
            write!(f, ";ppt={}", ppt)?;
        }
        write!(f, ";info=<{}>", self.info)?;
        for (name, value) in &self.extra_params {
            match value {
                Some(v) => write!(f, ";{}={}", name, v)?,
                None => write!(f, ";{}", name)?,
            }
        }
        Ok(())
    }
}

impl std::convert::From<Identity> for String {
    fn from(i: Identity) -> String {
        i.to_string()
    }
}

impl std::convert::From<Identity> for Header {
    fn from(i: Identity) -> Header {
        Header::Identity(crate::sip::headers::untyped::Identity::new(format!(
            "{};alg={}{};info=<{}>{}",
            i.token,
            i.alg,
            i.ppt
                .as_deref()
                .map(|p| format!(";ppt={}", p))
                .unwrap_or_default(),
            i.info,
            i.extra_params
                .iter()
                .map(|(k, v)| match v {
                    Some(val) => format!(";{}={}", k, val),
                    None => format!(";{}", k),
                })
                .collect::<String>(),
        )))
    }
}

impl<'a> super::TypedHeader<'a> for Identity {}

#[cfg(test)]
mod tests {
    use super::Identity;

    #[test]
    fn identity_basic_parse() {
        let raw = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwicHB0Ijoic2hha2VuIiwieDV1IjoiaHR0cHM6Ly9jZXJ0LnJlc3RzZW5kLmNvbS9jZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxNTU1NTU1MTIzNCJdfSwiaWF0IjoxNjA5NDU5MjAwLCJvcmlnIjp7InRuIjoiKzE2MTc1NTUxMjM0In0sIm9yaWdpZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCJ9.signature;alg=ES256;ppt=shaken;info=<https://cert.restsend.com/cert.pem>";
        let id = Identity::parse(raw).unwrap();
        assert!(id.token.contains('.'));
        assert_eq!(id.alg, "ES256");
        assert_eq!(id.ppt, Some("shaken".to_string()));
        assert_eq!(id.info, "https://cert.restsend.com/cert.pem");
        assert!(id.extra_params.is_empty());
    }

    #[test]
    fn identity_no_ppt() {
        let raw = "eyJ0.eyJ.sig;alg=ES256;info=<https://cert.restsend.com/cert.pem>";
        let id = Identity::parse(raw).unwrap();
        assert_eq!(id.alg, "ES256");
        assert_eq!(id.ppt, None);
        assert_eq!(id.info, "https://cert.restsend.com/cert.pem");
    }

    #[test]
    fn identity_display_roundtrip() {
        let raw = "eyJ0.eyJ.sig;alg=ES256;ppt=shaken;info=<https://cert.restsend.com/cert.pem>";
        let id = Identity::parse(raw).unwrap();
        // Display prepends "Identity: "
        let displayed = id.to_string();
        assert!(displayed.contains("alg=ES256"));
        assert!(displayed.contains("ppt=shaken"));
        assert!(displayed.contains("info=<https://cert.restsend.com/cert.pem>"));

        // Re-parse from value portion (strip "Identity: " prefix)
        let value_part = displayed.trim_start_matches("Identity: ");
        let id2 = Identity::parse(value_part).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn identity_info_contains_colon_and_path() {
        let raw = "tok.tok.tok;alg=RS256;info=<https://cert.restsend.com/path/to/cert.pem>";
        let id = Identity::parse(raw).unwrap();
        assert_eq!(id.alg, "RS256");
        assert_eq!(id.info, "https://cert.restsend.com/path/to/cert.pem");
    }

    #[test]
    fn identity_missing_alg_errors() {
        let raw = "tok.tok.tok;info=<https://cert.restsend.com/cert.pem>";
        assert!(Identity::parse(raw).is_err());
    }

    #[test]
    fn identity_missing_info_errors() {
        let raw = "tok.tok.tok;alg=ES256";
        assert!(Identity::parse(raw).is_err());
    }

    #[test]
    fn identity_params_order_independent() {
        // info before alg before ppt
        let raw = "tok.tok.tok;info=<https://cert.restsend.com/cert.pem>;alg=ES256;ppt=shaken";
        let id = Identity::parse(raw).unwrap();
        assert_eq!(id.alg, "ES256");
        assert_eq!(id.ppt, Some("shaken".to_string()));
    }
}
