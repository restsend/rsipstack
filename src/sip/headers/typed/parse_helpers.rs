use crate::prelude::*;
use crate::sip::{
    uri::{parse_params, parse_uri, Param, Uri},
    Error,
};
use memchr::memchr;

/// Split a combined header value into comma-joined entries, honouring
/// quoted strings and angle-bracket delimited name-addr forms (`<...>`).
pub fn split_comma_entries(s: &str) -> Vec<String> {
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

/// Look up a header/URI param by (ASCII-case-insensitive) name.
pub fn param_value(params: &[Param], key: &str) -> Option<String> {
    params.iter().find_map(|p| match p {
        Param::Other(n, v) if n.value().eq_ignore_ascii_case(key) => {
            v.as_ref().map(|t| t.value().to_string())
        }
        _ => None,
    })
}

pub(crate) fn find_unquoted_lt(s: &str) -> Result<Option<usize>, Error> {
    let mut in_quotes = false;
    let mut escaped = false;
    let mut lt_pos = None;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes && ch == '<' && lt_pos.is_none() {
            lt_pos = Some(i);
        }
    }
    if in_quotes {
        return Err(Error::ParseError("unclosed quote in display name".into()));
    }
    Ok(lt_pos)
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

pub(crate) fn validate_display_name(display_raw: &str) -> Result<Option<String>, Error> {
    let display_raw = display_raw.trim();
    if display_raw.is_empty() {
        return Ok(None);
    }
    if display_raw.starts_with('"') && display_raw.ends_with('"') && display_raw.len() >= 2 {
        return Ok(Some(display_raw[1..display_raw.len() - 1].to_string()));
    }
    if !display_raw.split_whitespace().all(is_token) {
        return Err(Error::ParseError("invalid display name".into()));
    }
    Ok(Some(display_raw.to_string()))
}

pub fn parse_display_uri_params_str(s: &str) -> Result<(Option<String>, Uri, Vec<Param>), Error> {
    let s = s.trim();
    if let Some(lt) = find_unquoted_lt(s)? {
        let display = validate_display_name(&s[..lt])?;
        let rest = &s[lt + 1..];
        let gt = rest
            .find('>')
            .ok_or_else(|| Error::ParseError("missing '>' in name-addr".into()))?;
        let uri_str = &rest[..gt];
        if uri_str.is_empty() || uri_str.chars().any(char::is_whitespace) {
            return Err(Error::ParseError("invalid URI in <>".into()));
        }
        let after_gt = rest[gt + 1..].trim();
        let params = if after_gt.is_empty() {
            vec![]
        } else {
            let params_str = after_gt
                .strip_prefix(';')
                .ok_or_else(|| Error::ParseError("expected ';' after '>'".into()))?;
            if params_str.trim().is_empty() {
                return Err(Error::ParseError("empty parameter".into()));
            }
            parse_params(params_str)?
        };
        let uri = parse_uri(uri_str)?;
        return Ok((display, uri, params));
    }

    let mut uri_end = None;
    let bytes = s.as_bytes();
    // Pre-locate '@' once with memchr; used below to decide whether a ':'
    // introduces a scheme/port or just a userinfo separator.
    let at_pos = memchr(b'@', bytes);
    let mut in_userinfo = false;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'@' => {
                in_userinfo = false;
            }
            b':' if !in_userinfo => {
                // A ':' before the '@' (or when there is no '@') means we are
                // in the userinfo section (scheme colon is already consumed by
                // the caller via parse_uri, so here it signals user:password).
                if at_pos.is_some_and(|at| i < at) {
                    in_userinfo = true;
                }
            }
            b';' if !in_userinfo => {
                uri_end = Some(i);
                break;
            }
            _ => {}
        }
    }

    let (uri, params) = if let Some(end) = uri_end {
        let uri_str = &s[..end];
        let params_str = &s[end + 1..];
        if params_str.trim().is_empty() {
            return Err(Error::ParseError("empty parameter".into()));
        }
        let uri = parse_uri(uri_str)?;
        let params = parse_params(params_str)?;
        (uri, params)
    } else {
        // No header params, entire string is URI
        let uri = parse_uri(s)?;
        (uri, vec![])
    };

    if !uri.headers.is_empty() || uri.scheme.is_none() {
        return Err(Error::ParseError("invalid unbracketed addr-spec".into()));
    }
    Ok((None, uri, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_angle_brackets() {
        let result = parse_display_uri_params_str("<sip:user@example.com>;tag=12345").unwrap();
        assert_eq!(result.0, None);
        assert_eq!(result.1.to_string(), "sip:user@example.com");
        assert_eq!(result.2.len(), 1);
        assert!(matches!(&result.2[0], Param::Tag(t) if t.value() == "12345"));
    }

    #[test]
    fn test_with_display_name_and_angle_brackets() {
        let result =
            parse_display_uri_params_str("\"John Doe\" <sip:user@example.com>;tag=12345").unwrap();
        assert_eq!(result.0, Some("John Doe".to_string()));
        assert_eq!(result.1.to_string(), "sip:user@example.com");
        assert_eq!(result.2.len(), 1);
        assert!(matches!(&result.2[0], Param::Tag(t) if t.value() == "12345"));
    }

    #[test]
    fn test_without_angle_brackets() {
        let result = parse_display_uri_params_str("sip:user@example.com;tag=12345").unwrap();
        assert_eq!(result.0, None);
        assert_eq!(result.1.to_string(), "sip:user@example.com");
        assert_eq!(result.2.len(), 1);
        assert!(matches!(&result.2[0], Param::Tag(t) if t.value() == "12345"));
    }

    #[test]
    fn test_without_angle_brackets_multiple_params() {
        let result =
            parse_display_uri_params_str("sip:user@example.com;tag=12345;other=value").unwrap();
        assert_eq!(result.0, None);
        assert_eq!(result.1.to_string(), "sip:user@example.com");
        assert_eq!(result.2.len(), 2);
    }

    #[test]
    fn test_just_uri_no_params() {
        let result = parse_display_uri_params_str("sip:user@example.com").unwrap();
        assert_eq!(result.0, None);
        assert_eq!(result.1.to_string(), "sip:user@example.com");
        assert!(result.2.is_empty());
    }

    #[test]
    fn test_with_port() {
        let result = parse_display_uri_params_str("sip:user@example.com:5060;tag=12345").unwrap();
        assert_eq!(result.0, None);
        assert_eq!(result.1.to_string(), "sip:user@example.com:5060");
        assert_eq!(result.2.len(), 1);
        assert!(matches!(&result.2[0], Param::Tag(t) if t.value() == "12345"));
    }

    #[test]
    fn test_no_userinfo_with_port_and_params() {
        // sip:host:5060;transport=tcp — ':' before ';' but no '@', so
        // in_userinfo must remain false and ';' triggers uri_end.
        let result = parse_display_uri_params_str("sip:example.com:5060;transport=tcp").unwrap();
        assert_eq!(result.1.host_with_port.to_string(), "example.com:5060");
        assert_eq!(result.2.len(), 1);
    }

    #[test]
    fn test_userinfo_password_no_brackets() {
        let result = parse_display_uri_params_str("sip:alice:secret@example.com;tag=abc").unwrap();
        let auth = result.1.auth.unwrap();
        assert_eq!(auth.user, "alice");
        assert_eq!(auth.password, Some("secret".into()));
        assert_eq!(result.2.len(), 1);
    }

    // ── no brackets, bare host (no scheme, no @, no ';') ──────────────────────────

    #[test]
    fn test_no_brackets_no_params_host_only() {
        let result = parse_display_uri_params_str("sip:example.com").unwrap();
        assert!(result.1.auth.is_none());
        assert_eq!(result.1.host_with_port.to_string(), "example.com");
        assert!(result.2.is_empty());
    }

    #[test]
    fn test_display_name_with_quotes() {
        let result =
            parse_display_uri_params_str("\"Alice Smith\" <sip:alice@example.com>").unwrap();
        assert_eq!(result.0, Some("Alice Smith".to_string()));
        assert_eq!(result.1.to_string(), "sip:alice@example.com");
        assert!(result.2.is_empty());
    }

    #[test]
    fn test_empty_display_name_with_brackets() {
        let result = parse_display_uri_params_str("<sip:alice@example.com>;tag=xyz").unwrap();
        assert!(result.0.is_none());
        assert_eq!(result.2.len(), 1);
    }

    #[test]
    fn test_no_brackets_multiple_params_with_at() {
        let result =
            parse_display_uri_params_str("sip:bob@example.com;tag=1;expires=60;lr").unwrap();
        assert_eq!(result.1.auth.as_ref().unwrap().user, "bob");
        assert_eq!(result.2.len(), 3);
    }
}
