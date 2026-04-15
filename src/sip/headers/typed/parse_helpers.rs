use crate::sip::{
    uri::{parse_params, parse_uri, Param, Uri},
    Error,
};
use memchr::memchr;
pub fn parse_display_uri_params_str(s: &str) -> Result<(Option<String>, Uri, Vec<Param>), Error> {
    let s = s.trim();
    if let Some(lt) = s.find('<') {
        let display_name = s[..lt].trim().trim_matches('"').to_string();
        let rest = &s[lt + 1..];
        let gt = rest
            .find('>')
            .ok_or_else(|| Error::ParseError(format!("missing '>' in: {}", s)))?;
        let uri_str = &rest[..gt];
        let params_str = rest[gt + 1..].trim().trim_start_matches(';');
        let uri = parse_uri(uri_str)?;
        let params = parse_params(params_str)?;
        let display = if display_name.is_empty() {
            None
        } else {
            Some(display_name)
        };
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

    if let Some(end) = uri_end {
        let uri_str = &s[..end];
        let params_str = &s[end + 1..];
        let uri = parse_uri(uri_str)?;
        let params = parse_params(params_str)?;
        return Ok((None, uri, params));
    }

    // No header params, entire string is URI
    let uri = parse_uri(s)?;
    Ok((None, uri, vec![]))
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

    // ── 无括号、纯 host（无 scheme、无 @、无 ';'） ────────────────────────────

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
