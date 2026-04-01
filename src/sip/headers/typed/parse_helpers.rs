use crate::sip::{
    uri::{parse_params, parse_uri, Param, Uri},
    Error,
};
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
    let mut in_userinfo = false;
    let mut chars = s.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        match c {
            '@' if in_userinfo => {
                in_userinfo = false;
            }
            ':' if !in_userinfo => {
                if i > 0 && !s[..i].contains('@') {
                    in_userinfo = true;
                }
            }
            ';' => {
                if !in_userinfo {
                    uri_end = Some(i);
                    break;
                }
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
}
