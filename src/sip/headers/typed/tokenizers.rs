use super::parse_helpers::unescape_quoted_pairs;
use crate::prelude::*;
use crate::sip::Error;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AuthTokenizer<'a> {
    pub scheme: &'a str,
    /// Param values are unescaped: RFC 3261 quoted-pairs (`\X` → `X`) are
    /// resolved here, and `Display` escapes `"` and `\` again when writing
    /// quoted values.
    pub params: Vec<(String, String)>,
}

impl<'a> super::Tokenize<'a> for AuthTokenizer<'a> {
    fn tokenize(part: &'a str) -> Result<Self, Error> {
        AuthTokenizer::parse(part)
    }
}

impl<'a> AuthTokenizer<'a> {
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        let s = s.trim();
        if s.chars().any(|c| c.is_control() && c != '\t') {
            return Err(Error::ParseError("control character in auth header".into()));
        }
        let (scheme, rest) = split_token(s).ok_or_else(|| {
            Error::TokenizeError(format!("auth header: missing scheme in {:?}", s))
        })?;
        let rest = rest.trim_start_matches(',').trim();
        let params = parse_auth_params(rest)?;
        Ok(AuthTokenizer { scheme, params })
    }
}

/// Reject the characters that would break re-serialization of an unquoted
/// auth-param name or value: `"`, `\` and control octets. Everything else
/// (base64 `+/=`, `,`-less URIs, ...) stays accepted.
fn validate_auth_component(s: &str, what: &str) -> Result<(), Error> {
    if s.chars().any(|c| matches!(c, '"' | '\\') || c.is_control()) {
        return Err(Error::ParseError(format!("invalid auth-param {}", what)));
    }
    Ok(())
}

pub fn parse_auth_params(s: &str) -> Result<Vec<(String, String)>, Error> {
    let mut params = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if rest.is_empty() {
            break;
        }
        let eq = rest.find('=').ok_or_else(|| {
            Error::TokenizeError(format!("auth param: expected '=' in {:?}", rest))
        })?;
        let key = rest[..eq].trim();
        validate_auth_component(key, "name")?;
        rest = &rest[eq + 1..];
        let (value, after) = if let Some(inner) = rest.strip_prefix('"') {
            let (raw, after) = scan_quoted(inner)?;
            (unescape_quoted_pairs(raw)?, after)
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let v = rest[..end].trim();
            validate_auth_component(v, "value")?;
            (v.to_string(), &rest[end..])
        };

        params.push((key.to_string(), value));
        rest = after;
    }
    Ok(params)
}

/// Find the closing `"` of a quoted string, honouring `\X` quoted-pairs.
fn scan_quoted(s: &str) -> Result<(&str, &str), Error> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Ok((&s[..i], &s[i + 1..])),
            _ => {}
        }
    }
    Err(Error::TokenizeError(format!(
        "auth param: unclosed quote in {:?}",
        s
    )))
}

fn split_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let end = s.find(|c: char| c.is_whitespace())?;
    Some((&s[..end], &s[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_values_unescape_quoted_pairs() {
        let tok = AuthTokenizer::parse(r#"Digest realm="a\"b", nonce="n1""#).unwrap();
        assert_eq!(tok.params[0], ("realm".to_string(), "a\"b".to_string()));
        assert_eq!(tok.params[1], ("nonce".to_string(), "n1".to_string()));
    }

    #[test]
    fn quoted_values_survive_embedded_commas_and_semicolons() {
        let tok = AuthTokenizer::parse(r#"Digest realm="a, b;c", nonce="n""#).unwrap();
        assert_eq!(tok.params[0].1, "a, b;c");
        assert_eq!(tok.params[1].1, "n");
    }

    #[test]
    fn quote_inside_unquoted_value_is_rejected() {
        // issue #258: the printed form quotes realm/nonce, so a raw `"` in an
        // unquoted value cannot round-trip and must be rejected.
        assert!(AuthTokenizer::parse(r#"Digest realm=a"b, nonce="n1""#).is_err());
    }

    #[test]
    fn control_characters_are_rejected() {
        assert!(AuthTokenizer::parse("Digest realm=a\u{7}b").is_err());
        assert!(AuthTokenizer::parse("Digest realm=\"a\u{7}b\"").is_err());
    }

    #[test]
    fn base64_looking_unquoted_values_are_still_accepted() {
        let tok = AuthTokenizer::parse(
            "Digest realm=example.com, nonce=MTM3MzAzNDQyNDo3OGM3MTczNmE6YjE1Zg==",
        )
        .unwrap();
        assert_eq!(tok.params[0].1, "example.com");
        assert_eq!(tok.params[1].1, "MTM3MzAzNDQyNDo3OGM3MTczNmE6YjE1Zg==");
    }

    #[test]
    fn unclosed_quote_is_rejected_even_with_escapes() {
        assert!(AuthTokenizer::parse(r#"Digest realm="a\"#).is_err());
    }
}

#[derive(Debug, Clone)]
pub struct CseqTokenizer<'a> {
    pub seq: &'a str,
    pub method: &'a str,
}

impl<'a> super::Tokenize<'a> for CseqTokenizer<'a> {
    fn tokenize(part: &'a str) -> Result<Self, Error> {
        CseqTokenizer::parse(part)
    }
}

impl<'a> CseqTokenizer<'a> {
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        let s = s.trim();
        let mut parts = s.splitn(2, |c: char| c.is_whitespace());
        let seq = parts
            .next()
            .ok_or_else(|| Error::TokenizeError("CSeq: missing seq".into()))?
            .trim();
        let method = parts
            .next()
            .ok_or_else(|| Error::TokenizeError("CSeq: missing method".into()))?
            .trim();
        Ok(CseqTokenizer { seq, method })
    }
}
