use crate::sip::Error;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AuthTokenizer<'a> {
    pub scheme: &'a str,
    pub params: Vec<(&'a str, &'a str)>,
}

impl<'a> super::Tokenize<'a> for AuthTokenizer<'a> {
    fn tokenize(part: &'a str) -> Result<Self, Error> {
        AuthTokenizer::parse(part)
    }
}

impl<'a> AuthTokenizer<'a> {
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        let s = s.trim();
        let (scheme, rest) = split_token(s).ok_or_else(|| {
            Error::TokenizeError(format!("auth header: missing scheme in {:?}", s))
        })?;
        let rest = rest.trim_start_matches(',').trim();
        let params = parse_auth_params(rest)?;
        Ok(AuthTokenizer { scheme, params })
    }
}

pub fn parse_auth_params<'a>(s: &'a str) -> Result<Vec<(&'a str, &'a str)>, Error>
where
    'a: 'a,
{
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
        rest = &rest[eq + 1..];
        let (value, after) = if rest.starts_with('"') {
            parse_quoted(rest)?
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let v = rest[..end].trim();
            (v, &rest[end..])
        };

        params.push((key, value));
        rest = after;
    }
    Ok(params)
}

fn parse_quoted(s: &str) -> Result<(&str, &str), Error> {
    if !s.starts_with('"') {
        return Err(Error::TokenizeError("expected '\"'".into()));
    }
    let s = &s[1..]; // skip opening quote
    let close = s
        .find('"')
        .ok_or_else(|| Error::TokenizeError(format!("auth param: unclosed quote in {:?}", s)))?;
    let value = &s[..close];
    let after = &s[close + 1..]; // skip closing quote
    Ok((value, after))
}

fn split_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let end = s.find(|c: char| c.is_whitespace())?;
    Some((&s[..end], &s[end..]))
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
