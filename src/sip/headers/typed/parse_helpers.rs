use crate::sip::{Error, uri::{parse_params, parse_uri, Param, Uri}};
pub fn parse_display_uri_params_str(s: &str) -> Result<(Option<String>, Uri, Vec<Param>), Error> {
    let s = s.trim();
    if let Some(lt) = s.find('<') {
        let display_name = s[..lt].trim().trim_matches('"').to_string();
        let rest = &s[lt + 1..];
        let gt = rest.find('>').ok_or_else(|| Error::ParseError(format!("missing '>' in: {}", s)))?;
        let uri_str = &rest[..gt];
        let params_str = rest[gt + 1..].trim().trim_start_matches(';');
        let uri = parse_uri(uri_str)?;
        let params = parse_params(params_str)?;
        let display = if display_name.is_empty() { None } else { Some(display_name) };
        return Ok((display, uri, params));
    }

    let uri = parse_uri(s)?;
    Ok((None, uri, vec![]))
}
