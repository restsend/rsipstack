//! Dialog route sets must be retained separately from the encoded Route headers.
use super::{typed, Header, HeadersExt, Param, Request, Response, Route, Uri};
use crate::prelude::*;

pub(crate) fn parse_routes(routes: &[Route]) -> crate::Result<Vec<typed::Route>> {
    let mut parsed = Vec::new();
    for route in routes {
        parsed.extend(typed::Route::parse_header_list(route.value())?);
    }
    Ok(parsed)
}

/// RFC 3261 section 12.2.1.1. Return the wire Request-URI and Route values.
pub(crate) fn encode(target: Uri, routes: &[Route]) -> crate::Result<(Uri, Vec<Route>)> {
    let parsed = parse_routes(routes)?;
    if parsed.first().is_none_or(|first| first.has_lr()) {
        return Ok((target, routes.to_vec()));
    }
    let mut routes = parsed;
    let uri = match routes.first() {
        Some(first) if !first.has_lr() => {
            let mut uri = routes.remove(0).uri;
            uri.headers.clear();
            uri.params.retain(|p| !matches!(p, Param::Method(_)));
            routes.push(typed::Route::from(target));
            uri
        }
        _ => target,
    };
    Ok((uri, routes.into_iter().map(Into::into).collect()))
}

/// The first route remains the next hop even when strict routing moved it
/// into the Request-URI. Do not use the first *encoded* Route in that case.
pub(crate) fn next_hop(target: &Uri, routes: &[Route]) -> crate::Result<Uri> {
    Ok(parse_routes(routes)?
        .into_iter()
        .next()
        .map(|r| r.uri)
        .unwrap_or_else(|| target.clone()))
}

pub(crate) fn ack_routes(
    invite: &Request,
    response: &Response,
    known: Option<&[Route]>,
) -> crate::Result<Vec<Route>> {
    if let Some(routes) = known {
        return Ok(routes.to_vec());
    }
    if invite
        .to_header()?
        .tag()?
        .is_some_and(|tag| !tag.value().is_empty())
    {
        // Legacy raw-transaction callers supply loose Route headers. Dialog
        // transactions pass their original route set explicitly, since a
        // strict route set cannot be inferred from the encoded request.
        return Ok(invite.route_headers().into_iter().cloned().collect());
    }
    let mut routes = Vec::new();
    for header in response.headers.iter() {
        if let Header::RecordRoute(value) = header {
            for route in typed::RecordRoute::parse_header_list(value.value())? {
                routes.push(typed::Route::from(route.uri).into());
            }
        }
    }
    routes.reverse();
    Ok(routes)
}
