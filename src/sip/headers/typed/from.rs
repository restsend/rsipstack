use super::parse_helpers::parse_display_uri_params_str;
use crate::sip::{
    uri::{Param, Tag},
    Error, Header, Uri,
};
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct From {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

impl From {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (display_name, uri, params) = parse_display_uri_params_str(s)?;
        Ok(From {
            display_name,
            uri,
            params,
        })
    }

    pub fn tag(&self) -> Option<&Tag> {
        self.params.iter().find_map(|p| match p {
            crate::sip::uri::Param::Tag(t) => Some(t),
            _ => None,
        })
    }

    pub fn with_tag(mut self, tag: Tag) -> Self {
        self.params
            .retain(|p| !matches!(p, crate::sip::uri::Param::Tag(_)));
        self.params.push(crate::sip::uri::Param::Tag(tag));
        self
    }

    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.uri = uri;
        self
    }
}

impl std::fmt::Display for From {
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

impl std::convert::From<Uri> for From {
    fn from(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: vec![],
        }
    }
}

impl std::convert::From<From> for String {
    fn from(s: From) -> String {
        s.to_string()
    }
}

impl std::convert::From<From> for Header {
    fn from(s: From) -> Header {
        Header::From(crate::sip::headers::untyped::From::new(s.to_string()))
    }
}

impl std::convert::From<From> for crate::sip::headers::untyped::From {
    fn from(s: From) -> crate::sip::headers::untyped::From {
        crate::sip::headers::untyped::From::new(s.to_string())
    }
}

impl<'a> super::TypedHeader<'a> for From {}
