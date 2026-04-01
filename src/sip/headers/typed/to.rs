use crate::sip::{Error, Header, Uri, uri::{Param, Tag}};
use super::parse_helpers::parse_display_uri_params_str;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct To {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

impl To {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (display_name, uri, params) = parse_display_uri_params_str(s)?;
        Ok(To { display_name, uri, params })
    }

    pub fn tag(&self) -> Option<&Tag> {
        self.params.iter().find_map(|p| match p {
            crate::sip::uri::Param::Tag(t) => Some(t),
            _ => None,
        })
    }

    pub fn with_tag(mut self, tag: Tag) -> Self {
        self.params.retain(|p| !matches!(p, crate::sip::uri::Param::Tag(_)));
        self.params.push(crate::sip::uri::Param::Tag(tag));
        self
    }

    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.uri = uri;
        self
    }
}

impl std::fmt::Display for To {
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

impl std::convert::From<Uri> for To {
    fn from(uri: Uri) -> Self {
        Self { display_name: None, uri, params: vec![] }
    }
}

impl std::convert::From<To> for String {
    fn from(s: To) -> String { s.to_string() }
}

impl std::convert::From<To> for Header {
    fn from(s: To) -> Header {
        Header::To(crate::sip::headers::untyped::To::new(s.to_string()))
    }
}

impl std::convert::From<To> for crate::sip::headers::untyped::To {
    fn from(s: To) -> crate::sip::headers::untyped::To {
        crate::sip::headers::untyped::To::new(s.to_string())
    }
}

impl<'a> super::TypedHeader<'a> for To {}
