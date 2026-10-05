use crate::prelude::*;
use crate::sip::{Error, Header, Method};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Allow {
    pub methods: Vec<Method>,
}

impl Allow {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let methods = s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|m| m.parse::<Method>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Allow { methods })
    }
}

impl core::fmt::Display for Allow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s: Vec<String> = self.methods.iter().map(|m| m.to_string()).collect();
        write!(f, "{}", s.join(", "))
    }
}

impl core::convert::From<Vec<Method>> for Allow {
    fn from(methods: Vec<Method>) -> Self {
        Allow { methods }
    }
}

impl core::convert::From<Allow> for String {
    fn from(a: Allow) -> String {
        a.to_string()
    }
}

impl core::convert::From<Allow> for Header {
    fn from(a: Allow) -> Header {
        Header::Allow(crate::sip::headers::untyped::Allow::new(a.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for Allow {}
