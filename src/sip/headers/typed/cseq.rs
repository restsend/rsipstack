use crate::sip::{Error, Header, Method};
use super::tokenizers::CseqTokenizer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CSeq {
    pub seq: u32,
    pub method: Method,
}

impl CSeq {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let t = CseqTokenizer::parse(s)?;
        let seq: u32 = t.seq.parse().map_err(|_| Error::ParseError("CSeq: invalid seq".into()))?;
        let method: Method = t.method.parse()?;
        Ok(CSeq { seq, method })
    }
}

impl std::fmt::Display for CSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.seq, self.method)
    }
}

impl std::convert::From<(u32, Method)> for CSeq {
    fn from((seq, method): (u32, Method)) -> Self {
        CSeq { seq, method }
    }
}

impl std::convert::From<CSeq> for String {
    fn from(c: CSeq) -> String { c.to_string() }
}

impl std::convert::From<CSeq> for Header {
    fn from(c: CSeq) -> Header {
        Header::CSeq(crate::sip::headers::untyped::CSeq::new(c.to_string()))
    }
}

impl<'a> super::TypedHeader<'a> for CSeq {}
