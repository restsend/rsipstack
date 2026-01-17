use crate::{Error, Result};
use rsip::headers::UntypedHeader;
use rsip::typed::Via;
use rsip::{
    param::Tag,
    prelude::{HeadersExt, ToTypedHeader},
    Method,
};
use rsip::{Request, Response};
use std::fmt::Write;
use std::hash::Hash;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum TransactionRole {
    Client,
    Server,
}

impl std::fmt::Display for TransactionRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionRole::Client => write!(f, "c"),
            TransactionRole::Server => write!(f, "s"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TransactionKey(String);

impl std::fmt::Display for TransactionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TransactionKey {
    pub fn from_request(req: &Request, role: TransactionRole) -> Result<Self> {
        let via = req.via_header()?.typed()?;
        let mut method = req.method().clone();

        if matches!(method, Method::Ack | Method::Cancel) && role == TransactionRole::Server {
            method = Method::Invite;
        }

        let from_tag = req
            .from_header()?
            .tag()?
            .ok_or(Error::Error("from tags missing".to_string()))?;
        let call_id = req.call_id_header()?.value();
        let cseq = req.cseq_header()?.seq()?;
        Self::build_key(role, via, method, cseq, from_tag, call_id)
    }

    pub fn from_response(resp: &Response, role: TransactionRole) -> Result<Self> {
        let via = resp.via_header()?.typed()?;
        let cseq = resp.cseq_header()?;
        let method = cseq.method()?;
        let from_tag = resp
            .from_header()?
            .tag()?
            .ok_or(Error::Error("from tags missing".to_string()))?;
        let call_id = resp.call_id_header()?.value();

        Self::build_key(role, via, method, cseq.seq()?, from_tag, call_id)
    }

    pub(super) fn build_key(
        role: TransactionRole,
        via: Via,
        method: Method,
        cseq: u32,
        from_tag: Tag,
        call_id: &str,
    ) -> Result<Self> {
        let mut key = String::new();
        match via.branch() {
            Some(branch) => {
                write!(
                    &mut key,
                    "{}.{}_{}_{}_{}_{}",
                    role, method, cseq, call_id, from_tag, branch
                )
            }
            None => {
                write!(
                    &mut key,
                    "{}.{}_{}_{}_{}_{}.2543",
                    role, method, cseq, call_id, from_tag, via.uri.host_with_port
                )
            }
        }
        .map_err(|e| Error::Error(e.to_string()))?;
        Ok(TransactionKey(key))
    }
}

#[test]
fn test_transaction_key() -> Result<()> {
    use rsip::headers::*;
    let register_req = rsip::message::Request {
        method: rsip::method::Method::Register,
        uri: rsip::Uri {
            scheme: Some(rsip::Scheme::Sips),
            host_with_port: rsip::Domain::from("restsend.com").into(),
            ..Default::default()
        },
        headers: vec![
            Via::new("SIP/2.0/TLS sip.restsend.com:5061;branch=z9hG4bKnashd92").into(),
            CSeq::new("2 REGISTER").into(),
            From::new("Bob <sips:bob@sip.restsend.com>;tag=ja743ks76zlflH").into(),
            CallId::new("1j9FpLxk3uxtm8tn@sip.restsend.com").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: Default::default(),
    };
    let key = TransactionKey::from_request(&register_req, TransactionRole::Client)?;
    assert_eq!(
        key,
        TransactionKey(
            "c.REGISTER_2_1j9FpLxk3uxtm8tn@sip.restsend.com_ja743ks76zlflH_z9hG4bKnashd92"
                .to_string()
        )
    );
    let register_resp = rsip::message::Response {
        status_code: rsip::StatusCode::OK,
        version: rsip::Version::V2,
        headers: vec![
            Via::new("SIP/2.0/TLS client.sip.restsend.com:5061;branch=z9hG4bKnashd92").into(),
            CSeq::new("2 REGISTER").into(),
            From::new("Bob <sips:bob@sip.restsend.com>;tag=ja743ks76zlflH").into(),
            CallId::new("1j9FpLxk3uxtm8tn@sip.restsend.com").into(),
        ]
        .into(),
        body: Default::default(),
    };
    let key = TransactionKey::from_response(&register_resp, TransactionRole::Server)?;
    assert_eq!(
        key,
        TransactionKey(
            "s.REGISTER_2_1j9FpLxk3uxtm8tn@sip.restsend.com_ja743ks76zlflH_z9hG4bKnashd92"
                .to_string()
        )
    );

    let mut ack_req = register_req.clone();
    ack_req.method = Method::Ack;
    ack_req.headers.unique_push(CSeq::new("2 ACK").into());

    let key = TransactionKey::from_request(&ack_req, TransactionRole::Server)?;
    assert_eq!(
        key,
        TransactionKey(
            "s.INVITE_2_1j9FpLxk3uxtm8tn@sip.restsend.com_ja743ks76zlflH_z9hG4bKnashd92"
                .to_string()
        )
    );
    Ok(())
}
