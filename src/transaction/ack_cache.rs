//! Successful INVITE ACKs are distinct for every fork and INVITE CSeq.
use super::key::TransactionRole;
use crate::{
    dialog::DialogId,
    sip::{HeadersExt, Request, Response},
    transport::SipAddr,
};
use alloc::collections::BTreeMap;

pub(crate) type AckKey = (DialogId, u32);
pub(crate) type AckCache = BTreeMap<AckKey, CachedAck>;
#[derive(Clone)]
pub(crate) struct CachedAck {
    pub(crate) request: Request,
    pub(crate) destination: Option<SipAddr>,
}
pub(crate) fn request_key(request: &Request) -> crate::Result<AckKey> {
    Ok((
        DialogId::try_from((request, TransactionRole::Client))?,
        request.cseq_header()?.seq()?,
    ))
}
pub(crate) fn response_key(response: &Response) -> crate::Result<AckKey> {
    Ok((
        DialogId::try_from((response, TransactionRole::Client))?,
        response.cseq_header()?.seq()?,
    ))
}
