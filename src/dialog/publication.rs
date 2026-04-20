use super::dialog::{DialogInnerRef, DialogState, TerminatedReason, TransactionHandle};
use super::DialogId;
use crate::sip::{Header, Method, StatusCode, StatusCodeKind};
use crate::Result;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ClientPublicationDialog {
    pub(super) inner: DialogInnerRef,
    pub(super) etag: Arc<Mutex<Option<String>>>,
}

impl ClientPublicationDialog {
    pub fn new(inner: DialogInnerRef) -> Self {
        Self {
            inner,
            etag: Arc::new(Mutex::new(None)),
        }
    }

    pub fn id(&self) -> DialogId {
        self.inner.id.lock().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub fn etag(&self) -> Option<String> {
        self.etag.lock().clone()
    }

    pub async fn publish(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        let mut headers = headers.unwrap_or_default();
        if let Some(etag) = self.etag() {
            headers.push(Header::Other("SIP-If-Match".into(), etag));
        }

        let resp = self.request(Method::Publish, Some(headers), body).await?;
        if let Some(ref response) = resp {
            if matches!(response.status_code.kind(), StatusCodeKind::Successful) {
                if let Some(Header::Other(_, value)) = response.headers.iter().find(|h| {
                    if let Header::Other(name, _) = h {
                        name.to_string().eq_ignore_ascii_case("SIP-ETag")
                    } else {
                        false
                    }
                }) {
                    *self.etag.lock() = Some(value.to_string());
                }
            }
        }
        Ok(resp)
    }

    pub async fn close(&self) -> Result<()> {
        self.close_with_headers(None).await
    }

    pub async fn close_with_headers(
        &self,
        extra_headers: Option<Vec<crate::sip::Header>>,
    ) -> Result<()> {
        let mut headers = extra_headers.unwrap_or_default();
        headers.push(Header::Expires(0.into()));
        if let Some(etag) = self.etag() {
            headers.push(Header::Other("SIP-If-Match".into(), etag));
        }
        self.request(Method::Publish, Some(headers), None).await?;
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UacBye))?;
        Ok(())
    }

    pub async fn request(
        &self,
        method: crate::sip::Method,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        let request = self
            .inner
            .make_request(method, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    pub async fn refer(
        &self,
        refer_to: impl Into<crate::sip::ReferTo>,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        let mut headers = headers.unwrap_or_default();
        headers.push(crate::sip::Header::ReferTo(refer_to.into()));
        self.request(crate::sip::Method::Refer, Some(headers), body)
            .await
    }

    pub async fn message(
        &self,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        self.request(crate::sip::Method::Message, headers, body)
            .await
    }

    pub async fn handle(
        &mut self,
        tx: &mut crate::transaction::transaction::Transaction,
    ) -> Result<()> {
        match tx.original.method {
            Method::Publish => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Publish(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;
                self.inner.process_transaction_handle(tx, rx).await
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct ServerPublicationDialog {
    pub(super) inner: DialogInnerRef,
    pub(super) etag: Arc<Mutex<Option<String>>>,
}

impl ServerPublicationDialog {
    pub fn new(inner: DialogInnerRef) -> Self {
        Self {
            inner,
            etag: Arc::new(Mutex::new(None)),
        }
    }

    pub fn id(&self) -> DialogId {
        self.inner.id.lock().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub fn etag(&self) -> Option<String> {
        self.etag.lock().clone()
    }

    pub fn accept(
        &self,
        etag: String,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut headers = headers.unwrap_or_default();
        headers.push(Header::Other("SIP-ETag".into(), etag.clone()));

        let resp = self.inner.make_response(
            &self.inner.initial_request.lock(),
            StatusCode::OK,
            Some(headers),
            body,
        );

        *self.etag.lock() = Some(etag);

        use crate::transaction::transaction::TransactionEvent;
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        self.inner
            .transition(DialogState::Confirmed(self.id(), resp))?;
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.close_with_headers(None).await
    }

    pub async fn close_with_headers(
        &self,
        extra_headers: Option<Vec<crate::sip::Header>>,
    ) -> Result<()> {
        let mut headers = extra_headers.unwrap_or_default();
        headers.push(Header::Expires(0.into()));
        if let Some(etag) = self.etag() {
            headers.push(Header::Other("SIP-If-Match".into(), etag));
        }
        self.request(Method::Publish, Some(headers), None).await?;
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UasBye))?;
        Ok(())
    }

    pub async fn request(
        &self,
        method: crate::sip::Method,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        let request = self
            .inner
            .make_request(method, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    pub async fn refer(
        &self,
        refer_to: impl Into<crate::sip::ReferTo>,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        let mut headers = headers.unwrap_or_default();
        headers.push(crate::sip::Header::ReferTo(refer_to.into()));
        self.request(crate::sip::Method::Refer, Some(headers), body)
            .await
    }

    pub async fn message(
        &self,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        self.request(crate::sip::Method::Message, headers, body)
            .await
    }

    pub async fn handle(
        &mut self,
        tx: &mut crate::transaction::transaction::Transaction,
    ) -> Result<()> {
        match tx.original.method {
            Method::Publish => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Publish(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;
                self.inner.process_transaction_handle(tx, rx).await
            }
            _ => Ok(()),
        }
    }
}
