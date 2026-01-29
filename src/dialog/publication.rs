use super::dialog::{DialogInnerRef, DialogState, TerminatedReason, TransactionHandle};
use super::DialogId;
use crate::Result;
use rsip::{Header, Method, StatusCode, StatusCodeKind};
use std::sync::{Arc, Mutex};
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
        self.inner.id.lock().unwrap().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().unwrap().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub fn etag(&self) -> Option<String> {
        self.etag.lock().unwrap().clone()
    }

    pub async fn publish(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        let mut headers = headers.unwrap_or_default();
        if let Some(etag) = self.etag() {
            headers.push(Header::Other("SIP-If-Match".into(), etag.into()));
        }

        let resp = self.request(Method::Publish, Some(headers), body).await?;
        if let Some(ref response) = resp {
            if matches!(response.status_code.kind(), StatusCodeKind::Successful) {
                if let Some(etag_header) = response.headers.iter().find(|h| {
                    if let Header::Other(name, _) = h {
                        name.to_string().eq_ignore_ascii_case("SIP-ETag")
                    } else {
                        false
                    }
                }) {
                    if let Header::Other(_, value) = etag_header {
                        *self.etag.lock().unwrap() = Some(value.to_string());
                    }
                }
            }
        }
        Ok(resp)
    }

    pub async fn close(&self) -> Result<()> {
        let mut headers = vec![Header::Expires(0.into())];
        if let Some(etag) = self.etag() {
            headers.push(Header::Other("SIP-If-Match".into(), etag.into()));
        }
        self.request(Method::Publish, Some(headers), None).await?;
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UacBye));
        Ok(())
    }

    pub async fn request(
        &self,
        method: rsip::Method,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        let request = self
            .inner
            .make_request(method, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    pub async fn refer(
        &self,
        refer_to: rsip::Uri,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        let mut headers = headers.unwrap_or_default();
        headers.push(rsip::Header::Other(
            "Refer-To".into(),
            format!("<{}>", refer_to).into(),
        ));
        self.request(rsip::Method::Refer, Some(headers), body).await
    }

    pub async fn message(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        self.request(rsip::Method::Message, headers, body).await
    }

    pub async fn handle(
        &mut self,
        tx: &mut crate::transaction::transaction::Transaction,
    ) -> Result<()> {
        match tx.original.method {
            Method::Publish => {
                let (handle, rx) = TransactionHandle::new();
                self.inner
                    .transition(DialogState::Publish(self.id(), tx.original.clone(), handle));
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
        self.inner.id.lock().unwrap().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().unwrap().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub fn etag(&self) -> Option<String> {
        self.etag.lock().unwrap().clone()
    }

    pub fn accept(
        &self,
        etag: String,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut headers = headers.unwrap_or_default();
        headers.push(Header::Other("SIP-ETag".into(), etag.clone().into()));

        let resp = self.inner.make_response(
            &self.inner.initial_request.lock().unwrap(),
            StatusCode::OK,
            Some(headers),
            body,
        );

        *self.etag.lock().unwrap() = Some(etag);

        use crate::transaction::transaction::TransactionEvent;
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        self.inner
            .transition(DialogState::Confirmed(self.id(), resp));
        Ok(())
    }

    pub async fn close(&self) {
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UasBye));
    }

    pub async fn request(
        &self,
        method: rsip::Method,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
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
        refer_to: rsip::Uri,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        let mut headers = headers.unwrap_or_default();
        headers.push(rsip::Header::Other(
            "Refer-To".into(),
            format!("<{}>", refer_to).into(),
        ));
        self.request(rsip::Method::Refer, Some(headers), body).await
    }

    pub async fn message(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        self.request(rsip::Method::Message, headers, body).await
    }

    pub async fn handle(
        &mut self,
        tx: &mut crate::transaction::transaction::Transaction,
    ) -> Result<()> {
        match tx.original.method {
            Method::Publish => {
                let (handle, rx) = TransactionHandle::new();
                self.inner
                    .transition(DialogState::Publish(self.id(), tx.original.clone(), handle));
                self.inner.process_transaction_handle(tx, rx).await
            }
            _ => Ok(()),
        }
    }
}
