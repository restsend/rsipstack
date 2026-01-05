use super::dialog::{
    DialogInnerRef, DialogState, TerminatedReason, TransactionHandle,
};
use super::DialogId;
use crate::transaction::transaction::Transaction;
use crate::Result;
use rsip::{Header, Method, StatusCode};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ClientSubscriptionDialog {
    pub(super) inner: DialogInnerRef,
}

impl ClientSubscriptionDialog {
    pub fn id(&self) -> DialogId {
        self.inner.id.lock().unwrap().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().unwrap().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub async fn subscribe(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        self.request(Method::Subscribe, headers, body).await
    }

    pub async fn unsubscribe(&self) -> Result<()> {
        let headers = vec![Header::Expires(0.into())];
        self.request(Method::Subscribe, Some(headers), None).await?;
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UacBye))?;
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

    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        match tx.original.method {
            Method::Notify => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Notify(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;
                self.inner.process_transaction_handle(tx, rx).await
            }
            Method::Refer => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Refer(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;

                self.inner.process_transaction_handle(tx, rx).await
            }
            Method::Message => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Message(
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
pub struct ServerSubscriptionDialog {
    pub(super) inner: DialogInnerRef,
}

impl ServerSubscriptionDialog {
    pub fn id(&self) -> DialogId {
        self.inner.id.lock().unwrap().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().unwrap().clone()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    pub fn accept(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> Result<()> {
        let resp = self.inner.make_response(
            &self.inner.initial_request.lock().unwrap(),
            StatusCode::OK,
            headers,
            body,
        );
        use crate::transaction::transaction::TransactionEvent;
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        self.inner
            .transition(DialogState::Confirmed(self.id(), resp))?;
        Ok(())
    }

    pub async fn notify(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        let request = self.inner.make_request_with_vias(
            Method::Notify,
            None,
            self.inner.build_vias_from_request()?,
            headers,
            body,
        )?;
        self.inner.do_request(request).await
    }

    pub async fn unsubscribe(&self) -> Result<()> {
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UasBye))?;
        Ok(())
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
        let request = self.inner.make_request_with_vias(
            method,
            None,
            self.inner.build_vias_from_request()?,
            headers,
            body,
        )?;
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

    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        match tx.original.method {
            Method::Subscribe => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Updated(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;
                self.inner.process_transaction_handle(tx, rx).await
            }
            Method::Refer => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Refer(
                    self.id(),
                    tx.original.clone(),
                    handle,
                ))?;
                self.inner.process_transaction_handle(tx, rx).await
            }
            Method::Message => {
                let (handle, rx) = TransactionHandle::new();
                self.inner.transition(DialogState::Message(
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
