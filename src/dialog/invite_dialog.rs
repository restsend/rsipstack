//! Unified INVITE dialog (`InviteDialog`).
//!
//! `InviteDialog` is the role-agnostic INVITE dialog type. It wraps the same
//! [`DialogInnerRef`] as the legacy [`ServerInviteDialog`] /
//! [`ClientInviteDialog`] wrappers and exposes the full method surface of
//! both, with role-specific behavior selected by [`InviteDialog::role`].
//!
//! This is the preferred type going forward; the legacy types are retained
//! as thin forwarding wrappers marked `#[deprecated]`.
//!
//! [`ServerInviteDialog`]: crate::dialog::server_dialog::ServerInviteDialog
//! [`ClientInviteDialog`]: crate::dialog::client_dialog::ClientInviteDialog

use super::dialog::{Dialog, DialogInnerRef, DialogState, TerminatedReason, TransactionHandle};
use super::subscription::{ClientSubscriptionDialog, ServerSubscriptionDialog};
use super::DialogId;
use crate::sip::prelude::{HasHeaders, HeadersExt};
use crate::sip::{Header, Method, Request, Response, SipMessage, StatusCode};
use crate::transaction::key::TransactionRole;
use crate::transaction::transaction::{Transaction, TransactionEvent};
use crate::Result;
use std::sync::atomic::Ordering;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// Unified INVITE dialog that can act as either a UAS (Server) or UAC (Client).
///
/// Role-specific methods (e.g. `ringing`/`accept`/`reject` for UAS, or
/// `cancel`/`hangup`/`options`/`process_invite` for UAC) are no-ops when
/// invoked on the "wrong" role.
#[derive(Clone)]
pub struct InviteDialog {
    pub(super) inner: DialogInnerRef,
}

impl InviteDialog {
    pub fn from_inner(inner: DialogInnerRef) -> Self {
        Self { inner }
    }

    /// The dialog role (Client = UAC we initiated, Server = UAS we received).
    pub fn role(&self) -> TransactionRole {
        self.inner.role
    }

    pub fn id(&self) -> DialogId {
        self.inner.id.lock().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().clone()
    }

    pub fn snapshot(&self) -> super::dialog::DialogSnapshot {
        self.inner.snapshot()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    /// The initial INVITE request that created this dialog.
    pub fn initial_request(&self) -> Request {
        self.inner.initial_request.lock().clone()
    }

    // ── UAS (Server) semantics ────────────────────────────────────────────

    /// Send `180 Ringing` (or `183 Session Progress` when a body is given).
    /// No-op for UAC dialogs.
    pub fn ringing(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> Result<()> {
        if self.role() != TransactionRole::Server {
            return Ok(());
        }
        if !self.inner.can_cancel() {
            return Ok(());
        }
        debug!(id = %self.id(), "sending ringing response");
        let resp = self.inner.make_response(
            &self.initial_request(),
            if body.is_some() {
                StatusCode::SessionProgress
            } else {
                StatusCode::Ringing
            },
            headers,
            body,
        );
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        self.inner.transition(DialogState::Early(self.id(), resp))?;
        Ok(())
    }

    /// Accept the incoming INVITE with a `200 OK`.
    /// No-op for UAC dialogs.
    pub fn accept(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> Result<()> {
        if self.role() != TransactionRole::Server {
            return Ok(());
        }
        let resp = self
            .inner
            .make_response(&self.initial_request(), StatusCode::OK, headers, body);
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        self.inner
            .transition(DialogState::WaitAck(self.id(), resp))?;
        Ok(())
    }

    /// Accept the incoming INVITE with a NAT-aware public Contact header.
    /// No-op for UAC dialogs.
    pub fn accept_with_public_contact(
        &self,
        username: &str,
        public_address: Option<crate::sip::HostWithPort>,
        local_address: &crate::transport::SipAddr,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        use super::registration::Registration;

        let contact_header =
            Registration::create_nat_aware_contact(username, public_address, local_address);

        let mut final_headers = headers.unwrap_or_default();
        final_headers.push(contact_header.into());

        self.accept(Some(final_headers), body)
    }

    /// Reject the incoming INVITE (default `603 Decline`).
    /// No-op for UAC dialogs.
    pub fn reject(&self, code: Option<StatusCode>, reason: Option<String>) -> Result<()> {
        if self.role() != TransactionRole::Server {
            return Ok(());
        }
        if self.inner.is_terminated() || self.inner.is_confirmed() {
            return Ok(());
        }
        debug!(id = %self.id(), ?code, ?reason, "rejecting dialog");
        let headers = reason.map(|reason| vec![Header::Reason(reason.into())]);
        let resp = self.inner.make_response(
            &self.initial_request(),
            code.unwrap_or(StatusCode::Decline),
            headers,
            None,
        );
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp))
            .ok();
        self.inner.transition(DialogState::Terminated(
            self.id(),
            TerminatedReason::UasDecline,
        ))
    }

    // ── UAC (Client) semantics ────────────────────────────────────────────

    /// Send a BYE request to terminate the dialog.
    /// No-op for UAS dialogs (which terminate via `hangup_with_headers`).
    pub async fn hangup(&self) -> Result<()> {
        self.hangup_with_headers(None).await
    }

    /// Terminate the dialog: send BYE when confirmed, CANCEL when still early.
    /// Role-agnostic — `cancel()` internally guards against non-UAC dialogs,
    /// and `bye_with_headers()` handles the confirmed UAS/UAC case uniformly.
    pub async fn hangup_with_headers(&self, headers: Option<Vec<Header>>) -> Result<()> {
        if self.inner.can_cancel() {
            self.cancel().await
        } else {
            self.bye_with_headers(headers).await
        }
    }

    /// Hang up and attach a SIP `Reason` header to the BYE.
    /// No-op for UAS dialogs.
    pub async fn hangup_with_reason(&self, reason: String) -> Result<()> {
        self.hangup_with_headers(Some(vec![Header::Reason(reason.into())]))
            .await
    }

    /// Send a CANCEL request to abort an unanswered INVITE.
    /// No-op for UAS dialogs.
    pub async fn cancel(&self) -> Result<()> {
        if self.role() != TransactionRole::Client {
            return Ok(());
        }
        if self.inner.is_confirmed() {
            return Ok(());
        }
        debug!(id = %self.id(), "sending cancel request");
        let mut cancel_request = self.inner.initial_request.lock().clone();
        let invite_seq = cancel_request.cseq_header()?.seq()?;
        cancel_request
            .headers_mut()
            .retain(|h| !matches!(h, Header::ContentLength(_) | Header::ContentType(_)));

        cancel_request.method = Method::Cancel;
        cancel_request
            .cseq_header_mut()?
            .mut_seq(invite_seq)?
            .mut_method(Method::Cancel)?;
        cancel_request.body = vec![];
        self.inner.do_request(cancel_request).await?;
        Ok(())
    }

    /// Send an OPTIONS request within the dialog.
    /// No-op for UAS dialogs.
    pub async fn options(&self, headers: Option<Vec<Header>>) -> Result<Option<Response>> {
        if self.role() != TransactionRole::Client {
            return Ok(None);
        }
        self.request(Method::Options, headers, None).await
    }

    /// Drive the outbound INVITE transaction until a final response arrives.
    /// Only meaningful for UAC dialogs.
    pub async fn process_invite(
        &self,
        tx: &mut Transaction,
    ) -> Result<(DialogId, Option<Response>)> {
        if self.role() != TransactionRole::Client {
            return Err(crate::Error::DialogError(
                "process_invite requires a UAC (Client) dialog".to_string(),
                self.id(),
                StatusCode::ServerInternalError,
            ));
        }
        use super::authenticate::handle_client_authenticate;

        self.inner.transition(DialogState::Calling(self.id()))?;
        let mut auth_sent = false;
        tx.send().await?;
        let mut dialog_id = self.id();
        let mut final_response = None;
        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Request(_) => {}
                SipMessage::Response(resp) => {
                    let status = resp.status_code.clone();

                    if status == StatusCode::Trying {
                        self.inner.transition(DialogState::Trying(self.id()))?;
                        continue;
                    }

                    if matches!(status.kind(), crate::sip::StatusCodeKind::Provisional) {
                        self.inner.handle_provisional_response(&resp).await?;
                        self.inner.transition(DialogState::Early(self.id(), resp))?;
                        continue;
                    }

                    if matches!(
                        status,
                        StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized
                    ) {
                        if auth_sent {
                            final_response = Some(resp.clone());
                            debug!(id = %self.id(), ?status, "received auth response after auth sent");
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            break;
                        }
                        auth_sent = true;
                        if let Some(credential) = &self.inner.credential {
                            *tx = handle_client_authenticate(
                                self.inner.increment_local_seq(),
                                tx,
                                resp,
                                credential,
                            )
                            .await?;
                            tx.send().await?;
                            self.inner.update_remote_tag("").ok();
                            {
                                let mut req = self.inner.initial_request.lock();
                                *req = tx.original.clone();
                            }
                            continue;
                        } else {
                            debug!(id = %self.id(), "received 407 response without auth option");
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            continue;
                        }
                    }
                    final_response = Some(resp.clone());
                    if let Some(tag) = resp.to_header()?.tag()? {
                        self.inner.update_remote_tag(tag.value())?
                    }

                    if let Ok(id) = DialogId::try_from((&resp, TransactionRole::Client)) {
                        dialog_id = id;
                    }
                    match resp.status_code {
                        StatusCode::Ringing | StatusCode::SessionProgress
                            if resp
                                .to_header()
                                .ok()
                                .and_then(|h| h.tag().ok().flatten())
                                .is_some() =>
                        {
                            self.inner.update_route_set_from_response(&resp);
                        }
                        StatusCode::OK => {
                            self.inner.update_route_set_from_response(&resp);
                            let contact = resp.contact_header()?;
                            self.inner.remote_contact.lock().replace(contact.clone());

                            let contact_uri = resp
                                .typed_contact_headers()?
                                .first()
                                .map(|c| c.uri.clone())
                                .ok_or_else(|| {
                                    crate::Error::Error("missing Contact header".to_string())
                                })?;
                            *self.inner.remote_uri.lock() = contact_uri;
                            self.inner
                                .transition(DialogState::Confirmed(dialog_id.clone(), resp))?;
                        }
                        _ => {
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::UasOther(resp.status_code.clone()),
                            ))?;
                        }
                    }
                    break;
                }
            }
        }
        Ok((dialog_id, final_response))
    }

    // ── Shared request semantics ──────────────────────────────────────────

    /// Send a BYE request to terminate the dialog.
    /// Convenience alias for [`bye_with_headers`](Self::bye_with_headers).
    pub async fn bye(&self) -> Result<()> {
        self.bye_with_headers(None).await
    }

    /// Send a BYE request with custom headers (role-aware termination reason).
    ///
    /// BYE can only be sent from `Confirmed` (or `WaitAck` for a server dialog).
    /// Calling BYE in any other non-terminated state returns an error; terminated
    /// dialogs remain a silent no-op.
    ///
    /// # Returns
    /// * `Ok(())` - BYE was sent successfully or dialog is already terminated.
    /// * `Err(Error)` - Failed to build/send BYE request, or dialog is in a state where BYE does not apply.
    pub async fn bye_with_headers(&self, headers: Option<Vec<Header>>) -> Result<()> {
        let confirmed_or_waiting_ack = self.inner.is_confirmed()
            || (self.role() == TransactionRole::Server && self.inner.waiting_ack());
        if !confirmed_or_waiting_ack {
            if !self.inner.is_terminated() {
                warn!(
                    dialog_id = %self.id(),
                    state = ?self.state(),
                    "bye skipped: dialog not confirmed or waiting ack"
                );
                return Err(crate::Error::Error(format!(
                    "dialog {} cannot send BYE in state {:?}",
                    self.id(),
                    self.state()
                )));
            }
            return Ok(());
        }

        let request = self
            .inner
            .make_request(Method::Bye, None, None, None, headers, None)?;

        self.inner.do_request(request).await?;
        let reason = match self.role() {
            TransactionRole::Server => TerminatedReason::UasBye,
            TransactionRole::Client => TerminatedReason::UacBye,
        };
        self.inner
            .transition(DialogState::Terminated(self.id(), reason))?;
        Ok(())
    }

    /// Send a BYE request with a SIP `Reason` header.
    pub async fn bye_with_reason(&self, reason: String) -> Result<()> {
        self.bye_with_headers(Some(vec![Header::Reason(reason.into())]))
            .await
    }

    /// Send a re-INVITE request to modify the session.
    pub async fn reinvite(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(
            id = %self.id(),
            body = ?body.as_deref().map(String::from_utf8_lossy),
            "sending re-invite request"
        );
        let request = self
            .inner
            .make_request(Method::Invite, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    /// Send an UPDATE request to modify session parameters.
    pub async fn update(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(
            id = %self.id(),
            body = ?body.as_deref().map(String::from_utf8_lossy),
            "sending update request"
        );
        let request = self
            .inner
            .make_request(Method::Update, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }

    /// Send an INFO request for mid-dialog information.
    pub async fn info(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(
            id = %self.id(),
            body = ?body.as_deref().map(String::from_utf8_lossy),
            "sending info request"
        );
        let request = self
            .inner
            .make_request(Method::Info, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }

    /// Send a generic in-dialog request.
    pub async fn request(
        &self,
        method: Method,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(id = %self.id(), %method, "sending request");
        let request = self
            .inner
            .make_request(method, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    /// Send a NOTIFY request.
    pub async fn notify(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        self.request(Method::Notify, headers, body).await
    }

    /// Send a REFER request to transfer the call.
    pub async fn refer(
        &self,
        refer_to: impl Into<crate::sip::ReferTo>,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        let mut headers = headers.unwrap_or_default();
        headers.push(Header::ReferTo(refer_to.into()));
        self.request(Method::Refer, Some(headers), body).await
    }

    /// Send a REFER progress notification (RFC 3515).
    pub async fn notify_refer(
        &self,
        status: StatusCode,
        sub_state: &str,
    ) -> Result<Option<Response>> {
        let headers = vec![
            Header::Event("refer".into()),
            Header::SubscriptionState(sub_state.into()),
            Header::ContentType("message/sipfrag".into()),
        ];

        let body = format!("SIP/2.0 {} {:?}", u16::from(status.clone()), status).into_bytes();

        self.notify(Some(headers), Some(body)).await
    }

    /// Send a MESSAGE request within the dialog.
    pub async fn message(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<Response>> {
        self.request(Method::Message, headers, body).await
    }

    /// Convert this INVITE dialog to a subscription dialog (role-aware).
    pub fn as_subscription(&self) -> super::dialog::Dialog {
        match self.role() {
            TransactionRole::Server => Dialog::ServerSubscription(ServerSubscriptionDialog {
                inner: self.inner.clone(),
            }),
            TransactionRole::Client => Dialog::ClientSubscription(ClientSubscriptionDialog {
                inner: self.inner.clone(),
            }),
        }
    }

    // ── Incoming request handling ─────────────────────────────────────────

    /// Handle an incoming transaction routed to this dialog.
    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        trace!(
            id = %self.id(),
            method = %tx.original.method,
            state = %self.inner.state.lock(),
            "handle request"
        );

        let cseq = tx.original.cseq_header()?.seq()?;
        let remote_seq = self.inner.remote_seq.load(Ordering::Relaxed);
        if remote_seq > 0 && cseq < remote_seq {
            match self.role() {
                // Server discards old requests silently.
                TransactionRole::Server => {
                    debug!(
                        id = %self.id(),
                        method = %tx.original.method(),
                        remote_seq = %remote_seq,
                        cseq = %cseq,
                        "received old request"
                    );
                    return Ok(());
                }
                // Client rejects old requests.
                TransactionRole::Client => {
                    debug!(
                        id = %self.id(),
                        remote_seq = %remote_seq,
                        cseq = %cseq,
                        "received old request"
                    );
                    tx.reply(StatusCode::ServerInternalError).await?;
                    return Ok(());
                }
            }
        }

        self.inner
            .remote_seq
            .compare_exchange(remote_seq, cseq, Ordering::Relaxed, Ordering::Relaxed)
            .ok();

        if self.inner.is_confirmed() {
            match tx.original.method {
                Method::Cancel => {
                    // UAS replies 200 to a CANCEL in confirmed state; UAC
                    // treats it as invalid.
                    if self.role() == TransactionRole::Server {
                        debug!(
                            id = %self.id(),
                            method = %tx.original.method,
                            uri = %tx.original.uri,
                            "received cancel in confirmed state"
                        );
                        tx.reply(StatusCode::OK).await?;
                        return Ok(());
                    }
                }
                Method::Ack => {
                    if self.role() == TransactionRole::Server {
                        debug!(
                            id = %self.id(),
                            method = %tx.original.method,
                            uri = %tx.original.uri,
                            "received ack in confirmed state"
                        );
                        return Err(crate::Error::DialogError(
                            "invalid request in confirmed state".to_string(),
                            self.id(),
                            StatusCode::MethodNotAllowed,
                        ));
                    }
                }
                Method::Invite => return self.handle_reinvite(tx).await,
                Method::Bye => return self.handle_bye(tx).await,
                Method::PRack => return self.handle_prack(tx).await,
                Method::Info => return self.handle_info(tx).await,
                Method::Options => return self.handle_options(tx).await,
                Method::Update => return self.handle_update(tx).await,
                Method::Refer => return self.handle_refer(tx).await,
                Method::Message => return self.handle_message(tx).await,
                Method::Notify => return self.handle_notify(tx).await,
                _ => {
                    debug!(id = %self.id(), method = ?tx.original.method, "invalid request method");
                    tx.reply(StatusCode::MethodNotAllowed).await?;
                    return Err(crate::Error::DialogError(
                        "invalid request".to_string(),
                        self.id(),
                        StatusCode::MethodNotAllowed,
                    ));
                }
            }
        }

        // Not confirmed — only the UAS side drives the INVITE transaction here.
        if self.role() == TransactionRole::Server {
            match tx.original.method {
                Method::Invite => return self.handle_invite(tx).await,
                Method::PRack => return self.handle_prack(tx).await,
                Method::Ack => {
                    self.inner.tu_sender.send(TransactionEvent::Received(
                        tx.original.clone().into(),
                        tx.connection.clone(),
                    ))?;
                    return Ok(());
                }
                // Accept BYE even in WaitAck state — remote may tear down call
                // before ACK arrives (common with SIP proxies)
                Method::Bye => return self.handle_bye(tx).await,
                _ => {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn handle_bye(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received bye");
        let reason = match self.role() {
            TransactionRole::Server => TerminatedReason::UacBye,
            TransactionRole::Client => TerminatedReason::UasBye,
        };
        self.inner
            .transition(DialogState::Terminated(self.id(), reason))?;
        tx.reply(StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_info(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received info");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Info(self.id(), tx.original.clone(), handle))?;
        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_prack(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received prack");

        let rack_ok = tx.original.rack_value().is_some()
            || tx
                .original
                .header_value("RAck")
                .and_then(|value| {
                    let mut items = value.split_whitespace();
                    let rseq = items.next()?.parse::<u32>().ok()?;
                    let cseq = items.next()?.parse::<u32>().ok()?;
                    let method = items.next()?.parse::<Method>().ok()?;
                    Some((rseq, cseq, method))
                })
                .is_some();

        if !rack_ok {
            warn!(id = %self.id(), "received PRACK without RAck header");
            tx.reply(StatusCode::BadRequest).await?;
            return Ok(());
        }

        tx.reply(StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_options(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received options");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Options(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_update(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received update");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Updated(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_refer(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received refer");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Refer(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_message(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received message");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Message(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_notify(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received notify");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Notify(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_reinvite(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), "received re-invite {}", tx.original.uri);
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Updated(self.id(), tx.original.clone(), handle))?;

        self.inner.process_transaction_handle(tx, rx).await?;

        while let Some(msg) = tx.receive().await {
            if let SipMessage::Request(req) = msg {
                if req.method == Method::Ack {
                    debug!(id = %self.id(), "received ack for re-invite {}", req.uri);
                    self.inner.transition(DialogState::Confirmed(
                        self.id(),
                        tx.last_response.clone().unwrap_or_default(),
                    ))?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_invite(&mut self, tx: &mut Transaction) -> Result<()> {
        let handle_loop = async {
            if !self.inner.is_confirmed()
                && matches!(tx.original.method, Method::Invite)
                && self
                    .inner
                    .transition(DialogState::Calling(self.id()))
                    .is_ok()
            {
                tx.send_trying().await.ok();
            }

            while let Some(msg) = tx.receive().await {
                match msg {
                    SipMessage::Request(req) => match req.method {
                        Method::Ack => {
                            if self.inner.is_terminated() {
                                break;
                            }
                            debug!(id = %self.id(), "received ack {}", req.uri);
                            self.inner.transition(DialogState::Confirmed(
                                self.id(),
                                tx.last_response.clone().unwrap_or_default(),
                            ))?;
                            break;
                        }
                        Method::Cancel => {
                            debug!(id = %self.id(), "received cancel {}", req.uri);
                            tx.reply(StatusCode::RequestTerminated).await?;
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::UacCancel,
                            ))?;
                            break;
                        }
                        _ => {}
                    },
                    SipMessage::Response(_) => {}
                }
            }
            Ok::<(), crate::Error>(())
        };
        match handle_loop.await {
            Ok(_) => {
                trace!(id = %self.id(), "process done");
                Ok(())
            }
            Err(e) => {
                warn!(id = %self.id(), "handle_invite error: {:?}", e);
                Err(e)
            }
        }
    }
}

impl From<crate::dialog::server_dialog::ServerInviteDialog> for InviteDialog {
    fn from(d: crate::dialog::server_dialog::ServerInviteDialog) -> Self {
        Self { inner: d.inner }
    }
}

impl From<crate::dialog::client_dialog::ClientInviteDialog> for InviteDialog {
    fn from(d: crate::dialog::client_dialog::ClientInviteDialog) -> Self {
        Self { inner: d.inner }
    }
}

impl TryFrom<InviteDialog> for crate::dialog::server_dialog::ServerInviteDialog {
    type Error = crate::Error;

    fn try_from(d: InviteDialog) -> Result<Self> {
        if d.role() != TransactionRole::Server {
            return Err(crate::Error::DialogError(
                "InviteDialog is not a Server dialog".to_string(),
                d.id(),
                StatusCode::BadRequest,
            ));
        }
        Ok(Self { inner: d.inner })
    }
}

impl TryFrom<InviteDialog> for crate::dialog::client_dialog::ClientInviteDialog {
    type Error = crate::Error;

    fn try_from(d: InviteDialog) -> Result<Self> {
        if d.role() != TransactionRole::Client {
            return Err(crate::Error::DialogError(
                "InviteDialog is not a Client dialog".to_string(),
                d.id(),
                StatusCode::BadRequest,
            ));
        }
        Ok(Self { inner: d.inner })
    }
}
