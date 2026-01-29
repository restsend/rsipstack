use super::dialog::{Dialog, DialogInnerRef, DialogState, TerminatedReason, TransactionHandle};
use super::subscription::ServerSubscriptionDialog;
use super::DialogId;
use crate::rsip_ext::parse_rack_header;
use crate::{
    transaction::transaction::{Transaction, TransactionEvent},
    Result,
};
use rsip::{prelude::HeadersExt, Header, Request, SipMessage, StatusCode};
use std::sync::atomic::Ordering;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// Server-side INVITE Dialog (UAS)
///
/// `ServerInviteDialog` represents a server-side INVITE dialog in SIP. This is used
/// when the local user agent acts as a User Agent Server (UAS) and receives
/// an INVITE transaction from a remote party to establish a session.
///
/// # Key Features
///
/// * **Session Acceptance** - Accepts or rejects incoming INVITE requests
/// * **In-dialog Requests** - Handles UPDATE, INFO, OPTIONS within established dialogs
/// * **Session Termination** - Handles BYE for ending sessions
/// * **Re-INVITE Support** - Supports session modification via re-INVITE
/// * **ACK Handling** - Properly handles ACK for 2xx responses
/// * **State Management** - Tracks dialog state transitions
///
/// # Dialog Lifecycle
///
/// 1. **Creation** - Dialog created when receiving INVITE
/// 2. **Processing** - Can send provisional responses (1xx)
/// 3. **Decision** - Accept (2xx) or reject (3xx-6xx) the INVITE
/// 4. **Wait ACK** - If accepted, wait for ACK from client
/// 5. **Confirmed** - ACK received, dialog established
/// 6. **Active** - Can handle in-dialog requests
/// 7. **Termination** - Receives BYE or sends BYE to end session
///
/// # Examples
///
/// ## Basic Call Handling
///
/// ```rust,no_run
/// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
/// # fn example() -> rsipstack::Result<()> {
/// # let dialog: ServerInviteDialog = todo!(); // Dialog is typically created by DialogLayer
/// # let answer_sdp = vec![];
/// // After receiving INVITE:
///
/// // Accept the call
/// dialog.accept(None, Some(answer_sdp))?;
///
/// // Or reject the call
/// dialog.reject(None, None);
/// # Ok(())
/// # }
/// ```
///
/// ```rust,no_run
/// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
/// # async fn example() -> rsipstack::Result<()> {
/// # let dialog: ServerInviteDialog = todo!();
/// // End an established call
/// dialog.bye().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Session Modification
///
/// ```rust,no_run
/// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
/// # async fn example() -> rsipstack::Result<()> {
/// # let dialog: ServerInviteDialog = todo!();
/// # let new_sdp = vec![];
/// // Send re-INVITE to modify session
/// let headers = vec![
///     rsip::Header::ContentType("application/sdp".into())
/// ];
/// let response = dialog.reinvite(Some(headers), Some(new_sdp)).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// ServerInviteDialog is thread-safe and can be cloned and shared across tasks.
/// All operations are atomic and properly synchronized.
#[derive(Clone)]
pub struct ServerInviteDialog {
    pub(super) inner: DialogInnerRef,
}

impl ServerInviteDialog {
    /// Get the dialog identifier
    ///
    /// Returns the unique DialogId that identifies this dialog instance.
    /// The DialogId consists of Call-ID, from-tag, and to-tag.
    pub fn id(&self) -> DialogId {
        self.inner.id.lock().unwrap().clone()
    }

    pub fn state(&self) -> DialogState {
        self.inner.state.lock().unwrap().clone()
    }

    pub fn from_inner(inner: DialogInnerRef) -> Self {
        Self { inner }
    }

    pub fn snapshot(&self) -> super::dialog::DialogSnapshot {
        self.inner.snapshot()
    }

    /// Get the cancellation token for this dialog
    ///
    /// Returns a reference to the CancellationToken that can be used to
    /// cancel ongoing operations for this dialog.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }

    /// Get the initial INVITE request
    ///
    /// Returns a reference to the initial INVITE request that created
    /// this dialog. This can be used to access the original request
    /// headers, body, and other information.
    pub fn initial_request(&self) -> Request {
        self.inner
            .initial_request
            .lock()
            .expect("get initial request posioned")
            .clone()
    }

    pub fn ringing(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> Result<()> {
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
        self.inner.transition(DialogState::Early(self.id(), resp));
        Ok(())
    }
    /// Accept the incoming INVITE request
    ///
    /// Sends a 200 OK response to accept the incoming INVITE request.
    /// This establishes the dialog and transitions it to the WaitAck state,
    /// waiting for the ACK from the client.
    ///
    /// # Parameters
    ///
    /// * `headers` - Optional additional headers to include in the response
    /// * `body` - Optional message body (typically SDP answer)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Response sent successfully
    /// * `Err(Error)` - Failed to send response or transaction terminated
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// // Accept with SDP answer
    /// let answer_sdp = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n...";
    /// let headers = vec![
    ///     rsip::Header::ContentType("application/sdp".into())
    /// ];
    /// dialog.accept(Some(headers), Some(answer_sdp.to_vec()))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> Result<()> {
        let resp =
            self.inner
                .make_response(&self.initial_request(), rsip::StatusCode::OK, headers, body);
        self.inner
            .tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;

        self.inner.transition(DialogState::WaitAck(self.id(), resp));
        Ok(())
    }

    /// Accept the incoming INVITE request with NAT-aware Contact header
    ///
    /// Sends a 200 OK response to accept the incoming INVITE request, automatically
    /// adding a Contact header with the provided public address for proper NAT traversal.
    /// This is the recommended method when working with NAT environments.
    ///
    /// # Parameters
    ///
    /// * `username` - SIP username for the Contact header
    /// * `public_address` - Optional public address discovered via registration
    /// * `local_address` - Local SIP address as fallback
    /// * `headers` - Optional additional headers to include
    /// * `body` - Optional SDP answer body
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Response sent successfully
    /// * `Err(Error)` - Failed to send response or transaction terminated
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # use rsipstack::transport::SipAddr;
    /// # use std::net::{IpAddr, Ipv4Addr};
    /// # fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// # let local_addr: SipAddr = todo!();
    /// let public_addr = Some(rsip::HostWithPort {
    ///     host: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)).into(),
    ///     port: Some(5060.into()),
    /// });
    /// let answer_sdp = b"v=0\r\no=- 123 456 IN IP4 203.0.113.1\r\n...";
    /// let headers = vec![
    ///     rsip::Header::ContentType("application/sdp".into())
    /// ];
    ///
    /// dialog.accept_with_public_contact(
    ///     "alice",
    ///     public_addr,
    ///     &local_addr,
    ///     Some(headers),
    ///     Some(answer_sdp.to_vec())
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_with_public_contact(
        &self,
        username: &str,
        public_address: Option<rsip::HostWithPort>,
        local_address: &crate::transport::SipAddr,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        use super::registration::Registration;

        // Create NAT-aware Contact header
        let contact_header =
            Registration::create_nat_aware_contact(username, public_address, local_address);

        // Combine provided headers with Contact header
        let mut final_headers = headers.unwrap_or_default();
        final_headers.push(contact_header.into());

        // Use the regular accept method with the enhanced headers
        self.accept(Some(final_headers), body)
    }

    /// Reject the incoming INVITE request
    ///
    /// Sends a reject response to reject the incoming INVITE request.
    /// Sends a 603 Decline by default, or a custom status code if provided.
    /// This terminates the dialog creation process.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Response sent successfully
    /// * `Err(Error)` - Failed to send response or transaction terminated
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// // Reject the incoming call
    /// dialog.reject(Some(rsip::StatusCode::BusyHere), Some("Busy here".into()));
    /// # Ok(())
    /// # }
    /// ```
    pub fn reject(&self, code: Option<rsip::StatusCode>, reason: Option<String>) {
        if self.inner.is_terminated() || self.inner.is_confirmed() {
            return;
        }
        debug!(id=%self.id(), ?code, ?reason, "rejecting dialog");
        let headers = if let Some(reason) = reason {
            Some(vec![rsip::Header::Other("Reason".into(), reason.into())])
        } else {
            None
        };
        let resp = self.inner.make_response(
            &self.initial_request(),
            code.unwrap_or(rsip::StatusCode::Decline),
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

    /// Send a BYE request to terminate the dialog.
    ///
    /// Thin wrapper over `bye_with_headers(None)`.
    ///
    /// The dialog must be in `Confirmed` state (or `WaitAck`) for BYE to be sent;
    /// otherwise this method is a no-op.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// dialog.bye().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bye(&self) -> Result<()> {
        self.bye_with_headers(None).await
    }

    /// Send a BYE request with custom headers to terminate the dialog.
    ///
    /// This is the low-level variant used to add SIP headers (e.g. `Reason`)
    /// to the outgoing BYE request.
    ///
    /// The dialog must be in `Confirmed` state (or `WaitAck`) for BYE to be sent;
    /// otherwise this method is a no-op.
    ///
    /// # Parameters
    /// * `headers` - Optional extra SIP headers to include in the BYE request.
    ///
    /// # Returns
    /// * `Ok(())` - BYE was sent successfully or dialog is not in a state where BYE applies.
    /// * `Err(Error)` - Failed to build/send BYE request.
    pub async fn bye_with_headers(&self, headers: Option<Vec<rsip::Header>>) -> Result<()> {
        if !self.inner.is_confirmed() && !self.inner.waiting_ack() {
            return Ok(());
        }

        let request =
            self.inner
                .make_request(rsip::Method::Bye, None, None, None, headers, None)?;

        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UasBye));
        self.inner.do_request(request).await.map(|_| ())
    }

    /// Send a BYE request with a SIP `Reason` header.
    ///
    /// Convenience wrapper over `bye_with_headers()` that adds:
    /// `Reason: <reason>`.
    ///
    /// Typical values:
    /// * `SIP;cause=804;text="MEDIA_TIMEOUT"`
    /// * `Q.850;cause=16;text="Normal call clearing"`
    ///
    /// # Parameters
    /// * `reason` - Value of the `Reason` header (without the `Reason:` name).
    pub async fn bye_with_reason(&self, reason: String) -> Result<()> {
        self.bye_with_headers(Some(vec![rsip::Header::Other(
            "Reason".into(),
            reason.into(),
        )]))
        .await
    }

    /// Send a re-INVITE request to modify the session
    /// Sends a re-INVITE request within an established dialog to modify
    /// the session parameters (e.g., change media, add/remove streams).
    /// This can only be called for confirmed dialogs.
    ///
    /// # Parameters
    ///
    /// * `headers` - Optional additional headers to include
    /// * `body` - Optional message body (typically new SDP)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Response))` - Response to the re-INVITE
    /// * `Ok(None)` - Dialog not confirmed, no request sent
    /// * `Err(Error)` - Failed to send re-INVITE
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// let new_sdp = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n...";
    /// let response = dialog.reinvite(None, Some(new_sdp.to_vec())).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn reinvite(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(id = %self.id(), ?body, "sending re-invite request");
        let request =
            self.inner
                .make_request(rsip::Method::Invite, None, None, None, headers, body)?;
        let resp = self.inner.do_request(request.clone()).await;
        match resp {
            Ok(Some(ref resp)) => {
                if resp.status_code == StatusCode::OK {
                    let (handle, _) = TransactionHandle::new();
                    self.inner
                        .transition(DialogState::Updated(self.id(), request, handle));
                }
            }
            _ => {}
        }
        resp
    }

    /// Send an UPDATE request to modify session parameters
    ///
    /// Sends an UPDATE request within an established dialog to modify
    /// session parameters without the complexity of a re-INVITE.
    /// This is typically used for smaller session modifications.
    ///
    /// # Parameters
    ///
    /// * `headers` - Optional additional headers to include
    /// * `body` - Optional message body (typically SDP)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Response))` - Response to the UPDATE
    /// * `Ok(None)` - Dialog not confirmed, no request sent
    /// * `Err(Error)` - Failed to send UPDATE
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// # let sdp_body = vec![];
    /// let response = dialog.update(None, Some(sdp_body)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(id = %self.id(), ?body, "sending update request");
        let request =
            self.inner
                .make_request(rsip::Method::Update, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }

    /// Send an INFO request for mid-dialog information
    ///
    /// Sends an INFO request within an established dialog to exchange
    /// application-level information. This is commonly used for DTMF
    /// tones, but can carry any application-specific data.
    ///
    /// # Parameters
    ///
    /// * `headers` - Optional additional headers to include
    /// * `body` - Optional message body (application-specific data)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Response))` - Response to the INFO
    /// * `Ok(None)` - Dialog not confirmed, no request sent
    /// * `Err(Error)` - Failed to send INFO
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::server_dialog::ServerInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ServerInviteDialog = todo!();
    /// // Send DTMF tone
    /// let dtmf_body = b"Signal=1\r\nDuration=100\r\n";
    /// let headers = vec![
    ///     rsip::Header::ContentType("application/dtmf-relay".into())
    /// ];
    /// let response = dialog.info(Some(headers), Some(dtmf_body.to_vec())).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn info(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(id = %self.id(), ?body, "sending info request");
        let request =
            self.inner
                .make_request(rsip::Method::Info, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }

    /// Send a generic in-dialog request
    pub async fn request(
        &self,
        method: rsip::Method,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        debug!(id = %self.id(), %method, "sending request");
        let request = self
            .inner
            .make_request(method, None, None, None, headers, body)?;
        self.inner.do_request(request).await
    }

    /// Send a NOTIFY request
    pub async fn notify(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        self.request(rsip::Method::Notify, headers, body).await
    }

    /// Send a REFER request
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

    /// Send a REFER progress notification (RFC 3515)
    ///
    /// This is used by the REFER recipient to notify the sender about the
    /// progress of the referred action.
    ///
    /// # Parameters
    ///
    /// * `status` - The status of the referred action (e.g., 100 Trying, 200 OK)
    /// * `sub_state` - The subscription state (e.g., "active", "terminated;reason=noresource")
    pub async fn notify_refer(
        &self,
        status: rsip::StatusCode,
        sub_state: &str,
    ) -> Result<Option<rsip::Response>> {
        let headers = vec![
            rsip::Header::Other("Event".into(), "refer".into()),
            rsip::Header::Other("Subscription-State".into(), sub_state.into()),
            rsip::Header::ContentType("message/sipfrag".into()),
        ];

        let body = format!("SIP/2.0 {} {:?}", u16::from(status.clone()), status).into_bytes();

        self.notify(Some(headers), Some(body)).await
    }

    /// Convert this INVITE dialog to a subscription dialog
    ///
    /// This is useful for handling implicit subscriptions created by REFER.
    pub fn as_subscription(&self) -> ServerSubscriptionDialog {
        ServerSubscriptionDialog {
            inner: self.inner.clone(),
        }
    }

    /// Send a MESSAGE request
    pub async fn message(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        self.request(rsip::Method::Message, headers, body).await
    }

    /// Handle incoming transaction for this dialog
    ///
    /// Processes incoming SIP requests that are routed to this dialog.
    /// This method handles sequence number validation and dispatches
    /// to appropriate handlers based on the request method and dialog state.
    ///
    /// # Parameters
    ///
    /// * `tx` - The incoming transaction to handle
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request handled successfully
    /// * `Err(Error)` - Failed to handle request
    ///
    /// # Supported Methods
    ///
    /// * `ACK` - Confirms 2xx response (transitions to Confirmed state)
    /// * `BYE` - Terminates the dialog
    /// * `INFO` - Handles information exchange
    /// * `OPTIONS` - Handles capability queries
    /// * `UPDATE` - Handles session updates
    /// * `INVITE` - Handles initial INVITE or re-INVITE
    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(
            id = %self.id(),
            method = %tx.original.method,
            state = %self.inner.state.lock().unwrap(),
            "handle request"
        );

        let cseq = tx.original.cseq_header()?.seq()?;
        let remote_seq = self.inner.remote_seq.load(Ordering::Relaxed);
        if remote_seq > 0 && cseq < remote_seq {
            debug!(
                id = %self.id(),
                method = %tx.original.method(),
                remote_seq = %remote_seq,
                cseq = %cseq,
                "received old request"
            );
            // discard old request
            return Ok(());
        }
        self.inner
            .remote_seq
            .compare_exchange(remote_seq, cseq, Ordering::Relaxed, Ordering::Relaxed)
            .ok();

        if self.inner.is_confirmed() {
            match tx.original.method {
                rsip::Method::Cancel => {
                    debug!(
                        id = %self.id(),
                        method = %tx.original.method,
                        uri = %tx.original.uri,
                        "invalid request received"
                    );
                    tx.reply(rsip::StatusCode::OK).await?;
                    return Ok(());
                }
                rsip::Method::Ack => {
                    debug!(
                        id = %self.id(),
                        method = %tx.original.method,
                        uri = %tx.original.uri,
                        "invalid request received"
                    );
                    return Err(crate::Error::DialogError(
                        "invalid request in confirmed state".to_string(),
                        self.id(),
                        rsip::StatusCode::MethodNotAllowed,
                    ));
                }
                rsip::Method::Invite => return self.handle_reinvite(tx).await,
                rsip::Method::Bye => return self.handle_bye(tx).await,
                rsip::Method::PRack => return self.handle_prack(tx).await,
                rsip::Method::Info => return self.handle_info(tx).await,
                rsip::Method::Options => return self.handle_options(tx).await,
                rsip::Method::Update => return self.handle_update(tx).await,
                rsip::Method::Refer => return self.handle_refer(tx).await,
                rsip::Method::Message => return self.handle_message(tx).await,
                rsip::Method::Notify => return self.handle_notify(tx).await,
                _ => {
                    debug!(id = %self.id(), method = ?tx.original.method, "invalid request method");
                    tx.reply(rsip::StatusCode::MethodNotAllowed).await?;
                    return Err(crate::Error::DialogError(
                        "invalid request".to_string(),
                        self.id(),
                        rsip::StatusCode::MethodNotAllowed,
                    ));
                }
            }
        }

        match tx.original.method {
            rsip::Method::Invite => return self.handle_invite(tx).await,
            rsip::Method::PRack => return self.handle_prack(tx).await,
            rsip::Method::Ack => {
                self.inner.tu_sender.send(TransactionEvent::Received(
                    tx.original.clone().into(),
                    tx.connection.clone(),
                ))?;
                return Ok(());
            }
            _ => {
                // ignore other requests in non-confirmed state
                return Ok(());
            }
        }
    }

    async fn handle_bye(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received bye");
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UacBye));
        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_info(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received info");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Info(self.id(), tx.original.clone(), handle));
        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_prack(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received prack");

        if parse_rack_header(&tx.original.headers).is_none() {
            warn!(id = %self.id(), "received PRACK without RAck header");
            tx.reply(rsip::StatusCode::BadRequest).await?;
            return Ok(());
        }

        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_options(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received options");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Options(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_update(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received update");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Updated(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_refer(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received refer");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Refer(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_message(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received message");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Message(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_notify(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), uri = %tx.original.uri, "received notify");
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Notify(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await
    }

    async fn handle_reinvite(&mut self, tx: &mut Transaction) -> Result<()> {
        debug!(id = %self.id(), "received re-invite {}", tx.original.uri);
        let (handle, rx) = TransactionHandle::new();
        self.inner
            .transition(DialogState::Updated(self.id(), tx.original.clone(), handle));

        self.inner.process_transaction_handle(tx, rx).await?;

        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Request(req) => match req.method {
                    rsip::Method::Ack => {
                        debug!(id = %self.id(),"received ack for re-invite {}", req.uri);
                        self.inner.transition(DialogState::Confirmed(
                            self.id(),
                            tx.last_response.clone().unwrap_or_default(),
                        ));
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_invite(&mut self, tx: &mut Transaction) -> Result<()> {
        let handle_loop = async {
            if !self.inner.is_confirmed() && matches!(tx.original.method, rsip::Method::Invite) {
                self.inner.transition(DialogState::Calling(self.id()));
                tx.send_trying().await.ok();
            }

            while let Some(msg) = tx.receive().await {
                match msg {
                    SipMessage::Request(req) => match req.method {
                        rsip::Method::Ack => {
                            if self.inner.is_terminated() {
                                // dialog already terminated, ignore
                                break;
                            }
                            debug!(id = %self.id(),"received ack {}", req.uri);
                            self.inner.transition(DialogState::Confirmed(
                                self.id(),
                                tx.last_response.clone().unwrap_or_default(),
                            ));
                            break;
                        }
                        rsip::Method::Cancel => {
                            debug!(id = %self.id(),"received cancel {}", req.uri);
                            tx.reply(rsip::StatusCode::RequestTerminated).await?;
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::UacCancel,
                            ));
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
                trace!(id = %self.id(),"process done");
                Ok(())
            }
            Err(e) => {
                warn!(id = %self.id(),"handle_invite error: {:?}", e);
                Err(e)
            }
        }
    }
}

impl TryFrom<&Dialog> for ServerInviteDialog {
    type Error = crate::Error;

    fn try_from(dlg: &Dialog) -> Result<Self> {
        match dlg {
            Dialog::ServerInvite(dlg) => Ok(dlg.clone()),
            _ => Err(crate::Error::DialogError(
                "Dialog is not a ServerInviteDialog".to_string(),
                dlg.id(),
                rsip::StatusCode::BadRequest,
            )),
        }
    }
}
