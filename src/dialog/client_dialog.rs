use super::dialog::DialogInnerRef;
use super::DialogId;
use crate::dialog::{
    authenticate::handle_client_authenticate,
    dialog::{DialogState, TerminatedReason},
};
use crate::rsip_ext::RsipResponseExt;
use crate::transaction::transaction::Transaction;
use crate::Result;
use rsip::prelude::HasHeaders;
use rsip::{prelude::HeadersExt, Header};
use rsip::{Response, SipMessage, StatusCode};
use std::sync::atomic::Ordering;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};

/// Client-side INVITE Dialog (UAC)
///
/// `ClientInviteDialog` represents a client-side INVITE dialog in SIP. This is used
/// when the local user agent acts as a User Agent Client (UAC) and initiates
/// an INVITE transaction to establish a session with a remote party.
///
/// # Key Features
///
/// * **Session Initiation** - Initiates INVITE transactions to establish calls
/// * **In-dialog Requests** - Sends UPDATE, INFO, OPTIONS within established dialogs
/// * **Session Termination** - Handles BYE and CANCEL for ending sessions
/// * **Re-INVITE Support** - Supports session modification via re-INVITE
/// * **Authentication** - Handles 401/407 authentication challenges
/// * **State Management** - Tracks dialog state transitions
///
/// # Dialog Lifecycle
///
/// 1. **Creation** - Dialog created when sending INVITE
/// 2. **Early State** - Receives provisional responses (1xx)
/// 3. **Confirmed** - Receives 2xx response and sends ACK
/// 4. **Active** - Can send in-dialog requests (UPDATE, INFO, etc.)
/// 5. **Termination** - Sends BYE or CANCEL to end session
///
/// # Examples
///
/// ## Basic Call Flow
///
/// ```rust,no_run
/// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
/// # async fn example() -> rsipstack::Result<()> {
/// # let dialog: ClientInviteDialog = todo!(); // Dialog is typically created by DialogLayer.do_invite()
/// # let new_sdp_body = vec![];
/// # let info_body = vec![];
/// // After dialog is established:
///
/// // Send an UPDATE request
/// let response = dialog.update(None, Some(new_sdp_body)).await?;
///
/// // Send INFO request
/// let response = dialog.info(None, Some(info_body)).await?;
///
/// // End the call
/// dialog.bye().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Session Modification
///
/// ```rust,no_run
/// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
/// # async fn example() -> rsipstack::Result<()> {
/// # let dialog: ClientInviteDialog = todo!();
/// # let new_sdp = vec![];
/// // Modify session with re-INVITE
/// let headers = vec![
///     rsip::Header::ContentType("application/sdp".into())
/// ];
/// let response = dialog.reinvite(Some(headers), Some(new_sdp)).await?;
///
/// if let Some(resp) = response {
///     if resp.status_code == rsip::StatusCode::OK {
///         println!("Session modified successfully");
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// ClientInviteDialog is thread-safe and can be cloned and shared across tasks.
/// All operations are atomic and properly synchronized.
#[derive(Clone)]
pub struct ClientInviteDialog {
    pub(super) inner: DialogInnerRef,
}

impl ClientInviteDialog {
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

    /// Get the cancellation token for this dialog
    ///
    /// Returns a reference to the CancellationToken that can be used to
    /// cancel ongoing operations for this dialog.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.inner.cancel_token
    }
    /// Hang up the call
    ///
    /// If the dialog is confirmed, send a BYE request to terminate the call.
    /// If the dialog is not confirmed, send a CANCEL request to cancel the call.
    pub async fn hangup(&self) -> Result<()> {
        if self.inner.can_cancel() {
            self.cancel().await
        } else {
            self.bye().await
        }
    }

    /// Send a BYE request to terminate the dialog
    ///
    /// Sends a BYE request to gracefully terminate an established dialog.
    /// This should only be called for confirmed dialogs. If the dialog
    /// is not confirmed, this method returns immediately without error.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - BYE was sent successfully or dialog not confirmed
    /// * `Err(Error)` - Failed to send BYE request
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ClientInviteDialog = todo!();
    /// // End an established call
    /// dialog.bye().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bye(&self) -> Result<()> {
        if !self.inner.is_confirmed() {
            return Ok(());
        }
        let request = self
            .inner
            .make_request(rsip::Method::Bye, None, None, None, None, None)?;

        match self.inner.do_request(request).await {
            Ok(_) => {}
            Err(e) => {
                info!("bye error: {}", e);
            }
        };
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UacBye))?;
        Ok(())
    }

    /// Send a CANCEL request to cancel an ongoing INVITE
    ///
    /// Sends a CANCEL request to cancel an INVITE transaction that has not
    /// yet been answered with a final response. This is used to abort
    /// call setup before the call is established.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - CANCEL was sent successfully
    /// * `Err(Error)` - Failed to send CANCEL request
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ClientInviteDialog = todo!();
    /// // Cancel an outgoing call before it's answered
    /// dialog.cancel().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cancel(&self) -> Result<()> {
        if self.inner.is_confirmed() {
            return Ok(());
        }
        info!(id=%self.id(),"sending cancel request");
        let mut cancel_request = self.inner.initial_request.clone();
        cancel_request
            .headers_mut()
            .retain(|h| !matches!(h, Header::ContentLength(_) | Header::ContentType(_)));

        cancel_request
            .to_header_mut()?
            .mut_tag(self.id().to_tag.clone().into())?; // ensure to-tag has tag param

        cancel_request.method = rsip::Method::Cancel;
        let invite_seq = self.inner.initial_request.cseq_header()?.seq()?;
        cancel_request
            .cseq_header_mut()?
            .mut_seq(invite_seq)?
            .mut_method(rsip::Method::Cancel)?;
        cancel_request.body = vec![];
        self.inner.do_request(cancel_request).await?;
        Ok(())
    }

    /// Send a re-INVITE request to modify the session
    ///
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
    /// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ClientInviteDialog = todo!();
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
        info!(id=%self.id(),"sending re-invite request, body:\n{:?}", body);
        let request =
            self.inner
                .make_request(rsip::Method::Invite, None, None, None, headers, body)?;
        let resp = self.inner.do_request(request.clone()).await;
        match resp {
            Ok(Some(ref resp)) => {
                if resp.status_code == StatusCode::OK {
                    self.inner
                        .transition(DialogState::Updated(self.id(), request))?;
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
    /// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ClientInviteDialog = todo!();
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
        info!(id=%self.id(),"sending update request, body:\n{:?}", body);
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
    /// # use rsipstack::dialog::client_dialog::ClientInviteDialog;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog: ClientInviteDialog = todo!();
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
        info!(id=%self.id(),"sending info request, body:\n{:?}", body);
        let request =
            self.inner
                .make_request(rsip::Method::Info, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }

    pub async fn options(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        if !self.inner.is_confirmed() {
            return Ok(None);
        }
        info!(id=%self.id(),"sending option request, body:\n{:?}", body);
        let request =
            self.inner
                .make_request(rsip::Method::Options, None, None, None, headers, body)?;
        self.inner.do_request(request.clone()).await
    }
    /// Handle incoming transaction for this dialog
    ///
    /// Processes incoming SIP requests that are routed to this dialog.
    /// This method handles sequence number validation and dispatches
    /// to appropriate handlers based on the request method.
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
    /// * `BYE` - Terminates the dialog
    /// * `INFO` - Handles information exchange
    /// * `OPTIONS` - Handles capability queries
    /// * `UPDATE` - Handles session updates
    /// * `INVITE` - Handles re-INVITE (when confirmed)
    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        trace!(
            id=%self.id(),
            "handle request: {:?} state:{}",
            tx.original,
            self.inner.state.lock().unwrap()
        );

        let cseq = tx.original.cseq_header()?.seq()?;
        let remote_seq = self.inner.remote_seq.load(Ordering::Relaxed);
        if remote_seq > 0 && cseq < remote_seq {
            info!(id=%self.id(),"received old request remote_seq: {} > {}", remote_seq, cseq);
            tx.reply(rsip::StatusCode::ServerInternalError).await?;
            return Ok(());
        }

        self.inner
            .remote_seq
            .compare_exchange(remote_seq, cseq, Ordering::Relaxed, Ordering::Relaxed)
            .ok();

        if self.inner.is_confirmed() {
            match tx.original.method {
                rsip::Method::Invite => {}
                rsip::Method::Bye => return self.handle_bye(tx).await,
                rsip::Method::Info => return self.handle_info(tx).await,
                rsip::Method::Options => return self.handle_options(tx).await,
                rsip::Method::Update => return self.handle_update(tx).await,
                _ => {
                    info!(id=%self.id(), "invalid request method: {:?}", tx.original.method);
                    tx.reply(rsip::StatusCode::MethodNotAllowed).await?;
                    return Err(crate::Error::DialogError(
                        "invalid request".to_string(),
                        self.id(),
                        rsip::StatusCode::MethodNotAllowed,
                    ));
                }
            }
        } else {
            info!(id=%self.id(),
                "received request before confirmed: {:?}",
                tx.original.method
            );
        }
        Ok(())
    }

    async fn handle_bye(&mut self, tx: &mut Transaction) -> Result<()> {
        info!(id=%self.id(), "received bye {}", tx.original.uri);
        self.inner
            .transition(DialogState::Terminated(self.id(), TerminatedReason::UasBye))?;
        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_info(&mut self, tx: &mut Transaction) -> Result<()> {
        info!(id=%self.id(),"received info {}", tx.original.uri);
        self.inner
            .transition(DialogState::Info(self.id(), tx.original.clone()))?;
        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_options(&mut self, tx: &mut Transaction) -> Result<()> {
        info!(id=%self.id(),"received options {}", tx.original.uri);
        self.inner
            .transition(DialogState::Options(self.id(), tx.original.clone()))?;
        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    async fn handle_update(&mut self, tx: &mut Transaction) -> Result<()> {
        info!(id=%self.id(),"received update {}", tx.original.uri);
        self.inner
            .transition(DialogState::Updated(self.id(), tx.original.clone()))?;
        tx.reply(rsip::StatusCode::OK).await?;
        Ok(())
    }

    pub async fn process_invite(
        &self,
        mut tx: Transaction,
    ) -> Result<(DialogId, Option<Response>)> {
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

                    if matches!(status.kind(), rsip::StatusCodeKind::Provisional) {
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
                            info!(id=%self.id(),"received {:?} response after auth sent", status);
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            break;
                        }
                        auth_sent = true;
                        if let Some(credential) = &self.inner.credential {
                            tx = handle_client_authenticate(
                                self.inner.increment_local_seq(),
                                tx,
                                resp,
                                credential,
                            )
                            .await?;
                            tx.send().await?;
                            self.inner.update_remote_tag("").ok();
                            continue;
                        } else {
                            info!(id=%self.id(),"received 407 response without auth option");
                            self.inner.transition(DialogState::Terminated(
                                self.id(),
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            continue;
                        }
                    }
                    final_response = Some(resp.clone());
                    match resp.to_header()?.tag()? {
                        Some(tag) => self.inner.update_remote_tag(tag.value())?,
                        None => {}
                    }

                    if let Ok(id) = DialogId::try_from(&resp) {
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
                            // 200 response to INVITE always contains Contact header
                            let contact = resp.contact_header()?;
                            self.inner
                                .remote_contact
                                .lock()
                                .unwrap()
                                .replace(contact.clone());

                            *self.inner.remote_uri.lock().unwrap() =
                                resp.remote_uri(tx.destination.as_ref())?;
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
}
