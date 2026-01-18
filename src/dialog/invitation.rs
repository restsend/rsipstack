use super::{
    authenticate::Credential,
    client_dialog::ClientInviteDialog,
    dialog::{DialogInner, DialogStateSender},
    dialog_layer::DialogLayer,
};
use crate::{
    dialog::{
        dialog::{Dialog, DialogState, TerminatedReason},
        dialog_layer::DialogLayerInnerRef,
        DialogId,
    },
    transaction::{
        key::{TransactionKey, TransactionRole},
        make_tag,
        transaction::Transaction,
    },
    transport::SipAddr,
    Result,
};
use futures::FutureExt;
use rsip::{
    prelude::{HeadersExt, ToTypedHeader},
    Request, Response, SipMessage, StatusCodeKind,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// INVITE Request Options
///
/// `InviteOption` contains all the parameters needed to create and send
/// an INVITE request to establish a SIP session. This structure provides
/// a convenient way to specify all the necessary information for initiating
/// a call or session.
///
/// # Fields
///
/// * `caller` - URI of the calling party (From header)
/// * `callee` - URI of the called party (To header and Request-URI)
/// * `content_type` - MIME type of the message body (default: "application/sdp")
/// * `offer` - Optional message body (typically SDP offer)
/// * `contact` - Contact URI for this user agent
/// * `credential` - Optional authentication credentials
/// * `headers` - Optional additional headers to include
///
/// # Examples
///
/// ## Basic Voice Call
///
/// ```rust,no_run
/// # use rsipstack::dialog::invitation::InviteOption;
/// # fn example() -> rsipstack::Result<()> {
/// # let sdp_offer_bytes = vec![];
/// let invite_option = InviteOption {
///     caller: "sip:alice@example.com".try_into()?,
///     callee: "sip:bob@example.com".try_into()?,
///     content_type: Some("application/sdp".to_string()),
///     offer: Some(sdp_offer_bytes),
///     contact: "sip:alice@192.168.1.100:5060".try_into()?,
///     ..Default::default()
/// };
/// # Ok(())
/// # }
/// ```
///
/// ```rust,no_run
/// # use rsipstack::dialog::dialog_layer::DialogLayer;
/// # use rsipstack::dialog::invitation::InviteOption;
/// # fn example() -> rsipstack::Result<()> {
/// # let dialog_layer: DialogLayer = todo!();
/// # let invite_option: InviteOption = todo!();
/// let request = dialog_layer.make_invite_request(&invite_option)?;
/// println!("Created INVITE to: {}", request.uri);
/// # Ok(())
/// # }
/// ```
///
/// ## Call with Custom Headers
///
/// ```rust,no_run
/// # use rsipstack::dialog::invitation::InviteOption;
/// # fn example() -> rsipstack::Result<()> {
/// # let sdp_bytes = vec![];
/// # let auth_credential = todo!();
/// let custom_headers = vec![
///     rsip::Header::UserAgent("MyApp/1.0".into()),
///     rsip::Header::Subject("Important Call".into()),
/// ];
///
/// let invite_option = InviteOption {
///     caller: "sip:alice@example.com".try_into()?,
///     callee: "sip:bob@example.com".try_into()?,
///     content_type: Some("application/sdp".to_string()),
///     offer: Some(sdp_bytes),
///     contact: "sip:alice@192.168.1.100:5060".try_into()?,
///     credential: Some(auth_credential),
///     headers: Some(custom_headers),
///     ..Default::default()
/// };
/// # Ok(())
/// # }
/// ```
///
/// ## Call with Authentication
///
/// ```rust,no_run
/// # use rsipstack::dialog::invitation::InviteOption;
/// # use rsipstack::dialog::authenticate::Credential;
/// # fn example() -> rsipstack::Result<()> {
/// # let sdp_bytes = vec![];
/// let credential = Credential {
///     username: "alice".to_string(),
///     password: "secret123".to_string(),
///     realm: Some("example.com".to_string()),
/// };
///
/// let invite_option = InviteOption {
///     caller: "sip:alice@example.com".try_into()?,
///     callee: "sip:bob@example.com".try_into()?,
///     offer: Some(sdp_bytes),
///     contact: "sip:alice@192.168.1.100:5060".try_into()?,
///     credential: Some(credential),
///     ..Default::default()
/// };
/// # Ok(())
/// # }
/// ```
#[derive(Default, Clone)]
pub struct InviteOption {
    pub caller_display_name: Option<String>,
    pub caller_params: Vec<rsip::uri::Param>,
    pub caller: rsip::Uri,
    pub callee: rsip::Uri,
    pub destination: Option<SipAddr>,
    pub content_type: Option<String>,
    pub offer: Option<Vec<u8>>,
    pub contact: rsip::Uri,
    pub credential: Option<Credential>,
    pub headers: Option<Vec<rsip::Header>>,
    pub support_prack: bool,
    pub call_id: Option<String>,
}

pub struct DialogGuard {
    pub dialog_layer_inner: DialogLayerInnerRef,
    pub id: DialogId,
}

impl DialogGuard {
    pub fn new(dialog_layer: &Arc<DialogLayer>, id: DialogId) -> Self {
        Self {
            dialog_layer_inner: dialog_layer.inner.clone(),
            id,
        }
    }
}

impl Drop for DialogGuard {
    fn drop(&mut self) {
        let dlg = match self.dialog_layer_inner.dialogs.write() {
            Ok(mut dialogs) => match dialogs.remove(&self.id.to_string()) {
                Some(dlg) => dlg,
                None => return,
            },
            _ => return,
        };
        let _ = tokio::spawn(async move {
            if let Err(e) = dlg.hangup().await {
                info!(id = %dlg.id(), error = %e, "failed to hangup dialog");
            }
        });
    }
}

pub(super) struct DialogGuardForUnconfirmed<'a> {
    pub dialog_layer_inner: &'a DialogLayerInnerRef,
    pub id: &'a DialogId,
    invite_tx: Option<Transaction>,
}

impl<'a> Drop for DialogGuardForUnconfirmed<'a> {
    fn drop(&mut self) {
        // If the dialog is still unconfirmed, we should try to cancel it
        match self.dialog_layer_inner.dialogs.write() {
            Ok(mut dialogs) => match dialogs.remove(&self.id.to_string()) {
                Some(dlg) => {
                    debug!(%self.id, "unconfirmed dialog dropped, cancelling it");
                    let invite_tx = self.invite_tx.take();
                    let _ = tokio::spawn(async move {
                        if let Dialog::ClientInvite(ref client_dialog) = dlg {
                            if client_dialog.inner.can_cancel() {
                                if let Err(e) = client_dialog.cancel().await {
                                    warn!(id = %client_dialog.id(), error = %e, "dialog cancel failed");
                                    return;
                                }

                                if let Some(mut invite_tx) = invite_tx {
                                    let duration = tokio::time::Duration::from_secs(2);
                                    let timeout = tokio::time::sleep(duration);
                                    tokio::pin!(timeout);
                                    loop {
                                        tokio::select! {
                                            _ = &mut timeout => break,
                                            msg = invite_tx.receive() => {
                                                if let Some(msg) = msg{
                                                    if let SipMessage::Response(resp) = msg {
                                                        if resp.status_code.kind() != StatusCodeKind::Provisional {
                                                            debug!(
                                                                id = %client_dialog.id(),
                                                                status = %resp.status_code,
                                                                "received final response"
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }else{
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                let _ = client_dialog.inner.transition(DialogState::Terminated(
                                    client_dialog.id(),
                                    TerminatedReason::UacCancel,
                                ));
                                debug!(id = %client_dialog.id(), "dialog terminated");
                                return;
                            }
                        }

                        if let Err(e) = dlg.hangup().await {
                            info!(id = %dlg.id(), error = %e, "failed to hangup unconfirmed dialog");
                        }
                    });
                }
                None => {}
            },
            Err(e) => {
                warn!(id = %self.id, error = %e, "failed to acquire write lock on dialogs");
            }
        }
    }
}

pub type InviteAsyncResult = Result<(DialogId, Option<Response>)>;

impl DialogLayer {
    /// Create an INVITE request from options
    ///
    /// Constructs a properly formatted SIP INVITE request based on the
    /// provided options. This method handles all the required headers
    /// and parameters according to RFC 3261.
    ///
    /// # Parameters
    ///
    /// * `opt` - INVITE options containing all necessary parameters
    ///
    /// # Returns
    ///
    /// * `Ok(Request)` - Properly formatted INVITE request
    /// * `Err(Error)` - Failed to create request
    ///
    /// # Generated Headers
    ///
    /// The method automatically generates:
    /// * Via header with branch parameter
    /// * From header with tag parameter
    /// * To header (without tag for initial request)
    /// * Contact header
    /// * Content-Type header
    /// * CSeq header with incremented sequence number
    /// * Call-ID header
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::dialog_layer::DialogLayer;
    /// # use rsipstack::dialog::invitation::InviteOption;
    /// # fn example() -> rsipstack::Result<()> {
    /// # let dialog_layer: DialogLayer = todo!();
    /// # let invite_option: InviteOption = todo!();
    /// let request = dialog_layer.make_invite_request(&invite_option)?;
    /// println!("Created INVITE to: {}", request.uri);
    /// # Ok(())
    /// # }
    /// ```
    pub fn make_invite_request(&self, opt: &InviteOption) -> Result<Request> {
        let last_seq = self.increment_last_seq();
        let to = rsip::typed::To {
            display_name: None,
            uri: opt.callee.clone(),
            params: vec![],
        };
        let recipient = to.uri.clone();

        let from = rsip::typed::From {
            display_name: opt.caller_display_name.clone(),
            uri: opt.caller.clone(),
            params: opt.caller_params.clone(),
        }
        .with_tag(make_tag());

        let call_id = opt
            .call_id
            .as_ref()
            .map(|id| rsip::headers::CallId::from(id.clone()));

        let via = self.endpoint.get_via(None, None)?;
        let mut request = self.endpoint.make_request(
            rsip::Method::Invite,
            recipient,
            via,
            from,
            to,
            last_seq,
            call_id,
        );

        let contact = rsip::typed::Contact {
            display_name: None,
            uri: opt.contact.clone(),
            params: vec![],
        };

        request
            .headers
            .unique_push(rsip::Header::Contact(contact.into()));

        request.headers.unique_push(rsip::Header::ContentType(
            opt.content_type
                .clone()
                .unwrap_or("application/sdp".to_string())
                .into(),
        ));

        if opt.support_prack {
            request
                .headers
                .unique_push(rsip::Header::Supported("100rel".into()));
        }
        // can't override default headers
        if let Some(headers) = opt.headers.as_ref() {
            for header in headers {
                // only override if it is a "max-forwards" header
                // so as not to duplicate it; this is important because
                // some clients consider messages with duplicate "max-forwards"
                // headers as malformed and may silently ignore invites
                match header {
                    rsip::Header::MaxForwards(_) => request.headers.unique_push(header.clone()),
                    _ => request.headers.push(header.clone()),
                }
            }
        }
        Ok(request)
    }

    /// Send an INVITE request and create a client dialog
    ///
    /// This is the main method for initiating outbound calls. It creates
    /// an INVITE request, sends it, and manages the resulting dialog.
    /// The method handles the complete INVITE transaction including
    /// authentication challenges and response processing.
    ///
    /// # Parameters
    ///
    /// * `opt` - INVITE options containing all call parameters
    /// * `state_sender` - Channel for receiving dialog state updates
    ///
    /// # Returns
    ///
    /// * `Ok((ClientInviteDialog, Option<Response>))` - Created dialog and final response
    /// * `Err(Error)` - Failed to send INVITE or process responses
    ///
    /// # Call Flow
    ///
    /// 1. Creates INVITE request from options
    /// 2. Creates client dialog and transaction
    /// 3. Sends INVITE request
    /// 4. Processes responses (1xx, 2xx, 3xx-6xx)
    /// 5. Handles authentication challenges if needed
    /// 6. Returns established dialog and final response
    ///
    /// # Examples
    ///
    /// ## Basic Call Setup
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::dialog_layer::DialogLayer;
    /// # use rsipstack::dialog::invitation::InviteOption;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog_layer: DialogLayer = todo!();
    /// # let invite_option: InviteOption = todo!();
    /// # let state_sender = todo!();
    /// let (dialog, response) = dialog_layer.do_invite(invite_option, state_sender).await?;
    ///
    /// if let Some(resp) = response {
    ///     match resp.status_code {
    ///         rsip::StatusCode::OK => {
    ///             println!("Call answered!");
    ///             // Process SDP answer in resp.body
    ///         },
    ///         rsip::StatusCode::BusyHere => {
    ///             println!("Called party is busy");
    ///         },
    ///         _ => {
    ///             println!("Call failed: {}", resp.status_code);
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Monitoring Dialog State
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::dialog_layer::DialogLayer;
    /// # use rsipstack::dialog::invitation::InviteOption;
    /// # use rsipstack::dialog::dialog::DialogState;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let dialog_layer: DialogLayer = todo!();
    /// # let invite_option: InviteOption = todo!();
    /// let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    /// let (dialog, response) = dialog_layer.do_invite(invite_option, state_tx).await?;
    ///
    /// // Monitor dialog state changes
    /// tokio::spawn(async move {
    ///     while let Some(state) = state_rx.recv().await {
    ///         match state {
    ///             DialogState::Early(_, resp) => {
    ///                 println!("Ringing: {}", resp.status_code);
    ///             },
    ///             DialogState::Confirmed(_,_) => {
    ///                 println!("Call established");
    ///             },
    ///             DialogState::Terminated(_, code) => {
    ///                 println!("Call ended: {:?}", code);
    ///                 break;
    ///             },
    ///             _ => {}
    ///         }
    ///     }
    /// });
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Error Handling
    ///
    /// The method can fail for various reasons:
    /// * Network connectivity issues
    /// * Authentication failures
    /// * Invalid SIP URIs or headers
    /// * Transaction timeouts
    /// * Protocol violations
    ///
    /// # Authentication
    ///
    /// If credentials are provided in the options, the method will
    /// automatically handle 401/407 authentication challenges by
    /// resending the request with proper authentication headers.
    pub async fn do_invite(
        &self,
        opt: InviteOption,
        state_sender: DialogStateSender,
    ) -> Result<(ClientInviteDialog, Option<Response>)> {
        let (dialog, tx) = self.create_client_invite_dialog(opt, state_sender)?;
        let id = dialog.id();

        self.inner
            .dialogs
            .write()
            .as_mut()
            .map(|ds| ds.insert(id.to_string(), Dialog::ClientInvite(dialog.clone())))
            .ok();

        debug!(%id, "client invite dialog created");
        let mut guard = DialogGuardForUnconfirmed {
            dialog_layer_inner: &self.inner,
            id: &id,
            invite_tx: Some(tx),
        };

        let tx = guard
            .invite_tx
            .as_mut()
            .expect("transcation should be avaible");

        let r = dialog.process_invite(tx).boxed().await;
        self.inner
            .dialogs
            .write()
            .as_mut()
            .map(|ds| ds.remove(&id.to_string()))
            .ok();

        match r {
            Ok((new_dialog_id, resp)) => {
                match resp {
                    Some(ref r) if r.status_code.kind() == rsip::StatusCodeKind::Successful => {
                        debug!(
                            "client invite dialog confirmed: {} => {}",
                            id, new_dialog_id
                        );
                        self.inner
                            .dialogs
                            .write()
                            .as_mut()
                            .map(|ds| {
                                ds.insert(
                                    new_dialog_id.to_string(),
                                    Dialog::ClientInvite(dialog.clone()),
                                )
                            })
                            .ok();
                    }
                    _ => {}
                }
                return Ok((dialog, resp));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    // Asynchronously executes an INVITE transaction in the background.
    ///
    /// Registers the dialog under an early dialog ID while the INVITE is in progress.
    /// Once completed, the early entry is removed and, on 2xx response,
    /// the dialog is re-registered under the confirmed dialog ID.
    /// Returns a JoinHandle resolving to the final dialog ID and response.

    pub fn do_invite_async(
        self: &Arc<Self>,
        opt: InviteOption,
        state_sender: DialogStateSender,
    ) -> Result<(
        ClientInviteDialog,
        tokio::task::JoinHandle<InviteAsyncResult>,
    )> {
        let (dialog, mut tx) = self.create_client_invite_dialog(opt, state_sender)?;
        let id0 = dialog.id();

        // 1) register early key (so in-dialog requests can be matched)
        self.inner
            .dialogs
            .write()
            .as_mut()
            .map(|ds| ds.insert(id0.to_string(), Dialog::ClientInvite(dialog.clone())))
            .ok();

        debug!(%id0, "client invite dialog created (async)");

        let inner = self.inner.clone();
        let dialog_clone = dialog.clone();

        // 2) run invite in background, keep registry updated like do_invite()
        let handle = tokio::spawn(async move {
            let r = dialog_clone.process_invite(&mut tx).boxed().await;

            // remove early key
            inner
                .dialogs
                .write()
                .as_mut()
                .map(|ds| ds.remove(&id0.to_string()))
                .ok();

            match &r {
                Ok((new_id, resp_opt)) => {
                    let is_2xx = resp_opt
                        .as_ref()
                        .map(|resp| resp.status_code.kind() == rsip::StatusCodeKind::Successful)
                        .unwrap_or(false);

                    if is_2xx {
                        debug!("client invite dialog confirmed: {} => {}", id0, new_id);
                        inner
                            .dialogs
                            .write()
                            .as_mut()
                            .map(|ds| {
                                ds.insert(
                                    new_id.to_string(),
                                    Dialog::ClientInvite(dialog_clone.clone()),
                                )
                            })
                            .ok();
                    }
                }
                Err(e) => debug!(%id0, error = %e, "async invite failed"),
            }

            r
        });

        Ok((dialog, handle))
    }

    pub fn create_client_invite_dialog(
        &self,
        opt: InviteOption,
        state_sender: DialogStateSender,
    ) -> Result<(ClientInviteDialog, Transaction)> {
        let mut request = self.make_invite_request(&opt)?;
        request.body = opt.offer.unwrap_or_default();
        request.headers.unique_push(rsip::Header::ContentLength(
            (request.body.len() as u32).into(),
        ));
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request.clone(), self.endpoint.clone(), None);

        if opt.destination.is_some() {
            tx.destination = opt.destination;
        } else {
            if let Some(route) = tx.original.route_header() {
                if let Some(first_route) =
                    route.typed().ok().and_then(|r| r.uris().first().cloned())
                {
                    tx.destination = SipAddr::try_from(&first_route.uri).ok();
                }
            }
        }

        let id = DialogId::from_uac_request(&request)?;
        let dlg_inner = DialogInner::new(
            TransactionRole::Client,
            id.clone(),
            request.clone(),
            self.endpoint.clone(),
            state_sender,
            opt.credential,
            Some(opt.contact),
            tx.tu_sender.clone(),
        )?;

        if let Some(destination) = &tx.destination {
            let uri = destination.clone().into();
            dlg_inner
                .remote_uri
                .lock()
                .map(|mut guard| {
                    *guard = uri;
                })
                .ok();
        }
        let dialog = ClientInviteDialog {
            inner: Arc::new(dlg_inner),
        };
        Ok((dialog, tx))
    }
}
