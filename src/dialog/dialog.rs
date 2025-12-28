use super::{
    authenticate::{handle_client_authenticate, Credential},
    client_dialog::ClientInviteDialog,
    publication::{ClientPublicationDialog, ServerPublicationDialog},
    server_dialog::ServerInviteDialog,
    subscription::{ClientSubscriptionDialog, ServerSubscriptionDialog},
    DialogId,
};
use crate::{
    rsip_ext::{extract_uri_from_contact, header_contains_token, parse_rseq_header},
    transaction::{
        endpoint::EndpointInnerRef,
        key::{TransactionKey, TransactionRole},
        make_via_branch,
        transaction::{Transaction, TransactionEventSender},
    },
    transport::SipAddr,
    Result,
};
use futures::FutureExt;
use rsip::{
    headers::Route,
    message::HasHeaders,
    prelude::{HeadersExt, ToTypedHeader, UntypedHeader},
    typed::{CSeq, Contact, Via},
    Header, Method, Param, Request, Response, SipMessage, StatusCode, StatusCodeKind,
};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub type TransactionCommandSender = mpsc::Sender<TransactionCommand>;
pub type TransactionCommandReceiver = mpsc::Receiver<TransactionCommand>;
#[derive(Debug)]
pub enum TransactionCommand {
    Respond {
        status: StatusCode,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
pub struct TransactionHandle {
    sender: TransactionCommandSender,
}

impl TransactionHandle {
    pub fn new() -> (Self, TransactionCommandReceiver) {
        let (tx, rx) = mpsc::channel(4);
        (Self { sender: tx }, rx)
    }

    pub async fn reply(
        &self,
        status: StatusCode,
    ) -> std::result::Result<(), mpsc::error::SendError<TransactionCommand>> {
        self.respond(status, None, None).await
    }

    pub async fn respond(
        &self,
        status: StatusCode,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> std::result::Result<(), mpsc::error::SendError<TransactionCommand>> {
        self.sender
            .send(TransactionCommand::Respond {
                status,
                headers,
                body,
            })
            .await
    }
}

/// SIP Dialog State
///
/// Represents the various states a SIP dialog can be in during its lifecycle.
/// These states follow the SIP dialog state machine as defined in RFC 3261.
///
/// # States
///
/// * `Calling` - Initial state when a dialog is created for an outgoing INVITE
/// * `Trying` - Dialog has received a 100 Trying response
/// * `Early` - Dialog is in early state (1xx response received, except 100)
/// * `WaitAck` - Server dialog waiting for ACK after sending 2xx response
/// * `Confirmed` - Dialog is established and confirmed (2xx response received/sent and ACK sent/received)
/// * `Updated` - Dialog received an UPDATE request
/// * `Notify` - Dialog received a NOTIFY request  
/// * `Info` - Dialog received an INFO request
/// * `Options` - Dialog received an OPTIONS request
/// * `Terminated` - Dialog has been terminated
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::dialog::dialog::DialogState;
/// use rsipstack::dialog::DialogId;
///
/// # fn example() {
/// # let dialog_id = DialogId {
/// #     call_id: "test@example.com".to_string(),
/// #     local_tag: "from-tag".to_string(),
/// #     remote_tag: "to-tag".to_string(),
/// # };
/// let state = DialogState::Confirmed(dialog_id, rsip::Response::default());
/// if state.is_confirmed() {
///     println!("Dialog is established");
/// }
/// # }
/// ```
#[derive(Clone)]
pub enum DialogState {
    Calling(DialogId),
    Trying(DialogId),
    Early(DialogId, rsip::Response),
    WaitAck(DialogId, rsip::Response),
    Confirmed(DialogId, rsip::Response),
    Updated(DialogId, rsip::Request, TransactionHandle),
    Publish(DialogId, rsip::Request, TransactionHandle),
    Notify(DialogId, rsip::Request, TransactionHandle),
    Refer(DialogId, rsip::Request, TransactionHandle),
    Message(DialogId, rsip::Request, TransactionHandle),
    Info(DialogId, rsip::Request, TransactionHandle),
    Options(DialogId, rsip::Request, TransactionHandle),
    Terminated(DialogId, TerminatedReason),
}

#[derive(Debug, Clone)]
pub enum TerminatedReason {
    Timeout,
    UacCancel,
    UacBye,
    UasBye,
    UacBusy,
    UasBusy,
    UasDecline,
    ProxyError(rsip::StatusCode),
    ProxyAuthRequired,
    UacOther(rsip::StatusCode),
    UasOther(rsip::StatusCode),
}

/// Represents the status of a REFER operation parsed from a NOTIFY request.
#[derive(Debug, Clone)]
pub struct ReferStatus {
    pub status_code: rsip::StatusCode,
    pub is_terminated: bool,
}

impl ReferStatus {
    pub fn parse(req: &rsip::Request) -> Option<Self> {
        use rsip::prelude::HasHeaders;

        let mut event = None;
        for header in req.headers().iter() {
            if let rsip::Header::Other(name, value) = header {
                if name.to_string().eq_ignore_ascii_case("event") {
                    event = Some(value.to_string().to_lowercase());
                    break;
                }
            }
        }
        let event = event?;
        if !event.contains("refer") {
            return None;
        }

        let mut sub_state = None;
        for header in req.headers().iter() {
            if let rsip::Header::Other(name, value) = header {
                if name.to_string().eq_ignore_ascii_case("subscription-state") {
                    sub_state = Some(value.to_string().to_lowercase());
                    break;
                }
            }
        }
        let sub_state = sub_state?;
        let is_terminated = sub_state.contains("terminated");

        let body = std::str::from_utf8(&req.body).ok()?;
        let status_line = body.lines().find(|l| l.starts_with("SIP/2.0"))?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        let code: u16 = parts[1].parse().ok()?;
        let status_code = rsip::StatusCode::from(code);

        Some(Self {
            status_code,
            is_terminated,
        })
    }
}

/// SIP Dialog
///
/// Represents a SIP dialog which can be either a server-side or client-side INVITE dialog.
/// A dialog is a peer-to-peer SIP relationship between two user agents that persists
/// for some time. Dialogs are established by SIP methods like INVITE.
///
/// # Variants
///
/// * `ServerInvite` - Server-side INVITE dialog (UAS)
/// * `ClientInvite` - Client-side INVITE dialog (UAC)
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::dialog::dialog::Dialog;
///
/// # fn handle_dialog(dialog: Dialog) {
/// match dialog {
///     Dialog::ServerInvite(server_dialog) => {
///         // Handle server dialog
///     },
///     Dialog::ClientInvite(client_dialog) => {
///         // Handle client dialog  
///     },
///     Dialog::ServerSubscription(server_dialog) => {
///         // Handle server subscription dialog
///     },
///     Dialog::ClientSubscription(client_dialog) => {
///         // Handle client subscription dialog
///     },
///     Dialog::ServerPublication(server_dialog) => {
///         // Handle server publication dialog
///     },
///     Dialog::ClientPublication(client_dialog) => {
///         // Handle client publication dialog
///     }
/// }
/// # }
/// ```
#[derive(Clone)]
pub enum Dialog {
    ServerInvite(ServerInviteDialog),
    ClientInvite(ClientInviteDialog),
    ServerSubscription(ServerSubscriptionDialog),
    ClientSubscription(ClientSubscriptionDialog),
    ServerPublication(ServerPublicationDialog),
    ClientPublication(ClientPublicationDialog),
}

impl Dialog {
    pub fn state(&self) -> DialogState {
        match self {
            Dialog::ServerInvite(d) => d.state(),
            Dialog::ClientInvite(d) => d.state(),
            Dialog::ServerSubscription(d) => d.state(),
            Dialog::ClientSubscription(d) => d.state(),
            Dialog::ServerPublication(d) => d.state(),
            Dialog::ClientPublication(d) => d.state(),
        }
    }

    /// Convert this dialog to a subscription dialog if possible.
    /// For INVITE dialogs, this creates a subscription dialog sharing the same inner state.
    pub fn as_subscription(&self) -> Option<Dialog> {
        match self {
            Dialog::ServerInvite(d) => Some(Dialog::ServerSubscription(d.as_subscription())),
            Dialog::ClientInvite(d) => Some(Dialog::ClientSubscription(d.as_subscription())),
            Dialog::ServerSubscription(_) => Some(self.clone()),
            Dialog::ClientSubscription(_) => Some(self.clone()),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(super) struct RemoteReliableState {
    last_rseq: u32,
    prack_request: Request,
}

/// Internal Dialog State and Management
///
/// `DialogInner` contains the core state and functionality shared between
/// client and server dialogs. It manages dialog state transitions, sequence numbers,
/// routing information, and communication with the transaction layer.
///
/// # Key Responsibilities
///
/// * Managing dialog state transitions
/// * Tracking local and remote sequence numbers
/// * Maintaining routing information (route set, contact URIs)
/// * Handling authentication credentials
/// * Coordinating with the transaction layer
///
/// # Fields
///
/// * `role` - Whether this is a client or server dialog
/// * `cancel_token` - Token for canceling dialog operations
/// * `id` - Unique dialog identifier
/// * `state` - Current dialog state
/// * `local_seq` - Local CSeq number for outgoing requests
/// * `remote_seq` - Remote CSeq number for incoming requests
/// * `local_contact` - Local contact URI
/// * `remote_uri` - Remote target URI
/// * `from` - From header value
/// * `to` - To header value
/// * `credential` - Authentication credentials if needed
/// * `route_set` - Route set for request routing
/// * `endpoint_inner` - Reference to the SIP endpoint
/// * `state_sender` - Channel for sending state updates
/// * `tu_sender` - Transaction user sender
/// * `initial_request` - The initial request that created this dialog
pub struct DialogInner {
    pub role: TransactionRole,
    pub cancel_token: CancellationToken,
    pub id: Mutex<DialogId>,
    pub state: Mutex<DialogState>,

    pub local_seq: AtomicU32,
    pub local_contact: Option<rsip::Uri>,
    pub remote_contact: Mutex<Option<rsip::headers::untyped::Contact>>,

    pub remote_seq: AtomicU32,
    pub remote_uri: Mutex<rsip::Uri>,

    pub from: rsip::typed::From,
    pub to: Mutex<rsip::typed::To>,

    pub credential: Option<Credential>,
    pub route_set: Mutex<Vec<Route>>,

    pub(super) endpoint_inner: EndpointInnerRef,
    pub(super) state_sender: DialogStateSender,
    pub(super) tu_sender: TransactionEventSender,
    // initial request updated when INVITE auth failed with new INVITE
    pub(super) initial_request: Mutex<Request>,
    pub(super) supports_100rel: bool,
    pub(super) remote_reliable: Mutex<Option<RemoteReliableState>>,
}

pub type DialogStateReceiver = UnboundedReceiver<DialogState>;
pub type DialogStateSender = UnboundedSender<DialogState>;

pub(super) type DialogInnerRef = Arc<DialogInner>;

impl DialogState {
    pub fn id(&self) -> &DialogId {
        match self {
            DialogState::Calling(id)
            | DialogState::Trying(id)
            | DialogState::Early(id, _)
            | DialogState::WaitAck(id, _)
            | DialogState::Confirmed(id, _)
            | DialogState::Updated(id, _, _)
            | DialogState::Publish(id, _, _)
            | DialogState::Notify(id, _, _)
            | DialogState::Info(id, _, _)
            | DialogState::Options(id, _, _)
            | DialogState::Refer(id, _, _)
            | DialogState::Message(id, _, _)
            | DialogState::Terminated(id, _) => id,
        }
    }

    pub fn can_cancel(&self) -> bool {
        matches!(
            self,
            DialogState::Calling(_) | DialogState::Trying(_) | DialogState::Early(_, _)
        )
    }
    pub fn is_confirmed(&self) -> bool {
        matches!(self, DialogState::Confirmed(_, _))
    }
    pub fn is_terminated(&self) -> bool {
        matches!(self, DialogState::Terminated(_, _))
    }
    pub fn waiting_ack(&self) -> bool {
        matches!(self, DialogState::WaitAck(_, _))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogSnapshotState {
    Calling,
    Trying,
    Early,
    WaitAck,
    Confirmed,
    Terminated,
}
#[derive(Clone, Debug)]
pub struct DialogSnapshot {
    pub state: DialogSnapshotState,
    pub role: TransactionRole,
    pub id: DialogId,

    pub from: rsip::typed::From,
    pub to: rsip::typed::To,

    pub local_cseq: u32,
    pub remote_cseq: u32,

    pub local_contact: Option<rsip::Uri>,

    pub remote_uri: rsip::Uri,
    pub remote_contact: Option<rsip::headers::untyped::Contact>,

    pub route_set: Vec<Route>,
    pub supports_100rel: bool,
}
impl DialogInner {
    pub fn new(
        role: TransactionRole,
        id: DialogId,
        initial_request: Request,
        endpoint_inner: EndpointInnerRef,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
        tu_sender: TransactionEventSender,
    ) -> Result<Self> {
        let cseq = initial_request.cseq_header()?.seq()?;

        let remote_uri = match role {
            TransactionRole::Client => initial_request.uri.clone(),
            TransactionRole::Server => {
                extract_uri_from_contact(initial_request.contact_header()?.value())?
            }
        };

        let from = initial_request.from_header()?.typed()?;
        let mut to = initial_request.to_header()?.typed()?;
        if !to.params.iter().any(|p| matches!(p, Param::Tag(_))) {
            let tag = match role {
                TransactionRole::Client => &id.remote_tag,
                TransactionRole::Server => &id.local_tag,
            };
            if !tag.is_empty() {
                to.params.push(rsip::Param::Tag(tag.clone().into()));
            }
        }

        let mut route_set = vec![];
        for h in initial_request.headers.iter() {
            if let Header::RecordRoute(rr) = h {
                route_set.push(Route::from(rr.value()));
            }
        }
        route_set.reverse();

        let supports_100rel =
            header_contains_token(&initial_request.headers, "Supported", "100rel")
                || header_contains_token(&initial_request.headers, "Require", "100rel");

        Ok(Self {
            role,
            cancel_token: CancellationToken::new(),
            id: Mutex::new(id.clone()),
            from: from,
            to: Mutex::new(to),
            local_seq: AtomicU32::new(cseq),
            remote_uri: Mutex::new(remote_uri),
            remote_seq: AtomicU32::new(0),
            credential,
            route_set: Mutex::new(route_set),
            endpoint_inner,
            state_sender,
            tu_sender,
            state: Mutex::new(DialogState::Calling(id)),
            initial_request: Mutex::new(initial_request),
            local_contact,
            remote_contact: Mutex::new(None),
            supports_100rel,
            remote_reliable: Mutex::new(None),
        })
    }
    pub fn can_cancel(&self) -> bool {
        self.state.lock().unwrap().can_cancel()
    }
    pub fn is_confirmed(&self) -> bool {
        self.state.lock().unwrap().is_confirmed()
    }
    pub fn is_terminated(&self) -> bool {
        self.state.lock().unwrap().is_terminated()
    }
    pub fn waiting_ack(&self) -> bool {
        self.state.lock().unwrap().waiting_ack()
    }
    pub fn get_local_seq(&self) -> u32 {
        self.local_seq.load(Ordering::Relaxed)
    }
    pub fn increment_local_seq(&self) -> u32 {
        self.local_seq.fetch_add(1, Ordering::Relaxed);
        self.local_seq.load(Ordering::Relaxed)
    }

    pub fn update_remote_tag(&self, tag: &str) -> Result<()> {
        self.id.lock().unwrap().remote_tag = tag.to_string();

        if self.role == TransactionRole::Client {
            let mut to = self.to.lock().unwrap();
            *to = to.clone().with_tag(tag.into());
        }
        Ok(())
    }

    fn clear_remote_reliable(&self) {
        self.remote_reliable.lock().unwrap().take();
    }

    pub(super) fn prepare_prack_request(&self, resp: &Response) -> Result<Option<Request>> {
        if !header_contains_token(resp.headers(), "Require", "100rel") {
            return Ok(None);
        }

        let Some(rseq) = parse_rseq_header(resp.headers()) else {
            warn!(
                id = self.id.lock().unwrap().to_string(),
                "received reliable provisional response without RSeq"
            );
            return Ok(None);
        };

        let cseq_header = resp.cseq_header()?;
        let cseq = cseq_header.seq()?;
        let method = cseq_header.method()?;

        {
            let state_guard = self.remote_reliable.lock().unwrap();
            if let Some(state) = state_guard.as_ref() {
                if state.last_rseq == rseq {
                    return Ok(Some(state.prack_request.clone()));
                }

                if state.last_rseq > rseq {
                    return Ok(None);
                }
            }
        }

        let rack_value = format!("{} {} {}", rseq, cseq, method);
        let mut headers = vec![Header::Other("RAck".into(), rack_value.into())];
        if self.supports_100rel {
            headers.push(Header::Other("Supported".into(), "100rel".into()));
        }

        let prack_request = self.make_request(
            Method::PRack,
            Some(self.increment_local_seq()),
            None,
            None,
            Some(headers),
            None,
        )?;

        let state = RemoteReliableState {
            last_rseq: rseq,
            prack_request: prack_request.clone(),
        };

        {
            let mut state_guard = self.remote_reliable.lock().unwrap();
            *state_guard = Some(state);
        }

        Ok(Some(prack_request))
    }

    pub(super) async fn handle_provisional_response(&self, resp: &Response) -> Result<()> {
        let to_header = resp.to_header()?;
        if let Ok(Some(tag)) = to_header.tag() {
            self.update_remote_tag(tag.value())?;
        }

        if let Some(prack) = self.prepare_prack_request(resp)? {
            let _ = self.send_prack_request(prack).await?;
        }

        Ok(())
    }

    pub(super) async fn send_prack_request(&self, request: Request) -> Result<Option<Response>> {
        let method = request.method().to_owned();
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint_inner.clone(), None);

        if let Some(route) = tx.original.route_header() {
            if let Some(first_route) = route.typed().ok().and_then(|r| r.uris().first().cloned()) {
                tx.destination = SipAddr::try_from(&first_route.uri).ok();
            }
        }

        match tx.send().await {
            Ok(_) => {
                debug!(
                    id = self.id.lock().unwrap().to_string(),
                    method = %method,
                    destination=tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    key=%tx.key,
                    "request sent done",
                );
            }
            Err(e) => {
                warn!(
                    id = self.id.lock().unwrap().to_string(),
                    destination = tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    "failed to send request error: {}\n{}",
                    e,
                    tx.original
                );
                return Err(e);
            }
        }

        let mut auth_sent = false;
        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => match resp.status_code {
                    StatusCode::Trying => continue,
                    StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized => {
                        let id = self.id.lock().unwrap().clone();
                        if auth_sent {
                            debug!(
                                id = self.id.lock().unwrap().to_string(),
                                "received {} response after auth sent", resp.status_code
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            break;
                        }
                        auth_sent = true;
                        if let Some(cred) = &self.credential {
                            let new_seq = self.increment_local_seq();
                            tx = handle_client_authenticate(new_seq, &tx, resp, cred).await?;
                            tx.send().await?;
                            continue;
                        } else {
                            debug!(
                                id = self.id.lock().unwrap().to_string(),
                                "received 407 response without auth option"
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            break;
                        }
                    }
                    _ => {
                        return Ok(Some(resp));
                    }
                },
                _ => break,
            }
        }
        Ok(None)
    }

    /// Update the dialog's remote target URI and optional Contact header.
    ///
    /// When a 2xx/UPDATE response carries a new Contact, call this to ensure
    /// subsequent in-dialog requests route to the latest remote target.
    pub fn set_remote_target(
        &self,
        uri: rsip::Uri,
        contact: Option<rsip::headers::untyped::Contact>,
    ) {
        *self.remote_uri.lock().unwrap() = uri;
        *self.remote_contact.lock().unwrap() = contact;
    }

    /// Update the stored route set from Record-Route headers present in a response.
    ///
    /// Client dialogs learn their route set from the 2xx response that establishes
    /// the dialog (RFC 3261 §12.1.2). Persisting it here ensures all subsequent
    /// in-dialog requests reuse the same proxy chain instead of targeting the
    /// remote contact directly.
    pub(crate) fn update_route_set_from_response(&self, resp: &Response) {
        if !matches!(self.role, TransactionRole::Client) {
            return;
        }

        let mut new_route_set: Vec<Route> = resp
            .headers()
            .iter()
            .filter_map(|header| match header {
                Header::RecordRoute(rr) => Some(Route::from(rr.value())),
                _ => None,
            })
            .collect();

        new_route_set.reverse();
        *self.route_set.lock().unwrap() = new_route_set;
    }

    pub(super) fn build_vias_from_request(&self) -> Result<Vec<Via>> {
        let mut vias = vec![];
        let initial_request = self
            .initial_request
            .lock()
            .expect("build vias from request poisoned mutex");
        for header in initial_request.headers.iter() {
            if let Header::Via(via) = header {
                if let Ok(mut typed_via) = via.typed() {
                    for param in typed_via.params.iter_mut() {
                        if let Param::Branch(_) = param {
                            *param = make_via_branch();
                        }
                    }
                    vias.push(typed_via);
                    return Ok(vias);
                }
            }
        }
        let via = self.endpoint_inner.get_via(None, None)?;
        vias.push(via);
        Ok(vias)
    }

    pub(super) fn make_request_with_vias(
        &self,
        method: rsip::Method,
        cseq: Option<u32>,
        vias: Vec<rsip::headers::typed::Via>,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<rsip::Request> {
        let mut headers = headers.unwrap_or_default();
        let cseq_header = CSeq {
            seq: cseq.unwrap_or_else(|| self.increment_local_seq()),
            method,
        };

        for via in vias {
            headers.push(Header::Via(via.into()));
        }
        headers.push(Header::CallId(
            self.id.lock().unwrap().call_id.clone().into(),
        ));

        let to = self
            .to
            .lock()
            .unwrap()
            .clone()
            .untyped()
            .value()
            .to_string();

        let from = self.from.clone().untyped().value().to_string();
        match self.role {
            TransactionRole::Client => {
                headers.push(Header::From(from.into()));
                headers.push(Header::To(to.into()));
            }
            TransactionRole::Server => {
                headers.push(Header::From(to.into()));
                headers.push(Header::To(from.into()));
            }
        }
        headers.push(Header::CSeq(cseq_header.into()));
        headers.push(Header::UserAgent(
            self.endpoint_inner.user_agent.clone().into(),
        ));

        self.local_contact
            .as_ref()
            .map(|c| headers.push(Contact::from(c.clone()).into()));

        {
            let route_set = self.route_set.lock().unwrap();
            headers.extend(route_set.iter().cloned().map(Header::Route));
        }
        headers.push(Header::MaxForwards(70.into()));

        headers.push(Header::ContentLength(
            body.as_ref().map_or(0u32, |b| b.len() as u32).into(),
        ));

        let req = rsip::Request {
            method,
            uri: self.remote_uri.lock().unwrap().clone(),
            headers: headers.into(),
            body: body.unwrap_or_default(),
            version: rsip::Version::V2,
        };
        Ok(req)
    }

    pub(super) fn make_request(
        &self,
        method: rsip::Method,
        cseq: Option<u32>,
        addr: Option<crate::transport::SipAddr>,
        branch: Option<Param>,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<rsip::Request> {
        let via = self.endpoint_inner.get_via(addr, branch)?;
        self.make_request_with_vias(method, cseq, vec![via], headers, body)
    }

    pub(super) fn make_response(
        &self,
        request: &Request,
        status: StatusCode,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> rsip::Response {
        let mut resp_headers = rsip::Headers::default();

        for header in request.headers.iter() {
            match header {
                Header::Via(via) => {
                    resp_headers.push(Header::Via(via.clone()));
                }
                Header::From(from) => {
                    resp_headers.push(Header::From(from.clone()));
                }
                Header::To(to) => {
                    let mut to = match to.clone().typed() {
                        Ok(to) => to,
                        Err(e) => {
                            info!(error = %e, "error parsing to header");
                            continue;
                        }
                    };

                    if status != StatusCode::Trying
                        && !to.params.iter().any(|p| matches!(p, Param::Tag(_)))
                    {
                        to.params.push(rsip::Param::Tag(
                            self.id.lock().unwrap().local_tag.clone().into(),
                        ));
                    }
                    resp_headers.push(Header::To(to.into()));
                }
                Header::CSeq(cseq) => {
                    resp_headers.push(Header::CSeq(cseq.clone()));
                }
                Header::CallId(call_id) => {
                    resp_headers.push(Header::CallId(call_id.clone()));
                }
                Header::RecordRoute(rr) => {
                    // Copy Record-Route headers from request to response (RFC 3261)
                    resp_headers.push(Header::RecordRoute(rr.clone()));
                }
                _ => {}
            }
        }

        self.local_contact
            .as_ref()
            .map(|c| resp_headers.push(Contact::from(c.clone()).into()));

        if let Some(headers) = headers {
            for header in headers {
                resp_headers.unique_push(header);
            }
        }

        resp_headers.retain(|h| !matches!(h, Header::ContentLength(_) | Header::UserAgent(_)));

        resp_headers.push(Header::ContentLength(
            body.as_ref().map_or(0u32, |b| b.len() as u32).into(),
        ));

        resp_headers.push(Header::UserAgent(
            self.endpoint_inner.user_agent.clone().into(),
        ));

        Response {
            status_code: status,
            headers: resp_headers,
            body: body.unwrap_or_default(),
            version: request.version().clone(),
        }
    }

    async fn send_dialog_request(&self, request: Request) -> Result<Option<Response>> {
        let method = request.method().to_owned();
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint_inner.clone(), None);

        if matches!(method, Method::Cancel) {
            self.remote_uri
                .lock()
                .map(|guard| {
                    tx.destination = SipAddr::try_from(guard.clone()).ok();
                })
                .ok();
        }

        if let Some(route) = tx.original.route_header() {
            if let Some(first_route) = route.typed().ok().and_then(|r| r.uris().first().cloned()) {
                tx.destination = SipAddr::try_from(&first_route.uri).ok();
            }
        }
        match tx.send().await {
            Ok(_) => {
                debug!(
                    id = self.id.lock().unwrap().to_string(),
                    method = %method,
                    destination=tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    key=%tx.key,
                    "request sent done",
                );
            }
            Err(e) => {
                warn!(
                    id = self.id.lock().unwrap().to_string(),
                    destination = tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    "failed to send request error: {}\n{}",
                    e,
                    tx.original
                );
                return Err(e);
            }
        }
        let mut auth_sent = false;
        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => {
                    let status = resp.status_code.clone();
                    if status == StatusCode::Trying {
                        continue;
                    }

                    if status.kind() == StatusCodeKind::Provisional {
                        if method == Method::Invite {
                            self.handle_provisional_response(&resp).await?;
                        }
                        self.transition(DialogState::Early(self.id.lock().unwrap().clone(), resp))?;
                        continue;
                    }

                    if matches!(
                        status,
                        StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized
                    ) {
                        let id = self.id.lock().unwrap().clone();
                        if auth_sent {
                            debug!(
                                id = self.id.lock().unwrap().to_string(),
                                "received {} response after auth sent", status
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            break;
                        }
                        auth_sent = true;
                        if let Some(cred) = &self.credential {
                            let new_seq = match method {
                                rsip::Method::Cancel => self.get_local_seq(),
                                _ => self.increment_local_seq(),
                            };
                            tx = handle_client_authenticate(new_seq, &tx, resp, cred).await?;
                            tx.send().await?;
                            continue;
                        } else {
                            debug!(
                                id = self.id.lock().unwrap().to_string(),
                                "received 407 response without auth option"
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                            continue;
                        }
                    }

                    debug!(
                        id = self.id.lock().unwrap().to_string(),
                        method = %method,
                        "dialog do_request done: {:?}", status
                    );
                    if !matches!(method, Method::PRack) {
                        self.clear_remote_reliable();
                    }
                    return Ok(Some(resp));
                }
                _ => break,
            }
        }
        Ok(None)
    }

    pub(super) async fn do_request(&self, request: Request) -> Result<Option<Response>> {
        self.send_dialog_request(request).boxed().await
    }

    pub fn snapshot(&self) -> DialogSnapshot {
        let id = self.id.lock().unwrap().clone();

        let state = match &*self.state.lock().unwrap() {
            DialogState::Calling(_) => DialogSnapshotState::Calling,
            DialogState::Trying(_) => DialogSnapshotState::Trying,
            DialogState::Early(_, _) => DialogSnapshotState::Early,
            DialogState::WaitAck(_, _) => DialogSnapshotState::WaitAck,
            DialogState::Confirmed(_, _) => DialogSnapshotState::Confirmed,
            DialogState::Terminated(_, _) => DialogSnapshotState::Terminated,

            DialogState::Updated(_, _, _)
            | DialogState::Publish(_, _, _)
            | DialogState::Notify(_, _, _)
            | DialogState::Refer(_, _, _)
            | DialogState::Message(_, _, _)
            | DialogState::Info(_, _, _)
            | DialogState::Options(_, _, _) => DialogSnapshotState::Confirmed,
        };

        DialogSnapshot {
            state,

            role: self.role.clone(),
            id: id.clone(),

            from: self.from.clone(),
            to: self.to.lock().unwrap().clone(),

            local_cseq: self.local_seq.load(Ordering::Relaxed),
            remote_cseq: self.remote_seq.load(Ordering::Relaxed),

            local_contact: self.local_contact.clone(),
            remote_uri: self.remote_uri.lock().unwrap().clone(),
            remote_contact: self.remote_contact.lock().unwrap().clone(),

            route_set: self.route_set.lock().unwrap().clone(),
            supports_100rel: self.supports_100rel,
        }
    }

    pub(crate) fn try_restore_from_snapshot(
        snapshot: DialogSnapshot,
        endpoint_inner: EndpointInnerRef,
        state_sender: DialogStateSender,
        tu_sender: TransactionEventSender,
    ) -> Result<Option<Self>> {
        if snapshot.state != DialogSnapshotState::Confirmed {
            warn!(
                dialog_id = %snapshot.id,
                state = ?snapshot.state,
                "ignoring non-confirmed dialog snapshot during restore"
            );
            return Ok(None);
        }

        // Ensure To has tag
        let mut to = snapshot.to.clone();
        let to_tag = match snapshot.role {
            TransactionRole::Client => snapshot.id.remote_tag.clone(),
            TransactionRole::Server => snapshot.id.local_tag.clone(),
        };
        if !to_tag.is_empty() && !to.params.iter().any(|p| matches!(p, rsip::Param::Tag(_))) {
            to.params.push(rsip::Param::Tag(to_tag.into()));
        }

        // Ensure From has tag
        let mut from = snapshot.from.clone();
        let from_tag = match snapshot.role {
            TransactionRole::Client => snapshot.id.local_tag.clone(),
            TransactionRole::Server => snapshot.id.remote_tag.clone(),
        };
        if !from_tag.is_empty() && from.tag().is_none() {
            from = from.with_tag(from_tag.into());
        }

        let role = snapshot.role.clone();

        let initial_request = Mutex::new(Self::build_restored_initial_request(
            role.clone(),
            &snapshot.id,
            &from,
            &to,
            &snapshot.remote_uri,
            snapshot.local_cseq,
            snapshot.local_contact.as_ref(),
            endpoint_inner.user_agent.as_str(),
        ));

        Ok(Some(Self {
            role,
            cancel_token: CancellationToken::new(),

            id: Mutex::new(snapshot.id.clone()),
            state: Mutex::new(DialogState::Confirmed(
                snapshot.id.clone(),
                Response::default(),
            )),

            local_seq: AtomicU32::new(snapshot.local_cseq),
            remote_seq: AtomicU32::new(snapshot.remote_cseq),

            local_contact: snapshot.local_contact,
            remote_uri: Mutex::new(snapshot.remote_uri),
            remote_contact: Mutex::new(snapshot.remote_contact),

            from,
            to: Mutex::new(to),

            credential: None,
            route_set: Mutex::new(snapshot.route_set),

            endpoint_inner,
            state_sender,
            tu_sender,

            initial_request,
            supports_100rel: snapshot.supports_100rel,
            remote_reliable: Mutex::new(None),
        }))
    }
    fn build_restored_initial_request(
        role: TransactionRole,
        id: &DialogId,
        from: &rsip::typed::From,
        to: &rsip::typed::To,
        remote_uri: &rsip::Uri,
        local_seq: u32,
        local_contact: Option<&rsip::Uri>,
        user_agent: &str,
    ) -> Request {
        use rsip::Version;

        let mut headers: Vec<Header> = Vec::new();

        headers.push(Header::CallId(id.call_id.clone().into()));

        let from_str = from.clone().untyped().value().to_string();
        let to_str = to.clone().untyped().value().to_string();
        match role {
            TransactionRole::Client => {
                headers.push(Header::From(from_str.into()));
                headers.push(Header::To(to_str.into()));
            }
            TransactionRole::Server => {
                headers.push(Header::From(to_str.into()));
                headers.push(Header::To(from_str.into()));
            }
        }

        let cseq = CSeq {
            seq: local_seq,
            method: Method::Invite,
        };
        headers.push(Header::CSeq(cseq.into()));

        headers.push(Header::UserAgent(user_agent.to_string().into()));

        if let Some(uri) = local_contact {
            headers.push(Contact::from(uri.clone()).into());
        }

        // Content-Length = 0
        headers.push(Header::ContentLength(0u32.into()));

        Request {
            method: Method::Invite,
            uri: remote_uri.clone(),
            headers: headers.into(),
            body: Vec::new(),
            version: Version::V2,
        }
    }
    pub(super) fn transition(&self, state: DialogState) -> Result<()> {
        // Try to send state update, but don't fail if channel is closed
        self.state_sender.send(state.clone()).ok();

        match state {
            DialogState::Updated(_, _, _)
            | DialogState::Notify(_, _, _)
            | DialogState::Info(_, _, _)
            | DialogState::Options(_, _, _) => {
                return Ok(());
            }
            _ => {}
        }
        let mut old_state = self.state.lock().unwrap();
        match (&*old_state, &state) {
            (DialogState::Terminated(id, _), _) => {
                warn!(
                    id = %id,
                    target = %state,
                    "dialog already terminated, ignoring transition"
                );
                return Ok(());
            }
            (DialogState::Confirmed(_, _), DialogState::WaitAck(_, _)) => {
                warn!(target = %state, "dialog already confirmed, ignoring transition");
                return Ok(());
            }
            _ => {}
        }
        debug!(from = %old_state, to = %state, "transitioning state");
        *old_state = state;
        Ok(())
    }

    pub async fn process_transaction_handle(
        &self,
        tx: &mut Transaction,
        mut rx: TransactionCommandReceiver,
    ) -> Result<()> {
        let timeout_duration = self.endpoint_inner.option.t1x64;
        let result = tokio::time::timeout(timeout_duration, async {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    TransactionCommand::Respond {
                        status,
                        headers,
                        body,
                    } => {
                        let is_final = status.kind() != StatusCodeKind::Provisional;
                        let response = self.make_response(&tx.original, status, headers, body);
                        tx.respond(response).await?;

                        if is_final {
                            return Ok(());
                        }
                    }
                }
            }
            Err(crate::Error::TransactionError(
                "User dropped handle without final response".into(),
                tx.key.clone(),
            ))
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => {
                let id = self.id.lock().unwrap().to_string();
                warn!(
                    id,
                    "{} handle dropped or timed out without final reply, returning 501",
                    tx.original.method,
                );
                tx.reply(StatusCode::NotImplemented).await
            }
        }
    }
}

impl std::fmt::Display for DialogState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialogState::Calling(id) => write!(f, "{}(Calling)", id),
            DialogState::Trying(id) => write!(f, "{}(Trying)", id),
            DialogState::Early(id, _) => write!(f, "{}(Early)", id),
            DialogState::WaitAck(id, _) => write!(f, "{}(WaitAck)", id),
            DialogState::Confirmed(id, _) => write!(f, "{}(Confirmed)", id),
            DialogState::Updated(id, _, _) => write!(f, "{}(Updated)", id),
            DialogState::Publish(id, _, _) => write!(f, "{}(Publish)", id),
            DialogState::Notify(id, _, _) => write!(f, "{}(Notify)", id),
            DialogState::Info(id, _, _) => write!(f, "{}(Info)", id),
            DialogState::Options(id, _, _) => write!(f, "{}(Options)", id),
            DialogState::Refer(id, _, _) => write!(f, "{}(Refer)", id),
            DialogState::Message(id, _, _) => write!(f, "{}(Message)", id),
            DialogState::Terminated(id, reason) => write!(f, "{}(Terminated {:?})", id, reason),
        }
    }
}

impl Dialog {
    pub fn id(&self) -> DialogId {
        match self {
            Dialog::ServerInvite(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ClientInvite(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ServerSubscription(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ClientSubscription(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ServerPublication(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ClientPublication(d) => d.inner.id.lock().unwrap().clone(),
        }
    }

    pub fn from(&self) -> &rsip::typed::From {
        match self {
            Dialog::ServerInvite(d) => &d.inner.from,
            Dialog::ClientInvite(d) => &d.inner.from,
            Dialog::ServerSubscription(d) => &d.inner.from,
            Dialog::ClientSubscription(d) => &d.inner.from,
            Dialog::ServerPublication(d) => &d.inner.from,
            Dialog::ClientPublication(d) => &d.inner.from,
        }
    }

    pub fn to(&self) -> rsip::typed::To {
        match self {
            Dialog::ServerInvite(d) => d.inner.to.lock().unwrap().clone(),
            Dialog::ClientInvite(d) => d.inner.to.lock().unwrap().clone(),
            Dialog::ServerSubscription(d) => d.inner.to.lock().unwrap().clone(),
            Dialog::ClientSubscription(d) => d.inner.to.lock().unwrap().clone(),
            Dialog::ServerPublication(d) => d.inner.to.lock().unwrap().clone(),
            Dialog::ClientPublication(d) => d.inner.to.lock().unwrap().clone(),
        }
    }

    pub fn from_inner(role: TransactionRole, inner: DialogInnerRef) -> Self {
        match role {
            TransactionRole::Client => Dialog::ClientInvite(ClientInviteDialog::from_inner(inner)),
            TransactionRole::Server => Dialog::ServerInvite(ServerInviteDialog::from_inner(inner)),
        }
    }
    pub fn remote_contact(&self) -> Option<rsip::Uri> {
        match self {
            Dialog::ServerInvite(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
            Dialog::ClientInvite(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
            Dialog::ServerSubscription(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
            Dialog::ClientSubscription(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
            Dialog::ServerPublication(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
            Dialog::ClientPublication(d) => d
                .inner
                .remote_contact
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| extract_uri_from_contact(c.value()).ok())
                .flatten(),
        }
    }

    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        match self {
            Dialog::ServerInvite(d) => d.handle(tx).await,
            Dialog::ClientInvite(d) => d.handle(tx).await,
            Dialog::ServerSubscription(d) => d.handle(tx).await,
            Dialog::ClientSubscription(d) => d.handle(tx).await,
            Dialog::ServerPublication(d) => d.handle(tx).await,
            Dialog::ClientPublication(d) => d.handle(tx).await,
        }
    }
    pub fn on_remove(&self) {
        match self {
            Dialog::ServerInvite(d) => {
                d.inner.cancel_token.cancel();
            }
            Dialog::ClientInvite(d) => {
                d.inner.cancel_token.cancel();
            }
            Dialog::ServerSubscription(d) => {
                d.inner.cancel_token.cancel();
            }
            Dialog::ClientSubscription(d) => {
                d.inner.cancel_token.cancel();
            }
            Dialog::ServerPublication(d) => {
                d.inner.cancel_token.cancel();
            }
            Dialog::ClientPublication(d) => {
                d.inner.cancel_token.cancel();
            }
        }
    }

    pub async fn hangup(&self) -> Result<()> {
        match self {
            Dialog::ServerInvite(d) => d.bye().await,
            Dialog::ClientInvite(d) => d.hangup().await,
            Dialog::ServerSubscription(d) => d.unsubscribe().await,
            Dialog::ClientSubscription(d) => d.unsubscribe().await,
            Dialog::ServerPublication(d) => d.close().await,
            Dialog::ClientPublication(d) => d.close().await,
        }
    }

    pub fn can_cancel(&self) -> bool {
        match self {
            Dialog::ServerInvite(d) => d.inner.can_cancel(),
            Dialog::ClientInvite(d) => d.inner.can_cancel(),
            Dialog::ServerSubscription(d) => d.inner.can_cancel(),
            Dialog::ClientSubscription(d) => d.inner.can_cancel(),
            Dialog::ServerPublication(d) => d.inner.can_cancel(),
            Dialog::ClientPublication(d) => d.inner.can_cancel(),
        }
    }

    /// Expose a safe hook to refresh the remote target URI/Contact after
    /// receiving responses such as 200 OK.
    pub fn set_remote_target(
        &self,
        uri: rsip::Uri,
        contact: Option<rsip::headers::untyped::Contact>,
    ) {
        match self {
            Dialog::ServerInvite(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ClientInvite(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ServerSubscription(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ClientSubscription(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ServerPublication(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ClientPublication(d) => d.inner.set_remote_target(uri, contact),
        }
    }

    pub async fn request(
        &self,
        method: rsip::Method,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        match self {
            Dialog::ServerInvite(d) => d.request(method, headers, body).await,
            Dialog::ClientInvite(d) => d.request(method, headers, body).await,
            Dialog::ServerSubscription(d) => d.request(method, headers, body).await,
            Dialog::ClientSubscription(d) => d.request(method, headers, body).await,
            Dialog::ServerPublication(d) => d.request(method, headers, body).await,
            Dialog::ClientPublication(d) => d.request(method, headers, body).await,
        }
    }

    pub async fn refer(
        &self,
        refer_to: rsip::Uri,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        match self {
            Dialog::ServerInvite(d) => d.refer(refer_to, headers, body).await,
            Dialog::ClientInvite(d) => d.refer(refer_to, headers, body).await,
            Dialog::ServerSubscription(d) => d.refer(refer_to, headers, body).await,
            Dialog::ClientSubscription(d) => d.refer(refer_to, headers, body).await,
            Dialog::ServerPublication(d) => d.refer(refer_to, headers, body).await,
            Dialog::ClientPublication(d) => d.refer(refer_to, headers, body).await,
        }
    }

    pub async fn message(
        &self,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>> {
        match self {
            Dialog::ServerInvite(d) => d.message(headers, body).await,
            Dialog::ClientInvite(d) => d.message(headers, body).await,
            Dialog::ServerSubscription(d) => d.message(headers, body).await,
            Dialog::ClientSubscription(d) => d.message(headers, body).await,
            Dialog::ServerPublication(d) => d.message(headers, body).await,
            Dialog::ClientPublication(d) => d.message(headers, body).await,
        }
    }
}
