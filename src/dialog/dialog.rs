use super::{
    authenticate::{handle_client_authenticate, Credential},
    client_dialog::ClientInviteDialog,
    server_dialog::ServerInviteDialog,
    DialogId,
};
use crate::{
    header_pop,
    rsip_ext::extract_uri_from_contact,
    transaction::{
        endpoint::EndpointInnerRef,
        key::{TransactionKey, TransactionRole},
        transaction::{Transaction, TransactionEventSender},
    },
    Result,
};
use rsip::{
    headers::Route,
    prelude::{HeadersExt, ToTypedHeader, UntypedHeader},
    typed::{CSeq, Contact},
    Header, Param, Request, Response, SipMessage, StatusCode,
};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

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
/// #     from_tag: "from-tag".to_string(),
/// #     to_tag: "to-tag".to_string(),
/// # };
/// let state = DialogState::Confirmed(dialog_id);
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
    Confirmed(DialogId),
    Updated(DialogId, rsip::Request),
    Notify(DialogId, rsip::Request),
    Info(DialogId, rsip::Request),
    Options(DialogId, rsip::Request),
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
    UacOther(Option<rsip::StatusCode>),
    UasOther(Option<rsip::StatusCode>),
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
///     }
/// }
/// # }
/// ```
#[derive(Clone)]
pub enum Dialog {
    ServerInvite(ServerInviteDialog),
    ClientInvite(ClientInviteDialog),
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

    pub remote_seq: AtomicU32,
    pub remote_uri: rsip::Uri,

    pub from: String,
    pub to: Mutex<String>,

    pub credential: Option<Credential>,
    pub route_set: Vec<Route>,
    pub(super) endpoint_inner: EndpointInnerRef,
    pub(super) state_sender: DialogStateSender,
    pub(super) tu_sender: TuSenderRef,
    pub(super) initial_request: Request,
}

pub type DialogStateReceiver = UnboundedReceiver<DialogState>;
pub type DialogStateSender = UnboundedSender<DialogState>;

pub(super) type DialogInnerRef = Arc<DialogInner>;
pub(super) type TuSenderRef = Mutex<Option<TransactionEventSender>>;

impl DialogState {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, DialogState::Confirmed(_))
    }
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
    ) -> Result<Self> {
        let mut initial_request = initial_request;
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
            to.params.push(rsip::Param::Tag(id.to_tag.clone().into()));
        }

        let (from, to) = match role {
            TransactionRole::Client => (from.to_string(), to.to_string()),
            TransactionRole::Server => (to.to_string(), from.to_string()),
        };

        let mut route_set = vec![];
        for h in initial_request.headers.iter() {
            if let Header::RecordRoute(rr) = h {
                route_set.push(Route::from(rr.value()));
            }
        }
        
        // For UAS (server), route set must be reversed (RFC 3261 section 12.1.1)
        if role == TransactionRole::Server {
            route_set.reverse();
        }
        Ok(Self {
            role,
            cancel_token: CancellationToken::new(),
            id: Mutex::new(id.clone()),
            from,
            to: Mutex::new(to),
            local_seq: AtomicU32::new(cseq),
            remote_uri,
            remote_seq: AtomicU32::new(0),
            credential,
            route_set,
            endpoint_inner,
            state_sender,
            tu_sender: Mutex::new(None),
            state: Mutex::new(DialogState::Calling(id)),
            initial_request,
            local_contact,
        })
    }

    pub fn is_confirmed(&self) -> bool {
        self.state.lock().unwrap().is_confirmed()
    }
    pub fn get_local_seq(&self) -> u32 {
        self.local_seq.load(Ordering::Relaxed)
    }
    pub fn increment_local_seq(&self) -> u32 {
        self.local_seq.fetch_add(1, Ordering::Relaxed);
        self.local_seq.load(Ordering::Relaxed)
    }

    pub fn update_remote_tag(&self, tag: &str) -> Result<()> {
        self.id.lock().unwrap().to_tag = tag.to_string();
        let to: rsip::headers::untyped::To = self.to.lock().unwrap().clone().into();
        *self.to.lock().unwrap() = to.typed()?.with_tag(tag.to_string().into()).to_string();
        info!("updating remote tag to: {}", self.to.lock().unwrap());
        Ok(())
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
        let mut headers = headers.unwrap_or_default();
        let cseq_header = CSeq {
            seq: cseq.unwrap_or_else(|| self.increment_local_seq()),
            method,
        };

        let via = self.endpoint_inner.get_via(addr, branch)?;
        headers.push(via.into());
        headers.push(Header::CallId(
            self.id.lock().unwrap().call_id.clone().into(),
        ));
        headers.push(Header::From(self.from.clone().into()));
        headers.push(Header::To(self.to.lock().unwrap().clone().into()));
        headers.push(Header::CSeq(cseq_header.into()));
        headers.push(Header::UserAgent(
            self.endpoint_inner.user_agent.clone().into(),
        ));

        self.local_contact
            .as_ref()
            .map(|c| headers.push(Contact::from(c.clone()).into()));

        for route in &self.route_set {
            headers.push(Header::Route(route.clone()));
        }
        headers.push(Header::MaxForwards(70.into()));

        body.as_ref().map(|b| {
            headers.push(Header::ContentLength((b.len() as u32).into()));
        });

        let req = rsip::Request {
            method,
            uri: self.remote_uri.clone(),
            headers: headers.into(),
            body: body.unwrap_or_default(),
            version: rsip::Version::V2,
        };
        Ok(req)
    }

    pub(super) fn make_response(
        &self,
        request: &Request,
        status: StatusCode,
        headers: Option<Vec<rsip::Header>>,
        body: Option<Vec<u8>>,
    ) -> rsip::Response {
        let mut resp_headers = rsip::Headers::default();
        self.local_contact
            .as_ref()
            .map(|c| resp_headers.push(Contact::from(c.clone()).into()));

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
                            info!("error parsing to header {}", e);
                            continue;
                        }
                    };

                    if status != StatusCode::Trying {
                        if !to.params.iter().any(|p| matches!(p, Param::Tag(_))) {
                            to.params.push(rsip::Param::Tag(
                                self.id.lock().unwrap().to_tag.clone().into(),
                            ));
                        }
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

        if let Some(headers) = headers {
            for header in headers {
                resp_headers.unique_push(header);
            }
        }

        body.as_ref().map(|b| {
            resp_headers.push(Header::ContentLength((b.len() as u32).into()));
        });

        resp_headers.unique_push(Header::UserAgent(
            self.endpoint_inner.user_agent.clone().into(),
        ));

        Response {
            status_code: status,
            headers: resp_headers,
            body: body.unwrap_or_default(),
            version: request.version().clone(),
        }
    }

    pub(super) async fn do_request(&self, mut request: Request) -> Result<Option<rsip::Response>> {
        let method = request.method().to_owned();
        let destination = request
            .route_header()
            .map(|r| {
                r.typed()
                    .ok()
                    .map(|r| r.uris().first().map(|u| u.uri.clone()))
                    .flatten()
            })
            .flatten();

        header_pop!(request.headers, Header::Route);

        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint_inner.clone(), None);
        tx.destination = destination.as_ref().map(|d| d.try_into().ok()).flatten();

        tx.send().await?;
        let mut auth_sent = false;

        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => match resp.status_code {
                    StatusCode::Trying => {
                        continue;
                    }
                    StatusCode::Ringing | StatusCode::SessionProgress => {
                        self.transition(DialogState::Early(self.id.lock().unwrap().clone(), resp))?;
                        continue;
                    }
                    StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized => {
                        let id = self.id.lock().unwrap().clone();
                        if auth_sent {
                            info!("received {} response after auth sent", resp.status_code);
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
                            tx = handle_client_authenticate(new_seq, tx, resp, cred).await?;
                            tx.send().await?;
                            continue;
                        } else {
                            info!("received 407 response without auth option");
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ))?;
                        }
                    }
                    _ => {
                        debug!("dialog do_request done: {:?}", resp.status_code);
                        return Ok(Some(resp));
                    }
                },
                _ => break,
            }
        }
        Ok(None)
    }

    pub(super) fn transition(&self, state: DialogState) -> Result<()> {
        // Try to send state update, but don't fail if channel is closed
        if let Err(_) = self.state_sender.send(state.clone()) {
            debug!("State sender channel closed, continuing with state transition");
        }

        match state {
            DialogState::Updated(_, _)
            | DialogState::Notify(_, _)
            | DialogState::Info(_, _)
            | DialogState::Options(_, _) => {
                return Ok(());
            }
            _ => {}
        }
        let mut old_state = self.state.lock().unwrap();
        info!("transitioning state: {} -> {}", old_state, state);
        *old_state = state;
        Ok(())
    }
}

impl std::fmt::Display for DialogState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialogState::Calling(id) => write!(f, "{}(Calling)", id),
            DialogState::Trying(id) => write!(f, "{}(Trying)", id),
            DialogState::Early(id, _) => write!(f, "{}(Early)", id),
            DialogState::WaitAck(id, _) => write!(f, "{}(WaitAck)", id),
            DialogState::Confirmed(id) => write!(f, "{}(Confirmed)", id),
            DialogState::Updated(id, _) => write!(f, "{}(Updated)", id),
            DialogState::Notify(id, _) => write!(f, "{}(Notify)", id),
            DialogState::Info(id, _) => write!(f, "{}(Info)", id),
            DialogState::Options(id, _) => write!(f, "{}(Options)", id),
            DialogState::Terminated(id, reason) => write!(f, "{}(Terminated {:?})", id, reason),
        }
    }
}

impl Dialog {
    pub fn id(&self) -> DialogId {
        match self {
            Dialog::ServerInvite(d) => d.inner.id.lock().unwrap().clone(),
            Dialog::ClientInvite(d) => d.inner.id.lock().unwrap().clone(),
        }
    }
    pub async fn handle(&mut self, tx: Transaction) -> Result<()> {
        match self {
            Dialog::ServerInvite(d) => d.handle(tx).await,
            Dialog::ClientInvite(d) => d.handle(tx).await,
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
        }
    }

    pub async fn hangup(&self) -> Result<()> {
        match self {
            Dialog::ServerInvite(d) => d.bye().await,
            Dialog::ClientInvite(d) => {
                if d.inner.is_confirmed() {
                    d.bye().await
                } else {
                    d.cancel().await
                }
            }
        }
    }
}
