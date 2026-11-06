use super::{
    authenticate::{handle_client_authenticate, AuthRetry, Credential},
    invite_dialog::InviteDialog,
    publication::{ClientPublicationDialog, ServerPublicationDialog},
    subscription::{ClientSubscriptionDialog, ServerSubscriptionDialog},
    DialogId,
};
use crate::platform::mpsc::{self, UnboundedReceiver, UnboundedSender};
use crate::platform::sync::Mutex;
use crate::platform::CancellationToken;
use crate::prelude::*;
use crate::sip::{
    headers::typed::record_route::split_rr_values,
    prelude::{HeadersExt, ToTypedHeader},
    typed::{CSeq, Contact},
    Header, Method, Param, Request, Response, Route, SipMessage, StatusCode, StatusCodeKind,
};
use crate::{
    transaction::{
        endpoint::EndpointInnerRef,
        invite_usage::InviteUsage,
        key::{TransactionKey, TransactionRole},
        make_uuid_v4,
        transaction::{Transaction, TransactionEventSender},
    },
    transport::{SipAddr, SipConnection},
    Result,
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use futures::FutureExt;
use tracing::{debug, info, warn};

pub type TransactionCommandSender = crate::platform::BoundedSender<TransactionCommand>;
pub type TransactionCommandReceiver = crate::platform::BoundedReceiver<TransactionCommand>;
#[derive(Debug)]
pub enum TransactionCommand {
    Respond {
        status: StatusCode,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
pub struct TransactionHandle {
    sender: TransactionCommandSender,
    pub(super) control: Arc<super::reinvite::HandleControl>,
}

impl TransactionHandle {
    pub fn new() -> (Self, TransactionCommandReceiver) {
        let (tx, rx) = mpsc::channel(4);
        (
            Self {
                sender: tx,
                control: Arc::default(),
            },
            rx,
        )
    }

    pub async fn reply(
        &self,
        status: StatusCode,
    ) -> core::result::Result<(), mpsc::error::SendError<TransactionCommand>> {
        self.respond(status, None, None).await
    }

    pub async fn respond(
        &self,
        status: StatusCode,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> core::result::Result<(), mpsc::error::SendError<TransactionCommand>> {
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
/// * `Confirmed` - UAC received 2xx (ACK may still be sending); UAS received ACK
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
/// let state = DialogState::Confirmed(dialog_id, rsipstack::sip::Response::default());
/// if state.is_confirmed() {
///     println!("Dialog is established");
/// }
/// # }
/// ```
#[derive(Clone, Debug)]
pub enum DialogState {
    Calling(DialogId),
    Trying(DialogId),
    Early(DialogId, crate::sip::Response),
    WaitAck(DialogId, crate::sip::Response),
    Confirmed(DialogId, crate::sip::Response),
    Updated(DialogId, crate::sip::Request, TransactionHandle),
    Publish(DialogId, crate::sip::Request, TransactionHandle),
    Notify(DialogId, crate::sip::Request, TransactionHandle),
    Refer(DialogId, crate::sip::Request, TransactionHandle),
    Message(DialogId, crate::sip::Request, TransactionHandle),
    Info(DialogId, crate::sip::Request, TransactionHandle),
    Options(DialogId, crate::sip::Request, TransactionHandle),
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
    ProxyError(crate::sip::StatusCode),
    ProxyAuthRequired,
    UacOther(crate::sip::StatusCode),
    UasOther(crate::sip::StatusCode),
}

/// Represents the status of a REFER operation parsed from a NOTIFY request.
#[derive(Debug, Clone)]
pub struct ReferStatus {
    pub status_code: crate::sip::StatusCode,
    pub is_terminated: bool,
}

impl ReferStatus {
    pub fn parse(req: &crate::sip::Request) -> Option<Self> {
        use crate::sip::HasHeaders;

        let mut event = None;
        for header in req.headers().iter() {
            if let crate::sip::Header::Other(name, value) = header {
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
            if let crate::sip::Header::Other(name, value) = header {
                if name.to_string().eq_ignore_ascii_case("subscription-state") {
                    sub_state = Some(value.to_string().to_lowercase());
                    break;
                }
            }
        }
        let sub_state = sub_state?;
        let is_terminated = sub_state.contains("terminated");

        let body = core::str::from_utf8(&req.body).ok()?;
        let status_line = body.lines().find(|l| l.starts_with("SIP/2.0"))?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        let code: u16 = parts[1].parse().ok()?;
        let status_code = crate::sip::StatusCode::from(code);

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
///     Dialog::Invite(invite_dialog) => {
///         // Handle invite dialog (role via invite_dialog.role())
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
    Invite(InviteDialog),
    ServerSubscription(ServerSubscriptionDialog),
    ClientSubscription(ClientSubscriptionDialog),
    ServerPublication(ServerPublicationDialog),
    ClientPublication(ClientPublicationDialog),
}

impl Dialog {
    pub fn state(&self) -> DialogState {
        match self {
            Dialog::Invite(d) => d.state(),
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
            Dialog::Invite(d) => Some(d.as_subscription()),
            Dialog::ServerSubscription(_) => Some(self.clone()),
            Dialog::ClientSubscription(_) => Some(self.clone()),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(super) struct RemoteReliableState {
    dialog_id: DialogId,
    invite_cseq: u32,
    last_rseq: u32,
}

/// A validated Contact, kept separate from the dialog until its refresh is accepted.
pub(super) struct RemoteTarget {
    pub(super) uri: crate::sip::Uri,
    pub(super) contact: crate::sip::headers::untyped::Contact,
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
    pub(super) invite_usage: Arc<Mutex<InviteUsage>>,
    pub role: TransactionRole,
    pub cancel_token: CancellationToken,
    pub id: Mutex<DialogId>,
    pub state: Mutex<DialogState>,

    pub local_seq: AtomicU32,
    pub local_contact: Option<crate::sip::Uri>,
    pub remote_contact: Mutex<Option<crate::sip::headers::untyped::Contact>>,

    pub remote_seq: AtomicU32,
    pub remote_uri: Mutex<crate::sip::Uri>,
    // Latest accepted incoming target refresh. A slow older transaction must
    // not overwrite a newer refresh when its application finally responds.
    remote_target_cseq: Mutex<Option<u32>>,

    pub from: crate::sip::typed::From,
    pub to: Mutex<crate::sip::typed::To>,

    pub credential: Option<Credential>,
    pub route_set: Mutex<Vec<Route>>,

    pub(super) endpoint_inner: EndpointInnerRef,
    pub(super) state_sender: DialogStateSender,
    pub(crate) lifecycle: Mutex<super::lifecycle::LifecycleState>,
    pub(crate) persistence: Mutex<Option<Arc<super::persistence::PersistenceRuntime>>>,
    pub(crate) persistence_owner: Mutex<alloc::sync::Weak<DialogInner>>,
    pub(super) tu_sender: TransactionEventSender,
    /// RFC 7989 Session-ID state; `None` when the dialog does not participate
    /// (no UUID supplied by the application and none received from the peer).
    pub(super) session_id: Mutex<Option<SessionIdState>>,
    // initial request updated when INVITE auth failed with new INVITE
    pub(super) initial_request: Mutex<Request>,
    pub(super) supports_100rel: bool,
    pub(super) remote_reliable: Mutex<Vec<RemoteReliableState>>,
    pub(super) reliable_clients: Mutex<BTreeMap<(DialogId, u32), super::reliable::ReliableClient>>,
    pub(super) reliable_config: Mutex<Option<super::reliable::ReliableProvisionalConfig>>,
    pub(crate) session_timer: Mutex<Option<Arc<super::session_timer::SessionTimer>>>,
    pub(super) reliable_servers: Mutex<BTreeMap<u32, Arc<super::reliable::ReliableServer>>>,
    /// The last ACK received for an INVITE or re-INVITE this dialog answered
    /// (UAS role). Carries the answer when the 2xx carried the offer.
    pub(super) remote_ack: Mutex<Option<Request>>,
    pub(super) server_connection: Mutex<Option<SipConnection>>,
    /// Structural source address of the flow that created this server dialog,
    /// captured at creation time from the connection itself (not parsed from
    /// Via headers). First tier of the dial-back ladder when the affinity
    /// connection is unavailable: immune to missing received/rport params and
    /// valid even after the socket object died.
    pub(super) dialback_target: Mutex<Option<SipAddr>>,
    /// `cancel()` was called on this UAC dialog's INVITE.
    pub(super) cancel_requested: AtomicBool,
    /// That CANCEL waits for a provisional response (RFC 3261 §9.1).
    pub(super) cancel_deferred: AtomicBool,
    pub(super) initial_ack: Mutex<Option<Arc<InviteAck>>>,
    pub(super) reinvite_ack: Mutex<Option<Arc<InviteAck>>>,
}

pub type DialogStateReceiver = UnboundedReceiver<DialogState>;
pub type DialogStateSender = UnboundedSender<DialogState>;

pub(super) type DialogInnerRef = Arc<DialogInner>;

/// Outgoing teardown waits for an ACK attempt; incoming BYE does not.
pub(super) struct InviteAck {
    pub done: CancellationToken,
    completed: AtomicBool,
}

impl InviteAck {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            done: CancellationToken::new(),
            completed: AtomicBool::new(false),
        })
    }

    pub fn finish(&self) {
        self.completed.store(true, Ordering::SeqCst);
        self.done.cancel();
    }
}

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

/// RFC 7989 session-identifier state for a dialog.
///
/// `local` is this endpoint's UUID (stable for the dialog lifetime);
/// `remote` is the peer's UUID, learned from received messages (§8).
/// A dialog only participates in Session-ID when this is `Some` — i.e. the
/// application supplied a UUID (UAC) or the peer sent a Session-ID header
/// (UAS). No UUID is ever generated speculatively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdState {
    pub local: String,
    pub remote: Option<String>,
}
/// A coherent snapshot for application-owned storage and recovery.
///
/// Use [`Self::builder`] to reconstruct stored data. Direct field access remains
/// available; destructuring outside this crate must include `..`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DialogSnapshot {
    /// Captured with routing, CSeq, lifecycle facts, and transaction admission.
    pub runtime: super::snapshot::DialogSnapshotRuntime,
    pub state: DialogSnapshotState,
    pub role: TransactionRole,
    pub id: DialogId,

    pub from: crate::sip::typed::From,
    pub to: crate::sip::typed::To,

    pub local_cseq: u32,
    pub remote_cseq: u32,

    pub local_contact: Option<crate::sip::Uri>,

    pub remote_uri: crate::sip::Uri,
    pub remote_contact: Option<crate::sip::headers::untyped::Contact>,

    pub route_set: Vec<Route>,
    pub supports_100rel: bool,
    /// RFC 7989 Session-ID state, preserved across snapshot restore.
    pub session_id: Option<SessionIdState>,
}
impl DialogSnapshot {
    /// Reconstruct a snapshot without depending on its complete field list.
    ///
    /// State, both CSeq values, and runtime metadata must be supplied explicitly
    /// before building. See [`super::snapshot`] for the 0.9 migration guide.
    pub fn builder(
        id: DialogId,
        role: TransactionRole,
        from: crate::sip::typed::From,
        to: crate::sip::typed::To,
        remote_uri: crate::sip::Uri,
    ) -> super::snapshot::DialogSnapshotBuilder {
        super::snapshot::DialogSnapshotBuilder::new(id, role, from, to, remote_uri)
    }

    /// Only confirmed snapshots with no unfinished signaling can be resumed.
    pub fn is_quiescent(&self) -> bool {
        self.state == DialogSnapshotState::Confirmed && self.runtime.pending.is_empty()
    }
}

impl DialogInner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: TransactionRole,
        id: DialogId,
        initial_request: Request,
        endpoint_inner: EndpointInnerRef,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
        tu_sender: TransactionEventSender,
    ) -> Result<Self> {
        let cseq = initial_request.cseq_header()?.seq()?;

        let remote_uri = match role {
            TransactionRole::Client => initial_request.uri.clone(),
            TransactionRole::Server => initial_request
                .typed_contact_headers()?
                .first()
                .map(|c| c.uri.clone())
                .ok_or_else(|| crate::Error::Error("missing Contact header".to_string()))?,
        };

        let from = initial_request.from_header()?.typed()?;
        let mut to = initial_request.to_header()?.typed()?;
        if !to.params.iter().any(|p| matches!(p, Param::Tag(_))) {
            let tag = match role {
                TransactionRole::Client => &id.remote_tag,
                TransactionRole::Server => &id.local_tag,
            };
            if !tag.is_empty() {
                to.params.push(crate::sip::Param::Tag(tag.clone().into()));
            }
        }

        let mut route_set: Vec<Route> = Vec::new();
        if let TransactionRole::Server = role {
            route_set = initial_request
                .record_route_headers()
                .into_iter()
                .flat_map(|rr| split_rr_values(rr.value()))
                .map(Route::from)
                .collect();
        }

        let supports_100rel = initial_request.header_contains_token("Supported", "100rel")
            || initial_request.header_contains_token("Require", "100rel");

        let session_id = Self::extract_session_id(&initial_request, role);

        Ok(Self {
            invite_usage: Arc::new(Mutex::new(InviteUsage::default())),
            role,
            cancel_token: CancellationToken::new(),
            id: Mutex::new(id.clone()),
            from,
            to: Mutex::new(to),
            local_seq: AtomicU32::new(cseq),
            remote_uri: Mutex::new(remote_uri),
            remote_target_cseq: Mutex::new(None),
            remote_seq: AtomicU32::new(0),
            credential,
            route_set: Mutex::new(route_set),
            endpoint_inner,
            state_sender,
            persistence: Mutex::new(None),
            persistence_owner: Mutex::new(alloc::sync::Weak::new()),
            lifecycle: Mutex::new(super::lifecycle::LifecycleState::default()),
            tu_sender,
            state: Mutex::new(DialogState::Calling(id)),
            initial_request: Mutex::new(initial_request),
            session_id: Mutex::new(session_id),
            local_contact,
            remote_contact: Mutex::new(None),
            supports_100rel,
            remote_reliable: Mutex::new(Vec::new()),
            reliable_clients: Mutex::new(BTreeMap::new()),
            reliable_config: Mutex::new(None),
            session_timer: Mutex::new(None),
            reliable_servers: Mutex::new(BTreeMap::new()),
            remote_ack: Mutex::new(None),
            server_connection: Mutex::new(None),
            dialback_target: Mutex::new(None),
            cancel_requested: AtomicBool::new(false),
            cancel_deferred: AtomicBool::new(false),
            initial_ack: Mutex::new(None),
            reinvite_ack: Mutex::new(None),
        })
    }
    /// Extract RFC 7989 Session-ID state from the initial request.
    ///
    /// * Client role: the header's local-uuid is ours (the application had to
    ///   supply it — the stack never generates one for outgoing requests);
    ///   its remote= value (usually nil) is kept as the initial peer hint.
    /// * Server role: the header's local-uuid belongs to the peer; a local
    ///   UUID is generated so responses can mirror correctly (§6).
    ///
    /// Malformed headers (non-nil local-uuid that is not 32 hex chars) are
    /// discarded per RFC 7989 §6 and the dialog does not participate.
    fn extract_session_id(
        initial_request: &Request,
        role: TransactionRole,
    ) -> Option<SessionIdState> {
        let sid = initial_request.session_id_header()?;
        if !sid.is_valid_header() {
            return None;
        }
        let peer = sid.local_uuid()?;
        match role {
            TransactionRole::Client => Some(SessionIdState {
                local: peer,
                remote: sid.remote_uuid(),
            }),
            TransactionRole::Server => Some(SessionIdState {
                local: make_dialog_session_uuid(),
                remote: Some(peer),
            }),
        }
    }

    /// RFC 7989 §8: learn/refresh the peer's UUID from a received message.
    /// `None` (missing Session-ID) leaves the stored value untouched — the
    /// caller decides CANCEL exemptions per §8. Nil or malformed values are
    /// rejected here as well: the nil UUID is never a valid peer identity.
    pub fn observe_peer_session_uuid(&self, peer: Option<String>) {
        let Some(uuid) = peer else {
            return;
        };
        if !crate::sip::headers::SessionId::is_valid(&uuid)
            || uuid == crate::sip::headers::SessionId::NIL
        {
            return;
        }
        let _snapshot_gate = self.state.lock();
        let mut state = self.session_id.lock();
        if let Some(sid) = state.as_mut() {
            if sid.local != uuid {
                sid.remote = Some(uuid);
                self.lifecycle.lock().revision += 1;
            }
        }
    }

    /// Current session-identifier state, if this dialog participates.
    pub fn session_id_state(&self) -> Option<SessionIdState> {
        self.session_id.lock().clone()
    }

    pub fn set_server_connection(&self, connection: Option<SipConnection>) {
        // Recorded for both roles: server dialogs get it at creation time,
        // client dialogs after the initial INVITE is sent (see
        // `ClientInviteDialog::process_invite`). Drives RFC 5626/7118 flow
        // affinity and the dial-back ladder for both legs.
        *self.server_connection.lock() = connection.clone();
        // Capture the structural source address for the dial-back ladder.
        *self.dialback_target.lock() = connection.and_then(|conn| conn.get_remote_addr().cloned());
    }
    pub fn can_cancel(&self) -> bool {
        self.state.lock().can_cancel()
    }
    pub fn is_confirmed(&self) -> bool {
        self.state.lock().is_confirmed()
    }
    pub fn is_terminated(&self) -> bool {
        self.state.lock().is_terminated()
    }
    pub fn waiting_ack(&self) -> bool {
        self.state.lock().waiting_ack()
    }
    pub fn get_local_seq(&self) -> u32 {
        self.local_seq.load(Ordering::Relaxed)
    }
    pub fn increment_local_seq(&self) -> u32 {
        let _snapshot_gate = self.state.lock();
        self.increment_local_seq_locked()
    }

    fn increment_local_seq_locked(&self) -> u32 {
        self.lifecycle.lock().revision += 1;
        self.local_seq
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    pub(crate) fn admit_remote_seq(
        &self,
        cseq: u32,
        method: &Method,
    ) -> core::result::Result<u32, u32> {
        let _snapshot_gate = self.state.lock();
        let previous = self.remote_seq.load(Ordering::Relaxed);
        if cseq < previous {
            return Err(previous);
        }
        if *method == Method::Bye && (_snapshot_gate.is_confirmed() || _snapshot_gate.waiting_ack())
        {
            let mut lifecycle = self.lifecycle.lock();
            if !lifecycle.pending_remote_bye {
                lifecycle.pending_remote_bye = true;
                lifecycle.revision += 1;
            }
        }
        if cseq != previous {
            self.remote_seq.store(cseq, Ordering::Relaxed);
            self.lifecycle.lock().revision += 1;
        }
        Ok(previous)
    }

    pub fn update_remote_tag(&self, tag: &str) -> Result<()> {
        let _snapshot_gate = self.state.lock();
        self.lifecycle.lock().revision += 1;
        self.id.lock().remote_tag = tag.to_string();

        if self.role == TransactionRole::Client {
            let mut to = self.to.lock();
            *to = to.clone().with_tag(tag.into());
        }
        Ok(())
    }

    pub(super) fn attach_reliable_server(self: &Arc<Self>, tx: &Transaction) -> Result<()> {
        if tx.original.method != Method::Invite {
            return Ok(());
        }
        let Some(config) = self.reliable_config.lock().clone() else {
            return Ok(());
        };
        if !tx.original.header_contains_token("Supported", "100rel")
            && !tx.original.header_contains_token("Require", "100rel")
        {
            return Ok(());
        }
        let cseq = tx.original.cseq_header()?.seq()?;
        let mut servers = self.reliable_servers.lock();
        let server = servers
            .entry(cseq)
            .or_insert_with(|| {
                super::reliable::ReliableServer::new(
                    self,
                    tx.original.clone(),
                    tx.tu_sender.clone(),
                    config,
                )
            })
            .clone();
        *tx.reliable_provisional.lock() = Some(server);
        Ok(())
    }

    pub(super) async fn receive_prack(&self, tx: &mut Transaction) -> Result<()> {
        let Some((_, cseq, _)) = crate::sip::message::rack_parts(&tx.original) else {
            return tx.reply(StatusCode::BadRequest).await;
        };
        let server = self.reliable_servers.lock().get(&cseq).cloned();
        if let Some(server) = server {
            server.handle_prack(tx).await
        } else {
            self.reject_unmatched_prack(tx).await
        }
    }

    pub(super) fn clear_remote_reliable(&self, invite_cseq: u32) {
        self.reliable_clients
            .lock()
            .retain(|(_, cseq), _| *cseq != invite_cseq);
        self.remote_reliable
            .lock()
            .retain(|s| s.invite_cseq != invite_cseq);
    }

    pub(super) fn prepare_prack_request(&self, resp: &Response) -> Result<Option<Request>> {
        if !(101..200).contains(&resp.status_code.code())
            || !resp.header_contains_token("Require", "100rel")
        {
            return Ok(None);
        }
        let Some(rseq) = resp.rseq_value() else {
            return Ok(None);
        };
        let cseq_header = resp.cseq_header()?;
        let cseq = cseq_header.seq()?;
        if cseq_header.method()? != Method::Invite {
            return Ok(None);
        }
        let dialog_id = DialogId::try_from((resp, TransactionRole::Client))?;
        let local_id = self.id.lock().clone();
        if dialog_id.call_id != local_id.call_id
            || dialog_id.local_tag != local_id.local_tag
            || dialog_id.remote_tag.is_empty()
        {
            return Ok(None);
        }

        let mut states = self.remote_reliable.lock();
        let state = states
            .iter_mut()
            .find(|s| s.dialog_id == dialog_id && s.invite_cseq == cseq);
        if let Some(state) = state.as_ref() {
            // RFC 3262 §4: duplicates, old responses and gaps are discarded
            // without delivering their SDP or generating another PRACK.
            if state.last_rseq.checked_add(1) != Some(rseq) {
                return Ok(None);
            }
        } else if rseq > i32::MAX as u32 {
            // The first RSeq in a transaction is in 1..=2^31-1 (§3).
            return Ok(None);
        }
        // RFC 6141: a newly accepted reliable provisional refreshes Contact
        // before its PRACK is routed. Duplicates and gaps were rejected above.
        self.refresh_target_from_response(resp)?;
        let headers = vec![Header::RAck(format!("{} {} INVITE", rseq, cseq).into())];
        let mut prack = self.make_request(
            Method::PRack,
            Some(self.increment_local_seq()),
            None,
            None,
            Some(headers),
            None,
        )?;
        // Select the early dialog that sent this response, including forks.
        prack
            .headers
            .unique_push(Header::To(resp.to_header()?.clone()));
        if let Some(state) = state {
            state.last_rseq = rseq;
        } else {
            states.push(RemoteReliableState {
                dialog_id,
                invite_cseq: cseq,
                last_rseq: rseq,
            });
        }
        Ok(Some(prack))
    }

    /// Returns false when the provisional must be discarded, including its body.
    pub(super) async fn handle_provisional_response(
        self: &Arc<Self>,
        resp: &Response,
        request: &Request,
    ) -> Result<bool> {
        if resp.header_contains_token("Require", "100rel") && resp.status_code != StatusCode::Trying
        {
            let config = self.reliable_config.lock().clone();
            if let Some(config) = config {
                return self.start_reliable_prack(resp, request, config);
            }

            if request.method != Method::Invite
                || resp.cseq_header()?.seq()? != request.cseq_header()?.seq()?
            {
                return Ok(false);
            }
            // An in-dialog response must not change the peer's tag.
            if let Some(tag) = request.to_header()?.tag()? {
                if resp.to_header()?.tag()?.as_ref() != Some(&tag) {
                    return Ok(false);
                }
            }
            let Some(prack) = self.prepare_prack_request(resp)? else {
                return Ok(false);
            };
            if let Some(tag) = resp.to_header()?.tag()? {
                self.update_remote_tag(tag.value())?;
            }
            let _ = self.send_prack_request(prack).await?;
        } else if resp.status_code != StatusCode::Trying {
            if let Some(tag) = resp.to_header()?.tag()? {
                self.update_remote_tag(tag.value())?;
            }
        }
        Ok(true)
    }

    /// Disabled dialogs reject required 100rel rather than falsely accepting it.
    /// RFC 3262 §3 explicitly permits rejecting required 100rel with 420.
    pub(super) async fn reject_required_100rel(&self, tx: &mut Transaction) -> Result<bool> {
        if self.reliable_config.lock().is_some()
            || tx.original.method != Method::Invite
            || !tx.original.header_contains_token("Require", "100rel")
        {
            return Ok(false);
        }
        let initial =
            self.role == TransactionRole::Server && tx.original.to_header()?.tag()?.is_none();
        tx.reply_with(
            StatusCode::BadExtension,
            vec![Header::Unsupported("100rel".into())],
            None,
        )
        .await?;
        if initial {
            let id = self.id.lock().clone();
            self.transition(DialogState::Terminated(
                id,
                TerminatedReason::UasOther(StatusCode::BadExtension),
            ));
        }
        Ok(true)
    }

    pub(super) async fn reject_unmatched_prack(&self, tx: &mut Transaction) -> Result<()> {
        // A syntactically valid RAck is not proof of a matching outstanding
        // reliable response. The built-in UAS does not create any (§3).
        let status = if crate::sip::message::rack_parts(&tx.original).is_some() {
            StatusCode::CallTransactionDoesNotExist
        } else {
            StatusCode::BadRequest
        };
        tx.reply(status).await
    }

    pub(super) async fn send_prack_request(&self, request: Request) -> Result<Option<Response>> {
        self.send_prack_request_to(request, None).await
    }

    pub(super) async fn send_prack_request_to(
        &self,
        request: Request,
        destination: Option<SipAddr>,
    ) -> Result<Option<Response>> {
        let tx = self.start_prack_transaction(request, destination).await?;
        self.finish_prack_transaction(tx).await
    }

    pub(super) async fn start_prack_transaction(
        &self,
        request: Request,
        destination: Option<SipAddr>,
    ) -> Result<Transaction> {
        let method = request.method().to_owned();
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        // RFC 5626 flow affinity: reuse the reliable connection recorded for
        // this server dialog instead of resolving the remote Contact.
        let affinity_connection = self.resolve_affinity_connection();
        let mut tx = Transaction::new_client(
            key,
            request,
            self.endpoint_inner.clone(),
            affinity_connection,
        );

        if destination.is_some() {
            tx.destination = destination;
        } else if let Some(route) = tx.original.route_header() {
            if let Ok(first_route) = route.typed() {
                tx.destination = SipAddr::try_from(&first_route.uri).ok();
            }
        }

        self.bind_persistence(&tx);
        match tx.send().await {
            Ok(_) => {
                debug!(
                    id = self.id.lock().to_string(),
                    method = %method,
                    destination=tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    key=%tx.key,
                    "request sent done",
                );
            }
            Err(e) => {
                warn!(
                    id = self.id.lock().to_string(),
                    destination = tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    method = %method,
                    "failed to send request error: {}",
                    e
                );
                debug!(id = self.id.lock().to_string(), req = %tx.original, "request that failed to send");
                return Err(e);
            }
        }

        Ok(tx)
    }

    pub(super) async fn finish_prack_transaction(
        &self,
        mut tx: Transaction,
    ) -> Result<Option<Response>> {
        let mut auth = AuthRetry::new();
        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => match resp.status_code {
                    StatusCode::Trying => continue,
                    StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized => {
                        let id = self.id.lock().clone();
                        if !auth.should_answer(&resp) {
                            if self.reliable_config.lock().is_some() {
                                return Ok(Some(resp));
                            }
                            debug!(
                                id = self.id.lock().to_string(),
                                "received {} response after auth sent", resp.status_code
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ));
                            break;
                        }
                        if let Some(cred) = &self.credential {
                            let new_seq = self.increment_local_seq();
                            tx = handle_client_authenticate(new_seq, &tx, resp, cred).await?;
                            self.bind_persistence(&tx);
                            tx.send().await?;
                            continue;
                        } else {
                            if self.reliable_config.lock().is_some() {
                                return Ok(Some(resp));
                            }
                            debug!(
                                id = self.id.lock().to_string(),
                                "received 407 response without auth option"
                            );
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ));
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
        tx.check_persistence()?;
        Ok(None)
    }

    /// Update the dialog's remote target URI and optional Contact header.
    ///
    /// When a 2xx/UPDATE response carries a new Contact, call this to ensure
    /// subsequent in-dialog requests route to the latest remote target.
    pub fn set_remote_target(
        &self,
        uri: crate::sip::Uri,
        contact: Option<crate::sip::headers::untyped::Contact>,
    ) {
        let _snapshot_gate = self.state.lock();
        self.set_remote_target_locked(uri, contact);
    }

    fn set_remote_target_locked(
        &self,
        uri: crate::sip::Uri,
        contact: Option<crate::sip::headers::untyped::Contact>,
    ) {
        *self.remote_uri.lock() = uri;
        *self.remote_contact.lock() = contact;
        self.lifecycle.lock().revision += 1;
    }

    pub(super) fn is_target_refresh(method: &Method) -> bool {
        matches!(method, Method::Invite | Method::Update)
    }

    /// Parse without changing any dialog state. A refresh never learns a new
    /// route set; that only happens when the dialog is established (RFC 3261 §12.2).
    pub(super) fn parse_target_refresh_contact(
        message: &impl HeadersExt,
    ) -> Result<Option<RemoteTarget>> {
        let headers = message.contact_headers();
        if headers.is_empty() {
            return Ok(None);
        }
        let contacts = message.typed_contact_headers()?;
        if headers.len() != 1 || contacts.len() != 1 {
            return Err(crate::Error::Error(
                "target refresh requires a single Contact URI".into(),
            ));
        }
        let uri = contacts[0].uri.clone();
        if !matches!(
            uri.scheme,
            Some(crate::sip::Scheme::Sip | crate::sip::Scheme::Sips)
        ) || uri.host_with_port.host.to_string().is_empty()
        {
            return Err(crate::Error::Error(
                "target refresh requires a SIP or SIPS Contact URI".into(),
            ));
        }
        Ok(Some(RemoteTarget {
            uri,
            contact: headers[0].clone(),
        }))
    }

    /// Preserve the observed final response and its accepted target together.
    /// Initial INVITE confirmation is installed by its response observer;
    /// a re-INVITE may refresh only its own established dialog, not another fork.
    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    pub(crate) async fn checkpoint_invite_response(
        &self,
        request: &Request,
        response: &Response,
    ) -> Result<()> {
        let in_dialog = request
            .to_header()?
            .tag()?
            .is_some_and(|tag| !tag.value().is_empty());
        let target = if in_dialog
            && response.status_code.kind() == StatusCodeKind::Successful
            && DialogId::try_from((response, TransactionRole::Client))
                .is_ok_and(|id| id == *self.id.lock())
            && response.cseq_header()?.seq()? == request.cseq_header()?.seq()?
        {
            Self::parse_target_refresh_contact(response)?
        } else {
            None
        };
        let receiver = {
            let state = self.state.lock();
            if let Some(target) = target {
                self.set_remote_target_locked(target.uri, Some(target.contact));
            }
            self.enqueue_checkpoint_locked(
                &state,
                super::persistence::DialogCheckpointReason::BeforeAck,
                Some(response.clone().into()),
            )
        };
        if let Some(mut receiver) = receiver {
            receiver
                .recv()
                .await
                .unwrap_or_else(|| Err("dialog persistence worker stopped".into()))
                .map_err(crate::Error::Error)?;
        }
        Ok(())
    }

    fn refresh_target_from_response(&self, response: &Response) -> Result<()> {
        if let Some(target) = Self::parse_target_refresh_contact(response)? {
            self.set_remote_target(target.uri, Some(target.contact));
        }
        Ok(())
    }

    pub(super) fn accept_target_refresh(&self, cseq: u32, target: &RemoteTarget) {
        let _snapshot_gate = self.state.lock();
        let mut last = self.remote_target_cseq.lock();
        if last.is_some_and(|accepted| cseq <= accepted) {
            return;
        }
        self.set_remote_target_locked(target.uri.clone(), Some(target.contact.clone()));
        *last = Some(cseq);
    }

    pub(super) fn accepts_target_refresh(method: &Method, response: &Response) -> bool {
        Self::is_target_refresh(method)
            && (response.status_code.kind() == StatusCodeKind::Successful
                || (*method == Method::Invite
                    && response.status_code.kind() == StatusCodeKind::Provisional
                    && response.status_code != StatusCode::Trying
                    && response.header_contains_token("Require", "100rel")
                    && response.rseq_value().is_some()))
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
            .record_route_headers()
            .into_iter()
            .flat_map(|rr| split_rr_values(rr.value()))
            .map(Route::from)
            .collect();

        new_route_set.reverse();
        let _snapshot_gate = self.state.lock();
        *self.route_set.lock() = new_route_set;
        self.lifecycle.lock().revision += 1;
    }

    pub(super) fn make_request_with_vias(
        &self,
        method: crate::sip::Method,
        cseq: Option<u32>,
        vias: Vec<crate::sip::headers::typed::Via>,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<crate::sip::Request> {
        let _snapshot_gate = self.state.lock();
        let mut out: Vec<Header> = Vec::new();

        // --- system headers first ---

        let cseq_header = CSeq {
            seq: cseq.unwrap_or_else(|| self.increment_local_seq_locked()),
            method: method.clone(),
        };

        for via in vias {
            out.push(Header::Via(via.into()));
        }

        out.push(Header::CallId(self.id.lock().call_id.clone().into()));

        let to = self.to.lock().clone().to_string();

        let from = self.from.clone().to_string();

        match self.role {
            TransactionRole::Client => {
                out.push(Header::From(from.into()));
                out.push(Header::To(to.into()));
            }
            TransactionRole::Server => {
                out.push(Header::From(to.into()));
                out.push(Header::To(from.into()));
            }
        }

        out.push(Header::CSeq(cseq_header.into()));
        out.push(Header::UserAgent(
            self.endpoint_inner.user_agent.clone().into(),
        ));

        if let Some(uri) = self.local_contact.as_ref() {
            out.push(Contact::from(uri.clone()).into());
        }

        {
            let route_set = self.route_set.lock();
            out.extend(route_set.iter().cloned().map(Header::Route));
        }

        out.push(Header::MaxForwards(70.into()));

        // RFC 7989: participating dialogs carry `Session-ID: <local>;remote=<peer>`
        // on every in-dialog request. Skipped when the caller supplies their own.
        {
            let state = self.session_id.lock();
            if let Some(sid) = state.as_ref() {
                let caller_supplied = headers
                    .as_ref()
                    .is_some_and(|hs| hs.iter().any(|h| matches!(h, Header::SessionId(_))));
                if !caller_supplied {
                    if let Some(h) = build_session_id_header(&sid.local, sid.remote.as_deref()) {
                        out.push(h);
                    }
                }
            }
        }

        out.push(Header::ContentLength(
            body.as_ref().map_or(0u32, |b| b.len() as u32).into(),
        ));

        // --- custom headers LAST (filtered) ---
        if let Some(extra) = headers {
            for h in extra {
                if !is_system_header(&h) {
                    out.push(h);
                }
            }
        }

        let mut request = crate::sip::Request {
            method,
            uri: self.remote_uri.lock().clone(),
            headers: out.into(),
            body: body.unwrap_or_default(),
            version: crate::sip::Version::V2,
        };
        if request.method == Method::Invite {
            if let Some(config) = self.reliable_config.lock().as_ref() {
                super::reliable::add_option(&mut request, "Supported", "100rel");
                if config.require {
                    super::reliable::add_option(&mut request, "Require", "100rel");
                }
            }
        }
        if let Some(timer) = self.session_timer.lock().as_ref() {
            timer.outgoing(&mut request);
        }
        Ok(request)
    }

    pub(super) fn make_request(
        &self,
        method: crate::sip::Method,
        cseq: Option<u32>,
        addr: Option<crate::transport::SipAddr>,
        branch: Option<Param>,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<crate::sip::Request> {
        let addr = addr.or_else(|| self.via_addr_for_send_transport());
        let via = self.endpoint_inner.get_via(addr, branch)?;
        self.make_request_with_vias(method, cseq, vec![via], headers, body)
    }

    /// The listener address whose transport matches the one an in-dialog
    /// request will be sent over: the reliable flow reused by affinity, else
    /// the outbound proxy, else the transport of the first route, else of the
    /// remote target. The Via must name the transport the request is sent on
    /// (RFC 3261 §18.1.1); `make_invite_request` does the same for the
    /// initial INVITE. `None` keeps the endpoint's default (first) listener,
    /// also when a target locator decides the transport at send time.
    fn via_addr_for_send_transport(&self) -> Option<crate::transport::SipAddr> {
        use crate::sip::uri::ParamsExt;

        let transport = match self.resolve_affinity_connection() {
            Some(connection) => connection.get_addr().r#type,
            None if self.endpoint_inner.locator.is_some() => None,
            None => match self.endpoint_inner.transport_layer.outbound.as_ref() {
                Some(outbound) => outbound.r#type,
                None => {
                    let route = self.route_set.lock().first().cloned();
                    match route {
                        Some(route) => route
                            .typed()
                            .ok()
                            .and_then(|route| route.uri.transport().cloned()),
                        None => self.remote_uri.lock().transport().cloned(),
                    }
                }
            },
        }
        .filter(|t| *t != crate::sip::Transport::Udp)?;

        // The Via must advertise one of OUR addresses (RFC 3261 §18.1.1).
        // Search the listeners only: the connection cache holds remote peer
        // addresses, and a WS/WSS client's channel connection carries the
        // client's own ip:port — matching it here pointed the Via of every
        // in-dialog request (BYE / re-INVITE / UPDATE / INFO) back at the
        // remote client.
        let listens = self.endpoint_inner.transport_layer.get_listen_addrs();
        if let Some(addr) = listens.iter().find(|a| a.r#type == Some(transport)) {
            return Some(addr.clone());
        }
        // No listener of this transport (WS served through an HTTP upgrade,
        // for example): advertise the default listener's address with this
        // request's transport token, mirroring the manual Via dial-back
        // requests build. Responses to reliable-transport requests return on
        // the flow itself, so the token keeps them consistent.
        let mut addr = listens.first().cloned()?;
        addr.r#type = Some(transport);
        Some(addr)
    }

    pub(super) fn make_response(
        &self,
        request: &Request,
        status: StatusCode,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> crate::sip::Response {
        let mut resp_headers = crate::sip::Headers::default();

        // RFC 7989 §6: the response mirrors `<local=ours>;remote=<peer>`,
        // where the peer UUID is the local-uuid of the *request* (it may have
        // just changed on a mid-dialog request — §8). History-Info entries
        // are mirrored per RFC 7044 §9.4 only when the request carried any.
        let request_peer_uuid = request.session_id_header().and_then(|s| s.local_uuid());
        let request_has_history = !request.history_info_headers().is_empty();
        let user_supplied_history = headers
            .as_ref()
            .is_some_and(|hs| hs.iter().any(|h| matches!(h, Header::HistoryInfo(_))));

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
                        to.params.push(crate::sip::Param::Tag(
                            self.id.lock().local_tag.clone().into(),
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

        if let Some(c) = self.local_contact.as_ref() {
            resp_headers.push(Contact::from(c.clone()).into())
        }

        if status != StatusCode::Trying {
            {
                let state = self.session_id.lock();
                if let Some(sid) = state.as_ref() {
                    let remote = request_peer_uuid.clone().or_else(|| sid.remote.clone());
                    if let Some(h) = build_session_id_header(&sid.local, remote.as_deref()) {
                        resp_headers.push(h);
                    }
                }
            }
            if request_has_history && !user_supplied_history {
                for h in request.headers.iter() {
                    if let Header::HistoryInfo(hi) = h {
                        resp_headers.push(Header::HistoryInfo(hi.clone()));
                    }
                }
            }
        }

        if let Some(headers) = headers {
            for header in headers {
                match &header {
                    crate::sip::Header::Other(name, _) => {
                        let lname = name.to_ascii_lowercase();
                        resp_headers.retain(|h| {
                            !matches!(
                                h,
                                crate::sip::Header::Other(n, _) if n.to_ascii_lowercase() == lname
                            )
                        });
                        resp_headers.push(header);
                    }
                    // History-Info is multi-instance; never dedup entries.
                    crate::sip::Header::HistoryInfo(_) => {
                        resp_headers.push(header);
                    }
                    _ => resp_headers.unique_push(header),
                }
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
            wire_reason: None,
            headers: resp_headers,
            body: body.unwrap_or_default(),
            version: *request.version(),
        }
    }

    /// Resolve the connection to reuse for outgoing in-dialog requests
    /// (RFC 5626 flow affinity / RFC 7118 §6.2).
    ///
    /// Returns `Some(connection)` when all of the following hold:
    /// * the recorded connection uses a reliable transport (WS/WSS/TCP/TLS)
    ///   — UDP dialogs keep the classic destination-based routing,
    /// * the flow is still alive.
    ///
    /// Applies to both dialog roles: a UAS dialog rides the flow the initial
    /// request arrived on; a UAC dialog rides the flow its initial INVITE
    /// was sent on (e.g. a proxy dialing a WebSocket callee).
    ///
    /// A route set does NOT defeat the affinity: a TLS/WSS flow-bound peer
    /// (rustpbx among them) keeps its dialog state on the flow, so a BYE
    /// routed off-flow via a UDP Record-Route hop comes back 481 and the
    /// retransmissions burn Timer F. Reliable-transport flows are reused
    /// whenever they exist; UDP-only dialogs are unaffected.
    fn resolve_affinity_connection(&self) -> Option<SipConnection> {
        let conn = self.server_connection.lock().clone();
        let reason = match &conn {
            None => "no-recorded-connection",
            Some(c) if !c.is_reliable() => "connection-not-reliable",
            Some(c) => match c.cancel_token() {
                Some(token) if token.is_cancelled() => "connection-cancelled",
                _ => return conn,
            },
        };
        debug!(
            id = %self.id.lock(),
            has_route_set = !self.route_set.lock().is_empty(),
            why = reason,
            "affinity unavailable"
        );
        None
    }

    /// Test-visible wrapper around [`Self::resolve_affinity_connection`].
    #[cfg(test)]
    pub fn test_resolve_affinity_connection(&self) -> Option<SipConnection> {
        self.resolve_affinity_connection()
    }

    /// Extract a routable SipAddr from the initial request's top Via header
    /// (`received` + `rport`), usable as a last-resort dial-back target when
    /// normal resolution fails and no affinity connection exists.
    fn fallback_target_from_initial_via(initial_request: &Request) -> Option<SipAddr> {
        let via = initial_request.via_header().ok()?.typed().ok()?;
        let received = via.received()?.ok()?;
        let port: u16 = via.rport()??;
        Some(SipAddr {
            r#type: Some(via.transport),
            addr: crate::sip::HostWithPort {
                host: crate::sip::Host::IpAddr(received),
                port: Some(port.into()),
            },
        })
    }

    async fn send_dialog_request(
        self: &Arc<Self>,
        request: Request,
        options: Option<super::reinvite::ReinviteOptions>,
    ) -> Result<Option<Response>> {
        let negotiation = Self::is_target_refresh(&request.method);
        if negotiation {
            self.begin_negotiation();
        }
        let result = self.send_dialog_request_inner(request, options).await;
        if negotiation {
            self.finish_negotiation();
            self.checkpoint(
                super::persistence::DialogCheckpointReason::SignalingCompleted,
                None,
            )
            .await?;
        }
        result
    }

    async fn send_dialog_request_inner(
        self: &Arc<Self>,
        request: Request,
        options: Option<super::reinvite::ReinviteOptions>,
    ) -> Result<Option<Response>> {
        let method = request.method().to_owned();
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        // RFC 5626 flow affinity: deliver in-dialog requests to the remote
        // UA over the same reliable connection the initial request used.
        let affinity_connection = self.resolve_affinity_connection();
        let mut tx = Transaction::new_client(
            key,
            request,
            self.endpoint_inner.clone(),
            affinity_connection,
        );
        tx.defer_success_ack = options.as_ref().is_some_and(|o| o.answer_handler.is_some());
        tx.force_success_ack = options.is_some() && !tx.defer_success_ack;
        self.bind_persistence(&tx);
        self.reserve_invite(&tx)?;

        if let Some(route) = tx.original.route_header() {
            if let Ok(first_route) = route.typed() {
                tx.destination = SipAddr::try_from(&first_route.uri).ok();
            }
        }
        let need_fallback_retry;
        let mut send_error = None;
        match tx.send().await {
            Ok(_) => {
                debug!(
                    id = self.id.lock().to_string(),
                    method = %method,
                    destination=tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                    key=%tx.key,
                    "request sent done",
                );
                need_fallback_retry = tx.connection.is_none();
            }
            Err(e) => {
                // Hard transport-resolution failures must not abort server
                // legs whose remote target cannot be routed the classic way;
                // fall through to the dial-back retry below.
                need_fallback_retry = self.role == TransactionRole::Server && method != Method::Ack;
                if !need_fallback_retry {
                    warn!(
                        id = self.id.lock().to_string(),
                        destination = tx.destination.as_ref().map(|d| d.to_string()).as_deref(),
                        method = %method,
                        "failed to send request error: {}",
                        e
                    );
                    debug!(id = self.id.lock().to_string(), req = %tx.original, "request that failed to send");
                    return Err(e);
                }
                send_error = Some(e);
            }
        }

        // Last resort for server dialogs: when no usable connection was found
        // (dead WebSocket flow, restored dialog, unroutable Contact), retry
        // against the flow's real source address. Ladder:
        //   1. address captured from the connection at dialog creation
        //      (immune to missing received/rport parameters),
        //   2. initial request's Via header (`received` + `rport`),
        //      covering snapshot-restored dialogs with no stored connection.
        if need_fallback_retry && method != Method::Ack {
            let fallback_addr = {
                let stored = self.dialback_target.lock().clone();
                match stored {
                    Some(addr) => Some(addr),
                    None => {
                        let initial = self.initial_request.lock();
                        Self::fallback_target_from_initial_via(&initial)
                    }
                }
            };
            if let Some(fallback_addr) = fallback_addr {
                info!(
                    id = self.id.lock().to_string(),
                    method = %method,
                    fallback = %fallback_addr,
                    "no usable connection, retrying via recorded flow address"
                );
                tx.destination = Some(fallback_addr.clone());
                // The dial-back can leave on another transport than the one
                // the Via was built for; keep the Via matching it.
                let transport = fallback_addr.r#type.unwrap_or_default();
                // Listeners only (see `via_addr_for_send_transport`): a
                // connection-cache match here advertised the remote peer's
                // address as our own Via.
                let listens = self.endpoint_inner.transport_layer.get_listen_addrs();
                let listener = listens
                    .iter()
                    .find(|a| a.r#type.unwrap_or_default() == transport)
                    .cloned()
                    .or_else(|| {
                        let mut addr = listens.first().cloned()?;
                        addr.r#type = Some(transport);
                        Some(addr)
                    });
                let branch = tx
                    .original
                    .top_via_header()
                    .and_then(|via| via.typed())
                    .ok()
                    .filter(|via| via.transport != transport)
                    .and_then(|via| {
                        via.params
                            .into_iter()
                            .find(|p| matches!(p, Param::Branch(_)))
                    });
                if let (Some(listener), Some(branch)) = (listener, branch) {
                    if let (Ok(new_via), Ok(via)) = (
                        self.endpoint_inner.get_via(Some(listener), Some(branch)),
                        tx.original.via_header_mut(),
                    ) {
                        via.update_first_value(|_| Ok(new_via.into())).ok();
                    }
                }
                if let Err(e) = tx.send().await {
                    warn!(
                        id = self.id.lock().to_string(),
                        destination = %fallback_addr,
                        "fallback send failed error: {}",
                        e
                    );
                }
            } else {
                debug!(
                    id = self.id.lock().to_string(),
                    method = %method,
                    "no usable connection and no dial-back target; giving up after first send"
                );
                // The failed send never started the transaction: no response
                // or timer will ever end it, so report the error now.
                if let Some(e) = send_error {
                    return Err(e);
                }
            }
        }

        let mut cancel_watch = options
            .as_ref()
            .map(|o| super::reinvite::RequestCancellation::new(&tx, Some(o.cancellation.clone())));
        let mut auth = AuthRetry::new();
        let mut timer_retries = 0;
        loop {
            let timer = self.session_timer.lock().clone();
            let original = tx.original.clone();
            let mut timer_result = Ok(());
            let msg = tx
                .receive_with_response_observer(|response, _received_at| {
                    if DialogId::try_from((response, TransactionRole::Client))
                        .is_ok_and(|id| id == *self.id.lock())
                    {
                        if let Some(timer) = &timer {
                            timer_result = timer.received(&original, response);
                        }
                    }
                })
                .await;
            let Some(msg) = msg else {
                break;
            };
            match msg {
                SipMessage::Response(resp) => {
                    // RFC 7989 §8: accept the peer's (possibly new) UUID from
                    // any received response; missing/nil values change nothing.
                    let peer_uuid = resp.session_id_header().and_then(|s| s.local_uuid());
                    self.observe_peer_session_uuid(peer_uuid);
                    let status = resp.status_code.clone();
                    if let Some(watch) = &cancel_watch {
                        if status.kind() == StatusCodeKind::Provisional {
                            watch.provisional.cancel();
                        } else {
                            watch.finished.cancel();
                        }
                    }
                    if status == StatusCode::Trying {
                        continue;
                    }

                    // In-dialog responses cannot establish a different dialog.
                    // Do not let a mismatched tag rewrite either the target or
                    // the tag used for the next PRACK/request.
                    if Self::is_target_refresh(&method)
                        && !DialogId::try_from((&resp, TransactionRole::Client))
                            .is_ok_and(|id| id == *self.id.lock())
                    {
                        warn!(id = %self.id.lock(), "ignoring target refresh response for another dialog");
                        continue;
                    }

                    if status.kind() == StatusCodeKind::Provisional {
                        if method == Method::Invite
                            && !self
                                .handle_provisional_response(&resp, &tx.original)
                                .await?
                        {
                            continue;
                        }
                        if let Some(sender) = options
                            .as_ref()
                            .and_then(|o| o.provisional_responses.as_ref())
                        {
                            sender.send(resp.clone()).ok();
                        }
                        // RFC 3261 §12: a dialog moves from early to confirmed
                        // and never back. A 1xx to a mid-dialog request (re-INVITE,
                        // UPDATE, ...) must not regress an established dialog to
                        // Early, or BYE is refused and hangup() tries to CANCEL.
                        // The provisional is still notified so the caller sees it.
                        let state = DialogState::Early(self.id.lock().clone(), resp);
                        if self.can_cancel() {
                            self.transition(state);
                        } else if !self.is_terminated() {
                            // Still notify the provisional so the caller sees
                            // it (e.g. a reliable 183 with SDP to a
                            // re-INVITE) — but never after the dialog
                            // terminated, matching `transition`'s contract.
                            self.state_sender.send(state).ok();
                        }
                        continue;
                    }

                    if matches!(
                        status,
                        StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized
                    ) && !options
                        .as_ref()
                        .is_some_and(|o| o.cancellation.is_cancelled())
                    {
                        let id = self.id.lock().clone();
                        if !auth.should_answer(&resp) {
                            debug!(
                                id = self.id.lock().to_string(),
                                "received {} response after auth sent", status
                            );
                            // A failed in-dialog request does not undo the
                            // established session (RFC 3261 sections 12/14.1).
                            if self.is_confirmed() {
                                if method != Method::PRack {
                                    self.clear_remote_reliable(tx.original.cseq_header()?.seq()?);
                                }
                                return Ok(Some(resp));
                            }
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ));
                            break;
                        }
                        if let Some(cred) = &self.credential {
                            let new_seq = match method {
                                crate::sip::Method::Cancel => self.get_local_seq(),
                                _ => self.increment_local_seq(),
                            };
                            tx = handle_client_authenticate(new_seq, &tx, resp, cred).await?;
                            tx.defer_success_ack =
                                options.as_ref().is_some_and(|o| o.answer_handler.is_some());
                            tx.force_success_ack = options.is_some() && !tx.defer_success_ack;
                            self.bind_persistence(&tx);
                            self.reserve_invite(&tx)?;
                            tx.send().await?;
                            cancel_watch = options.as_ref().map(|o| {
                                super::reinvite::RequestCancellation::new(
                                    &tx,
                                    Some(o.cancellation.clone()),
                                )
                            });
                            continue;
                        } else {
                            debug!(
                                id = self.id.lock().to_string(),
                                "received 407 response without auth option"
                            );
                            // Return the final challenge to the application;
                            // the established dialog remains available for
                            // another operation or normal call teardown.
                            if self.is_confirmed() {
                                if method != Method::PRack {
                                    self.clear_remote_reliable(tx.original.cseq_header()?.seq()?);
                                }
                                return Ok(Some(resp));
                            }
                            self.transition(DialogState::Terminated(
                                id,
                                TerminatedReason::ProxyAuthRequired,
                            ));
                            continue;
                        }
                    }

                    let timer = self.session_timer.lock().clone();
                    if let Some(timer) = timer {
                        if !options
                            .as_ref()
                            .is_some_and(|o| o.cancellation.is_cancelled())
                        {
                            if let Some(next) = timer.retry(self, &tx, &resp, &mut timer_retries)? {
                                tx = next;
                                self.reserve_invite(&tx)?;
                                auth = AuthRetry::new();
                                tx.send().await?;
                                cancel_watch = options.as_ref().map(|o| {
                                    super::reinvite::RequestCancellation::new(
                                        &tx,
                                        Some(o.cancellation.clone()),
                                    )
                                });
                                continue;
                            }
                        }
                    }
                    debug!(
                        id = self.id.lock().to_string(),
                        method = %method,
                        "dialog do_request done: {:?}", status
                    );
                    if Self::is_target_refresh(&method)
                        && status.kind() == StatusCodeKind::Successful
                    {
                        self.refresh_target_from_response(&resp)?;
                    }
                    let reliable_sdp = method == Method::Invite
                        && self.has_reliable_sdp(tx.original.cseq_header()?.seq()?);
                    if method == Method::Invite {
                        self.clear_remote_reliable(tx.original.cseq_header()?.seq()?);
                    }
                    if let Some(options) = &options {
                        if status.kind() == StatusCodeKind::Successful {
                            let gate = options.answer_handler.as_ref().map(|_| {
                                let gate = InviteAck::new();
                                self.reinvite_ack.lock().replace(gate.clone());
                                super::reinvite::AckGuard(gate)
                            });
                            let answer = if let Some(handler) = &options.answer_handler {
                                if reliable_sdp {
                                    // The offer was answered in PRACK. The final
                                    // response repeats it; ACK must not negotiate again.
                                    tx.last_ack =
                                        Some(self.endpoint_inner.make_ack(&tx.original, &resp)?);
                                    tx.send_ack(tx.connection.clone()).await
                                } else {
                                    self.answer_reinvite(&mut tx, &resp, handler).await
                                }
                            } else {
                                Ok(())
                            };
                            // Keep the exact ACK (including SDP) until Timer M,
                            // including a rejecting answer followed by BYE.
                            crate::platform::spawn(
                                async move { while tx.receive().await.is_some() {} },
                            );
                            if let Err(error) = answer {
                                if !self.is_terminated() {
                                    let bye = self.make_request(
                                        Method::Bye,
                                        None,
                                        None,
                                        None,
                                        None,
                                        None,
                                    );
                                    self.transition(DialogState::Terminated(
                                        self.id.lock().clone(),
                                        TerminatedReason::UacOther(StatusCode::NotAcceptableHere),
                                    ));
                                    if let Some(gate) = &gate {
                                        gate.0.finish();
                                    }
                                    if let Ok(bye) = bye {
                                        self.do_request(bye).await.ok();
                                    }
                                } else if let Some(gate) = &gate {
                                    gate.0.finish();
                                }
                                return Err(error);
                            }
                            if let Some(gate) = &gate {
                                gate.0.finish();
                            }
                        }
                    }
                    // A malformed timer agreement cannot skip the successful
                    // INVITE's ACK, including an offer answered in that ACK.
                    if let Err(error) = timer_result {
                        super::invite_dialog::InviteDialog::from_inner(self.clone())
                            .bye()
                            .await
                            .ok();
                        return Err(error);
                    }
                    return Ok(Some(resp));
                }
                _ => break,
            }
        }
        tx.check_persistence()?;
        Ok(None)
    }

    pub(super) fn do_request(
        self: &Arc<Self>,
        request: Request,
    ) -> futures::future::BoxFuture<'_, Result<Option<Response>>> {
        self.send_dialog_request(request, None).boxed()
    }

    pub(super) async fn do_reinvite(
        self: &Arc<Self>,
        request: Request,
        options: super::reinvite::ReinviteOptions,
    ) -> Result<Option<Response>> {
        self.send_dialog_request(request, Some(options))
            .boxed()
            .await
    }

    pub(super) fn reserve_invite(&self, tx: &Transaction) -> Result<()> {
        tx.reserve_invite(&self.invite_usage).map_err(|_| {
            crate::Error::DialogError(
                "an INVITE transaction is already in progress".into(),
                self.id.lock().clone(),
                StatusCode::RequestPending,
            )
        })
    }

    /// Send the BYE that ends this dialog. RFC 3261 §15.1.1: the session ends
    /// once the BYE is handed to its transaction, and a 481, a 408 or no
    /// response ends the dialog. So whatever the transaction returns, the
    /// dialog is `Terminated(reason)`; a failure is still returned.
    pub(super) async fn send_bye(
        self: &Arc<Self>,
        request: Request,
        reason: TerminatedReason,
    ) -> Result<()> {
        {
            let state = self.state.lock();
            if state.is_terminated() {
                return Ok(());
            }
            self.record_local_termination();
        }
        self.checkpoint(
            super::persistence::DialogCheckpointReason::LocalTerminationRequested,
            None,
        )
        .await?;
        let initial_ack = self.initial_ack.lock().clone();
        let reinvite_ack = self.reinvite_ack.lock().clone();
        for ack in [initial_ack, reinvite_ack].into_iter().flatten() {
            ack.done.cancelled().await;
            // The peer may have ended the dialog while our ACK was blocked.
            if self.is_terminated() {
                return Ok(());
            }
            if !ack.completed.load(Ordering::SeqCst) {
                return Err(crate::Error::Error("INVITE ACK was interrupted".into()));
            }
        }
        let result = self.do_request(request).await;
        let id = self.id.lock().clone();
        self.transition(DialogState::Terminated(id, reason));
        self.checkpoint(super::persistence::DialogCheckpointReason::Terminated, None)
            .await?;
        result.map(|_| ())
    }

    /// End a dialog a forked 2xx established (RFC 3261 §13.2.2.4).
    ///
    /// Every 2xx to the INVITE with a new To tag creates its own dialog; the
    /// UAC keeps a single session (the first 2xx's), so the transaction has
    /// already ACKed the forked 2xx and this sends the BYE that terminates
    /// the extra branch. The BYE is built from that response's own remote
    /// target (Contact) and route set (Record-Route); the confirmed dialog's
    /// state is not touched and no dialog is registered for the branch.
    pub(super) async fn bye_forked_branch(self: &Arc<Self>, resp: &Response) -> Result<()> {
        let contact_uri = resp
            .typed_contact_headers()?
            .first()
            .map(|c| c.uri.clone())
            .ok_or_else(|| crate::Error::Error("missing Contact header".to_string()))?;

        // §12.2.1.1: the forked dialog's route set is the 2xx's Record-Route.
        let mut routes: Vec<Route> = resp
            .record_route_headers()
            .into_iter()
            .flat_map(|rr| split_rr_values(rr.value()))
            .map(Route::from)
            .collect();
        routes.reverse();

        // To carries the forked branch's tag, From keeps ours.
        let to = resp.to_header()?.clone();
        let id = self.id.lock().clone();
        let via = self
            .endpoint_inner
            .get_via(self.via_addr_for_send_transport(), None)?;
        let cseq = CSeq {
            seq: self.increment_local_seq(),
            method: Method::Bye,
        };

        let mut headers: Vec<Header> = vec![
            Header::Via(via.into()),
            Header::CallId(id.call_id.clone().into()),
            Header::From(self.from.clone().to_string().into()),
            Header::To(to),
            Header::CSeq(cseq.into()),
            Header::UserAgent(self.endpoint_inner.user_agent.clone().into()),
        ];
        if let Some(uri) = self.local_contact.as_ref() {
            headers.push(Contact::from(uri.clone()).into());
        }
        headers.extend(routes.into_iter().map(Header::Route));
        headers.push(Header::MaxForwards(70.into()));

        debug!(id = %id, uri = %contact_uri, "sending BYE to a forked dialog");
        self.do_request(crate::sip::Request {
            method: Method::Bye,
            uri: contact_uri,
            headers: headers.into(),
            body: Vec::new(),
            version: crate::sip::Version::V2,
        })
        .await?;
        Ok(())
    }

    /// RFC 3261 §13.3.1.4: the server transaction of an INVITE or re-INVITE
    /// retransmitted our 2xx (`answered_2xx`) for 64*T1 and ended without an
    /// ACK. The dialog is terminated with [`TerminatedReason::Timeout`] and the
    /// session is ended with a BYE.
    pub(super) async fn end_session_without_ack(
        self: &Arc<Self>,
        tx: &Transaction,
        answered_2xx: bool,
    ) {
        if !answered_2xx
            || tx.state != crate::transaction::TransactionState::Terminated
            || self.is_terminated()
        {
            return;
        }
        let id = self.id.lock().clone();
        warn!(%id, "no ACK for the 2xx within 64*T1, ending the session");
        let bye = self.make_request(Method::Bye, None, None, None, None, None);
        self.transition(DialogState::Terminated(
            id.clone(),
            TerminatedReason::Timeout,
        ));
        match bye {
            Ok(bye) => {
                if let Err(e) = self.do_request(bye).await {
                    warn!(%id, error = %e, "BYE after missing ACK failed");
                }
            }
            Err(e) => warn!(%id, error = %e, "failed to build BYE after missing ACK"),
        }
    }

    /// Capture a single revision. Mutate dialogs through their methods; direct
    /// writes to DialogInner public fields bypass these synchronization guarantees.
    pub fn snapshot(&self) -> DialogSnapshot {
        let state_guard = self.state.lock();
        self.snapshot_locked(&state_guard)
    }

    pub(crate) fn snapshot_locked(&self, state_guard: &DialogState) -> DialogSnapshot {
        let usage = self.invite_usage.lock();
        let lifecycle = self.lifecycle.lock();
        let id = self.id.lock().clone();

        let state = match state_guard {
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
            runtime: super::snapshot::DialogSnapshotRuntime {
                revision: lifecycle.revision + usage.revision,
                lifecycle: lifecycle.facts.clone(),
                pending: super::snapshot::DialogPendingState {
                    local_invite: usage.client_pending,
                    remote_invite: usage.server_pending,
                    remote_invite_awaiting_ack: usage.server_waiting_ack != 0,
                    initial_ack: lifecycle.pending_initial_ack,
                    negotiations: lifecycle.negotiations,
                    remote_termination: lifecycle.pending_remote_bye
                        && !state_guard.is_terminated(),
                    local_termination: lifecycle.emitted & 2 != 0 && !state_guard.is_terminated(),
                },
            },
            state,

            role: self.role,
            id: id.clone(),

            from: self.from.clone(),
            to: self.to.lock().clone(),

            local_cseq: self.local_seq.load(Ordering::Relaxed),
            remote_cseq: self.remote_seq.load(Ordering::Relaxed),

            local_contact: self.local_contact.clone(),
            remote_uri: self.remote_uri.lock().clone(),
            remote_contact: self.remote_contact.lock().clone(),

            route_set: self.route_set.lock().clone(),
            supports_100rel: self.supports_100rel,
            session_id: self.session_id.lock().clone(),
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

        if !snapshot.runtime.pending.is_empty() {
            return Err(crate::Error::Error("dialog snapshot contains unfinished signaling; application recovery policy is required".into()));
        }

        // Ensure To has tag
        let mut to = snapshot.to.clone();
        let to_tag = match snapshot.role {
            TransactionRole::Client => snapshot.id.remote_tag.clone(),
            TransactionRole::Server => snapshot.id.local_tag.clone(),
        };
        if !to_tag.is_empty()
            && !to
                .params
                .iter()
                .any(|p| matches!(p, crate::sip::Param::Tag(_)))
        {
            to.params.push(crate::sip::Param::Tag(to_tag.into()));
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

        let role = snapshot.role;
        let lifecycle = super::lifecycle::LifecycleState::restored(&snapshot.runtime)?;

        let initial_request = Mutex::new(Self::build_restored_initial_request(
            role,
            &snapshot.id,
            &from,
            &to,
            &snapshot.remote_uri,
            snapshot.local_cseq,
            snapshot.local_contact.as_ref(),
            endpoint_inner.user_agent.as_str(),
            snapshot.session_id.as_ref(),
        ));

        Ok(Some(Self {
            invite_usage: Arc::new(Mutex::new(InviteUsage::default())),
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
            remote_target_cseq: Mutex::new(Some(snapshot.remote_cseq)),
            remote_contact: Mutex::new(snapshot.remote_contact),

            from,
            to: Mutex::new(to),

            credential: None,
            route_set: Mutex::new(snapshot.route_set),

            endpoint_inner,
            state_sender,
            persistence: Mutex::new(None),
            persistence_owner: Mutex::new(alloc::sync::Weak::new()),
            lifecycle: Mutex::new(lifecycle),
            tu_sender,

            initial_request,
            session_id: Mutex::new(snapshot.session_id),
            supports_100rel: snapshot.supports_100rel,
            remote_reliable: Mutex::new(Vec::new()),
            reliable_clients: Mutex::new(BTreeMap::new()),
            reliable_config: Mutex::new(None),
            session_timer: Mutex::new(None),
            reliable_servers: Mutex::new(BTreeMap::new()),
            remote_ack: Mutex::new(None),
            server_connection: Mutex::new(None),
            dialback_target: Mutex::new(None),
            cancel_requested: AtomicBool::new(false),
            cancel_deferred: AtomicBool::new(false),
            initial_ack: Mutex::new(None),
            reinvite_ack: Mutex::new(None),
        }))
    }
    fn build_restored_initial_request(
        role: TransactionRole,
        id: &DialogId,
        from: &crate::sip::typed::From,
        to: &crate::sip::typed::To,
        remote_uri: &crate::sip::Uri,
        local_seq: u32,
        local_contact: Option<&crate::sip::Uri>,
        user_agent: &str,
        session_id: Option<&SessionIdState>,
    ) -> Request {
        use crate::sip::Version;

        let mut headers: Vec<Header> = Vec::new();

        headers.push(Header::CallId(id.call_id.clone().into()));

        let from_str = from.clone().to_string();
        let to_str = to.clone().to_string();
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

        if let Some(sid) = session_id {
            let header = match role {
                // Client: the synthetic initial request is our outgoing INVITE.
                TransactionRole::Client => {
                    build_session_id_header(&sid.local, sid.remote.as_deref())
                }
                // Server: it mirrors the incoming INVITE (peer's uuid first).
                TransactionRole::Server => build_session_id_header(
                    sid.remote
                        .as_deref()
                        .unwrap_or(crate::sip::headers::SessionId::NIL),
                    Some(&sid.local),
                ),
            };
            if let Some(h) = header {
                headers.push(h);
            }
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
    pub(crate) fn complete_initial_ack(&self) {
        let _snapshot_gate = self.state.lock();
        let mut lifecycle = self.lifecycle.lock();
        if lifecycle.pending_initial_ack {
            lifecycle.pending_initial_ack = false;
            lifecycle.revision += 1;
        }
    }

    pub(crate) fn begin_negotiation(&self) {
        let _snapshot_gate = self.state.lock();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.negotiations += 1;
        lifecycle.revision += 1;
    }

    pub(crate) fn finish_negotiation(&self) {
        let _snapshot_gate = self.state.lock();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.negotiations -= 1;
        lifecycle.revision += 1;
    }

    pub(crate) fn record_initial_acceptance(
        &self,
        response: &Response,
        time: super::lifecycle::LifecycleTime,
    ) {
        let _state = self.state.lock();
        // The send may complete after a concurrent BYE. Report the successful
        // send as a fact even then, without resurrecting the dialog state.
        self.lifecycle.lock().emit(
            self.id.lock().clone(),
            self.role,
            time,
            super::lifecycle::DialogLifecycleKind::InviteAccepted {
                status: response.status_code.clone(),
            },
        );
    }

    // Called under the state lock by admitted local teardown paths.
    pub(crate) fn record_local_termination(&self) {
        self.lifecycle.lock().emit(
            self.id.lock().clone(),
            self.role,
            super::lifecycle::LifecycleTime::now(),
            super::lifecycle::DialogLifecycleKind::LocalTerminationRequested,
        );
    }

    pub(crate) fn terminate_remote_bye(
        &self,
        reason: TerminatedReason,
        time: super::lifecycle::LifecycleTime,
    ) {
        let id = self.id.lock().clone();
        let mut state = self.state.lock();
        if !state.is_terminated() {
            self.lifecycle.lock().emit(
                id.clone(),
                self.role,
                time,
                super::lifecycle::DialogLifecycleKind::RemoteByeReceived,
            );
            self.transition_locked(&mut state, DialogState::Terminated(id, reason));
        }
    }

    pub(super) fn transition(&self, state: DialogState) {
        // Decide under the state lock and notify only transitions that are
        // applied, while still holding it, so notifications follow the order
        // in which the state changed.
        self.transition_locked(&mut self.state.lock(), state);
    }

    /// `handle()` announcing an initial INVITE: re-enters `Calling` only while
    /// the dialog is still `Calling`. Checked under the state lock `accept()`,
    /// `ringing()` and `reject()` take, so one that ran first (`WaitAck`,
    /// `Early`, `Terminated`) is never undone. Returns whether it applied.
    pub(super) fn transition_if_calling(&self) -> bool {
        let id = self.id.lock().clone();
        let mut state = self.state.lock();
        if !matches!(&*state, DialogState::Calling(_)) {
            return false;
        }
        self.transition_locked(&mut state, DialogState::Calling(id));
        true
    }

    /// The 2xx to the INVITE: `confirmed`, or `Terminated(UacCancel)` once
    /// `cancel()` was called. Decided under the state lock `cancel()` takes,
    /// so a racing `cancel()` is either seen here or sees `Confirmed`.
    /// Returns whether the INVITE was cancelled.
    pub(super) fn confirm_unless_cancelled(
        &self,
        confirmed: DialogState,
        received_at: super::lifecycle::LifecycleTime,
        register: impl FnOnce(),
    ) -> bool {
        let id = self.id.lock().clone();
        let mut state = self.state.lock();
        if self.cancel_requested.load(Ordering::SeqCst) {
            let cancelled = DialogState::Terminated(id, TerminatedReason::UacCancel);
            self.transition_locked(&mut state, cancelled);
            return true;
        }
        if state.is_terminated() {
            return false;
        }
        // Publish the full dialog key before notifying the application. A
        // concurrent handler cannot inspect the state until this lock releases.
        register();
        {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.pending_initial_ack = true;
            lifecycle.revision += 1;
        }
        if let DialogState::Confirmed(id, response) = &confirmed {
            self.lifecycle.lock().emit(
                id.clone(),
                self.role,
                received_at,
                super::lifecycle::DialogLifecycleKind::InviteAccepted {
                    status: response.status_code.clone(),
                },
            );
        }
        self.transition_locked(&mut state, confirmed);
        false
    }

    fn transition_locked(&self, old_state: &mut DialogState, state: DialogState) {
        // Late updates after termination (e.g. CANCEL's 200 arriving after
        // the INVITE's 487, or a second Terminated from a racing teardown)
        // are neither applied nor broadcast: observers already saw Terminated.
        if let DialogState::Terminated(id, _) = &*old_state {
            debug!(id = %id, target = %state, "dialog already terminated, ignoring late transition");
            return;
        }
        // In-dialog request events do not change the established lifecycle state.
        match state {
            DialogState::Updated(_, _, _)
            | DialogState::Notify(_, _, _)
            | DialogState::Info(_, _, _)
            | DialogState::Options(_, _, _)
            | DialogState::Refer(_, _, _) => {
                // Try to send state update, but don't fail if channel is closed
                self.state_sender.send(state).ok();
                return;
            }
            _ => {}
        }
        if let (DialogState::Confirmed(_, _), DialogState::WaitAck(_, _)) = (&*old_state, &state) {
            warn!(target = %state, "dialog already confirmed, ignoring transition");
            return;
        }
        debug!(from = %old_state, to = %state, "transitioning state");
        if let DialogState::Terminated(id, reason) = &state {
            self.lifecycle.lock().emit(
                id.clone(),
                self.role,
                super::lifecycle::LifecycleTime::now(),
                super::lifecycle::DialogLifecycleKind::DialogTerminated {
                    reason: reason.clone(),
                },
            );
        }
        self.lifecycle.lock().revision += 1;
        if matches!(state, DialogState::Terminated(..)) {
            if let Some(timer) = self.session_timer.lock().as_ref() {
                timer.stop();
            }
        }
        *old_state = state.clone();
        if state.is_terminated() {
            self.enqueue_checkpoint_locked(
                old_state,
                super::persistence::DialogCheckpointReason::Terminated,
                None,
            );
        }
        // Try to send state update, but don't fail if channel is closed
        self.state_sender.send(state).ok();
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    async fn process_reliable_invite_handle(
        &self,
        tx: &mut Transaction,
        mut rx: TransactionCommandReceiver,
    ) -> Result<()> {
        use crate::platform::{select3, Which3};
        let mut deadline =
            core::pin::pin!(crate::platform::sleep(self.endpoint_inner.option.t1x64));
        let mut commands_closed = false;
        loop {
            let selected = {
                let command = if commands_closed {
                    futures::future::pending().boxed()
                } else {
                    rx.recv().boxed()
                };
                let event = core::pin::pin!(tx.tu_receiver.recv());
                select3(command, event, &mut deadline).await
            };
            match selected {
                Which3::A(Some(TransactionCommand::Respond {
                    status,
                    headers,
                    body,
                })) => {
                    let response = self.make_response(&tx.original, status, headers, body);
                    tx.respond(response).await?;
                }
                Which3::A(None) => {
                    commands_closed = true;
                    // A final response may be waiting for SDP's PRACK.
                    if tx
                        .reliable_provisional
                        .lock()
                        .as_ref()
                        .is_none_or(|s| !s.pending())
                    {
                        return tx.reply(StatusCode::NotImplemented).await;
                    }
                }
                Which3::B(Some(event)) => match tx.dispatch_event(event).await {
                    Some(Some(SipMessage::Request(req))) if req.method == Method::Cancel => {
                        return tx.reply(StatusCode::RequestTerminated).await;
                    }
                    Some(None) => return Ok(()),
                    _ => {}
                },
                Which3::B(None) => return Ok(()),
                Which3::C(_) => return tx.reply(StatusCode::ServerTimeOut).await,
            }
            if tx
                .last_response
                .as_ref()
                .is_some_and(|r| r.status_code.kind() != StatusCodeKind::Provisional)
            {
                return Ok(());
            }
        }
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    pub async fn process_transaction_handle(
        &self,
        tx: &mut Transaction,
        rx: TransactionCommandReceiver,
    ) -> Result<()> {
        let negotiation = tx.original.method == Method::Update;
        if negotiation {
            self.begin_negotiation();
        }
        let result = self.process_transaction_handle_inner(tx, rx).await;
        if negotiation {
            self.finish_negotiation();
            self.checkpoint(
                super::persistence::DialogCheckpointReason::SignalingCompleted,
                None,
            )
            .await?;
        }
        result
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    async fn process_transaction_handle_inner(
        &self,
        tx: &mut Transaction,
        mut rx: TransactionCommandReceiver,
    ) -> Result<()> {
        self.bind_persistence(tx);
        let target = if Self::is_target_refresh(&tx.original.method) {
            match Self::parse_target_refresh_contact(&tx.original) {
                Ok(target) => target,
                Err(_) => return tx.reply(StatusCode::BadRequest).await,
            }
        } else {
            None
        };
        let cseq = tx.original.cseq_header()?.seq()?;
        if tx.reliable_provisional.lock().is_some() {
            return self.process_reliable_invite_handle(tx, rx).await;
        }
        let timeout_duration = self.endpoint_inner.option.t1x64;
        let result = crate::platform::timeout(timeout_duration, async {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    TransactionCommand::Respond {
                        status,
                        headers,
                        body,
                    } => {
                        let is_final = status.kind() != StatusCodeKind::Provisional;
                        let response = self.make_response(&tx.original, status, headers, body);
                        let accepts_refresh =
                            Self::accepts_target_refresh(&tx.original.method, &response);
                        tx.respond(response).await?;

                        // Commit only once the accepting response was sent.
                        // An error (including a later 488 after reliable 183)
                        // never rolls back an already accepted refresh.
                        // Non-INVITE respond() can terminate the transaction
                        // and move last_response into the finished cache.
                        if let Some(target) = &target {
                            if accepts_refresh {
                                self.accept_target_refresh(cseq, target);
                            }
                        }

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
                let id = self.id.lock().to_string();
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

impl core::fmt::Display for DialogState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            Dialog::Invite(d) => d.inner.id.lock().clone(),
            Dialog::ServerSubscription(d) => d.inner.id.lock().clone(),
            Dialog::ClientSubscription(d) => d.inner.id.lock().clone(),
            Dialog::ServerPublication(d) => d.inner.id.lock().clone(),
            Dialog::ClientPublication(d) => d.inner.id.lock().clone(),
        }
    }

    pub fn from(&self) -> &crate::sip::typed::From {
        match self {
            Dialog::Invite(d) => &d.inner.from,
            Dialog::ServerSubscription(d) => &d.inner.from,
            Dialog::ClientSubscription(d) => &d.inner.from,
            Dialog::ServerPublication(d) => &d.inner.from,
            Dialog::ClientPublication(d) => &d.inner.from,
        }
    }

    pub fn to(&self) -> crate::sip::typed::To {
        match self {
            Dialog::Invite(d) => d.inner.to.lock().clone(),
            Dialog::ServerSubscription(d) => d.inner.to.lock().clone(),
            Dialog::ClientSubscription(d) => d.inner.to.lock().clone(),
            Dialog::ServerPublication(d) => d.inner.to.lock().clone(),
            Dialog::ClientPublication(d) => d.inner.to.lock().clone(),
        }
    }

    pub fn from_inner(role: TransactionRole, inner: DialogInnerRef) -> Self {
        let _ = role;
        Dialog::Invite(InviteDialog::from_inner(inner))
    }
    pub fn remote_contact(&self) -> Option<crate::sip::Uri> {
        match self {
            Dialog::Invite(d) => d.inner.remote_contact.lock().as_ref().and_then(|c| {
                crate::sip::typed::Contact::parse(c.value())
                    .ok()
                    .map(|c| c.uri)
            }),
            Dialog::ServerSubscription(d) => d.inner.remote_contact.lock().as_ref().and_then(|c| {
                crate::sip::typed::Contact::parse(c.value())
                    .ok()
                    .map(|c| c.uri)
            }),
            Dialog::ClientSubscription(d) => d.inner.remote_contact.lock().as_ref().and_then(|c| {
                crate::sip::typed::Contact::parse(c.value())
                    .ok()
                    .map(|c| c.uri)
            }),
            Dialog::ServerPublication(d) => d.inner.remote_contact.lock().as_ref().and_then(|c| {
                crate::sip::typed::Contact::parse(c.value())
                    .ok()
                    .map(|c| c.uri)
            }),
            Dialog::ClientPublication(d) => d.inner.remote_contact.lock().as_ref().and_then(|c| {
                crate::sip::typed::Contact::parse(c.value())
                    .ok()
                    .map(|c| c.uri)
            }),
        }
    }

    pub async fn handle(&mut self, tx: &mut Transaction) -> Result<()> {
        match self {
            Dialog::Invite(d) => d.handle(tx).await,
            Dialog::ServerSubscription(d) => d.handle(tx).await,
            Dialog::ClientSubscription(d) => d.handle(tx).await,
            Dialog::ServerPublication(d) => d.handle(tx).await,
            Dialog::ClientPublication(d) => d.handle(tx).await,
        }
    }
    pub fn on_remove(&self) {
        match self {
            Dialog::Invite(d) => {
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
        self.hangup_with_headers(None).await
    }

    pub async fn hangup_with_headers(
        &self,
        headers: Option<Vec<crate::sip::Header>>,
    ) -> Result<()> {
        match self {
            Dialog::Invite(d) => d.hangup_with_headers(headers).await,
            Dialog::ServerSubscription(d) => d.unsubscribe_with_headers(headers).await,
            Dialog::ClientSubscription(d) => d.unsubscribe_with_headers(headers).await,
            Dialog::ServerPublication(d) => d.close_with_headers(headers).await,
            Dialog::ClientPublication(d) => d.close_with_headers(headers).await,
        }
    }

    pub fn can_cancel(&self) -> bool {
        match self {
            Dialog::Invite(d) => d.inner.can_cancel(),
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
        uri: crate::sip::Uri,
        contact: Option<crate::sip::headers::untyped::Contact>,
    ) {
        match self {
            Dialog::Invite(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ServerSubscription(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ClientSubscription(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ServerPublication(d) => d.inner.set_remote_target(uri, contact),
            Dialog::ClientPublication(d) => d.inner.set_remote_target(uri, contact),
        }
    }

    pub async fn request(
        &self,
        method: crate::sip::Method,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        match self {
            Dialog::Invite(d) => d.request(method, headers, body).await,
            Dialog::ServerSubscription(d) => d.request(method, headers, body).await,
            Dialog::ClientSubscription(d) => d.request(method, headers, body).await,
            Dialog::ServerPublication(d) => d.request(method, headers, body).await,
            Dialog::ClientPublication(d) => d.request(method, headers, body).await,
        }
    }

    pub async fn refer(
        &self,
        refer_to: impl Into<crate::sip::ReferTo>,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        match self {
            Dialog::Invite(d) => d.refer(refer_to, headers, body).await,
            Dialog::ServerSubscription(d) => d.refer(refer_to, headers, body).await,
            Dialog::ClientSubscription(d) => d.refer(refer_to, headers, body).await,
            Dialog::ServerPublication(d) => d.refer(refer_to, headers, body).await,
            Dialog::ClientPublication(d) => d.refer(refer_to, headers, body).await,
        }
    }

    pub async fn message(
        &self,
        headers: Option<Vec<crate::sip::Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<crate::sip::Response>> {
        match self {
            Dialog::Invite(d) => d.message(headers, body).await,
            Dialog::ServerSubscription(d) => d.message(headers, body).await,
            Dialog::ClientSubscription(d) => d.message(headers, body).await,
            Dialog::ServerPublication(d) => d.message(headers, body).await,
            Dialog::ClientPublication(d) => d.message(headers, body).await,
        }
    }
}

fn is_system_header(h: &crate::sip::Header) -> bool {
    use crate::sip::Header::*;
    matches!(
        h,
        Via(_)
            | CallId(_)
            | From(_)
            | To(_)
            | CSeq(_)
            | MaxForwards(_)
            | ContentLength(_)
            | Route(_)
    )
}

/// Generate a Session-ID UUID in the RFC 7989 wire format: 32 lowercase hex
/// chars (no dashes), derived from a version-4 UUID.
pub(crate) fn make_dialog_session_uuid() -> String {
    make_uuid_v4().replace('-', "")
}

/// Build a `Session-ID: <local>[;remote=<remote|nil>]` header.
/// Per RFC 7989 §5 the remote parameter MUST be present (nil UUID when the
/// peer's UUID is unknown), except when interworking with RFC 7329 peers.
pub(crate) fn build_session_id_header(local: &str, remote: Option<&str>) -> Option<Header> {
    let header = match remote {
        Some(remote) => crate::sip::headers::SessionId::from_pair(local, remote),
        None => crate::sip::headers::SessionId::from_local(local),
    }
    .ok()?;
    Some(Header::SessionId(header))
}
