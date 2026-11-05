//! RFC 3262 reliable provisional responses and application-owned SDP negotiation.
//!
//! Enable this on a `DialogLayer` before creating calls. The handler supplies
//! SDP answers (and, optionally, a new offer in PRACK); the stack owns RSeq,
//! RAck, transactions, retransmissions and final-response ordering.
use super::{
    dialog::{DialogInner, DialogState, TerminatedReason},
    DialogId,
};
use crate::platform::{self, sync::Mutex, CancellationToken};
use crate::prelude::*;
use crate::sip::{
    HasHeaders, Header, HeadersExt, Method, Request, Response, StatusCode, StatusCodeKind,
};
use crate::transaction::{
    key::TransactionRole,
    transaction::{Transaction, TransactionEvent, TransactionEventSender},
};
use crate::{Error, Result};
use async_trait::async_trait;

/// Meaning of the SDP carried by the message delivered to the handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdpKind {
    None,
    Offer,
    Answer,
    /// A subsequent SDP body for this INVITE; do not apply it as offer/answer.
    Ignored,
}

/// A body to put in PRACK or its 200 response. SDP is not synthesized by SIP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrackBody {
    pub content_type: String,
    pub body: Vec<u8>,
}
impl PrackBody {
    pub fn sdp(body: impl Into<Vec<u8>>) -> Self {
        Self {
            content_type: "application/sdp".into(),
            body: body.into(),
        }
    }
    pub(crate) fn is_sdp(&self) -> bool {
        !self.body.is_empty()
            && self
                .content_type
                .split(';')
                .next()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/sdp"))
    }
    fn apply(self, request: &mut Request) {
        request
            .headers
            .unique_push(Header::ContentType(self.content_type.into()));
        request
            .headers
            .unique_push(Header::ContentLength((self.body.len() as u32).into()));
        request.body = self.body;
    }
}

#[derive(Clone, Debug)]
pub struct ReliableResponse {
    pub dialog_id: DialogId,
    pub invite: Request,
    pub response: Response,
    pub sdp_kind: SdpKind,
}
#[derive(Clone, Debug)]
pub struct IncomingPrack {
    pub dialog_id: DialogId,
    pub invite: Request,
    pub response: Response,
    pub prack: Request,
    pub sdp_kind: SdpKind,
}

/// Callbacks may run concurrently for different dialogs. Do not wait for an
/// INVITE final response here: an SDP answer can be required before that final.
///
/// For an SDP offer return an SDP answer (use rejected media ports to decline
/// an offer). For an answer, apply it and normally return `None`; a UAC may
/// return a new SDP offer when acknowledging the first SDP answer. RFC 3262 §5.
#[async_trait]
pub trait PrackHandler: Send + Sync {
    async fn on_reliable_response(&self, event: ReliableResponse) -> Result<Option<PrackBody>>;
    async fn on_prack(&self, event: IncomingPrack) -> Result<Option<PrackBody>>;
    /// Includes the SDP answer to an offer sent in PRACK. A missing response
    /// means transaction timeout. The application decides whether to end a call.
    async fn on_prack_result(&self, _request: Request, _response: Option<Response>) {}
    /// Transport, callback and protocol errors, including UAS 64*T1 expiry.
    async fn on_error(&self, _dialog_id: DialogId, _message: String) {}
}

/// Explicitly enabled full 100rel support. A media handler is mandatory so
/// offerless INVITE and SDP in PRACK can be handled by the application.
#[derive(Clone)]
pub struct ReliableProvisionalConfig {
    pub handler: Arc<dyn PrackHandler>,
    /// Add Require: 100rel to outgoing INVITEs, in addition to Supported.
    pub require: bool,
}
impl ReliableProvisionalConfig {
    pub fn new(handler: Arc<dyn PrackHandler>) -> Self {
        Self {
            handler,
            require: false,
        }
    }
}
impl core::fmt::Debug for ReliableProvisionalConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReliableProvisionalConfig")
            .field("require", &self.require)
            .finish_non_exhaustive()
    }
}

pub(crate) fn has_sdp(message: &impl HeadersExt, body: &[u8]) -> bool {
    !body.is_empty()
        && message.header_value("Content-Type").is_some_and(|s| {
            s.split(';')
                .next()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/sdp"))
        })
}
pub(crate) fn add_option(message: &mut impl HasHeaders, name: &str, token: &str) {
    let exists = message
        .headers()
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case(name))
        .any(|h| {
            h.value()
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case(token))
        });
    if !exists {
        message.headers_mut().push(match name {
            "Require" => Header::Require(token.into()),
            _ => Header::Supported(token.into()),
        });
    }
}
fn error(message: &str) -> Error {
    Error::Error(message.into())
}

struct PrackJob {
    event: ReliableResponse,
    request: Request,
    destination: Option<crate::transport::SipAddr>,
}

pub(super) struct ReliableClient {
    sender: platform::BoundedSender<PrackJob>,
    last_rseq: u32,
    routes: Vec<crate::sip::Route>,
    target: crate::sip::Uri,
    first_sdp: Option<Vec<u8>>,
}

impl DialogInner {
    pub(super) fn has_reliable_sdp(&self, cseq: u32) -> bool {
        let id = self.id.lock().clone();
        self.reliable_clients
            .lock()
            .get(&(id, cseq))
            .is_some_and(|c| c.first_sdp.is_some())
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    pub(super) fn start_reliable_prack(
        self: &Arc<Self>,
        response: &Response,
        invite: &Request,
        config: ReliableProvisionalConfig,
    ) -> Result<bool> {
        use crate::sip::{Param, ToTypedHeader};
        if invite.method != Method::Invite
            || response.cseq_header()?.method()? != Method::Invite
            || response.cseq_header()?.seq()? != invite.cseq_header()?.seq()?
            || response.call_id_header()? != invite.call_id_header()?
            || response.from_header()?.tag()? != invite.from_header()?.tag()?
        {
            return Ok(false);
        }
        let id = DialogId::try_from((response, TransactionRole::Client))?;
        if id.remote_tag.is_empty() {
            return Ok(false);
        }
        let in_dialog = invite.to_header()?.tag()?;
        if in_dialog
            .as_ref()
            .is_some_and(|t| t.value() != id.remote_tag)
        {
            return Ok(false);
        }
        let Some(rseq) = response.rseq_value() else {
            return Ok(false);
        };
        let cseq = invite.cseq_header()?.seq()?;
        let (kind, target, routes, sender, receiver) = {
            let mut clients = self.reliable_clients.lock();
            let key = (id.clone(), cseq);
            if let Some(client) = clients.get(&key) {
                if client.last_rseq.checked_add(1) != Some(rseq) {
                    return Ok(false);
                }
            } else if rseq > i32::MAX as u32 {
                return Ok(false);
            }
            // RFC 6141 sections 4.7/4.9: each newly accepted reliable
            // provisional can refresh Contact, including on a re-INVITE.
            // Sequence validation above prevents replaying an old target.
            let target = if let Some(target) = Self::parse_target_refresh_contact(response)? {
                target.uri
            } else if in_dialog.is_some() {
                self.remote_uri.lock().clone()
            } else if let Some(client) = clients.get(&key) {
                client.target.clone()
            } else {
                return Err(error(
                    "dialog-establishing reliable response needs one Contact",
                ));
            };
            let routes = if let Some(client) = clients.get(&key) {
                client.routes.clone()
            } else if in_dialog.is_some() {
                self.route_set.lock().clone()
            } else {
                let mut routes: Vec<crate::sip::Route> = response
                    .record_route_headers()
                    .into_iter()
                    .flat_map(|h| {
                        crate::sip::headers::typed::record_route::split_rr_values(h.value())
                    })
                    .map(crate::sip::Route::from)
                    .collect();
                routes.reverse();
                routes
            };
            let first_sdp = clients.get(&key).and_then(|c| c.first_sdp.clone());
            let sdp = has_sdp(response, &response.body);
            let kind = if sdp {
                if first_sdp.is_some() {
                    // RFC 6337 §3.1: later SDP is not a new offer/answer,
                    // including peers that repeat a different description.
                    SdpKind::Ignored
                } else if has_sdp(invite, &invite.body) {
                    SdpKind::Answer
                } else {
                    SdpKind::Offer
                }
            } else {
                if first_sdp.is_none() && !has_sdp(invite, &invite.body) {
                    return Err(error(
                        "first reliable response to offerless INVITE has no SDP offer",
                    ));
                }
                SdpKind::None
            };
            let (sender, receiver) = match clients.get(&key) {
                Some(client) => (client.sender.clone(), None),
                None => {
                    let (sender, receiver) = platform::mpsc::channel(32);
                    (sender, Some(receiver))
                }
            };
            clients.insert(
                key,
                ReliableClient {
                    sender: sender.clone(),
                    last_rseq: rseq,
                    routes: routes.clone(),
                    target: target.clone(),
                    first_sdp: first_sdp.or_else(|| sdp.then(|| response.body.clone())),
                },
            );
            (kind, target, routes, sender, receiver)
        };
        let mut prack = self.make_request(
            Method::PRack,
            Some(0),
            None,
            None,
            Some(vec![Header::RAck(format!("{rseq} {cseq} INVITE").into())]),
            None,
        )?;
        prack
            .headers
            .unique_push(Header::To(response.to_header()?.clone()));
        prack.uri = target.clone();
        prack.headers.retain(|h| !matches!(h, Header::Route(_)));
        let destination = if let Some(first) = routes.first() {
            let first = first.typed()?;
            let destination = crate::transport::SipAddr::try_from(&first.uri)?;
            if first.uri.params.iter().any(|p| {
                matches!(p, Param::Lr)
                    || matches!(p, Param::Other(n, _) if n.value().eq_ignore_ascii_case("lr"))
            }) {
                prack
                    .headers
                    .extend(routes.iter().cloned().map(Header::Route).collect());
            } else {
                prack.uri = first.uri;
                prack
                    .headers
                    .extend(routes.iter().skip(1).cloned().map(Header::Route).collect());
                prack
                    .headers
                    .push(Header::Route(format!("<{target}>").into()));
            }
            Some(destination)
        } else {
            Some(crate::transport::SipAddr::try_from(&target)?)
        };
        // Keep the first early dialog as the public call's target; fork-specific
        // PRACK requests carry their own target, routes and To-tag above.
        let current = self.id.lock().clone();
        if current.remote_tag.is_empty() || current.remote_tag == id.remote_tag {
            self.update_remote_tag(&id.remote_tag)?;
            if let Some(target) = Self::parse_target_refresh_contact(response)? {
                self.set_remote_target(target.uri, Some(target.contact));
            }
            if in_dialog.is_none() {
                *self.route_set.lock() = routes;
            }
        }
        let event = ReliableResponse {
            dialog_id: id.clone(),
            invite: invite.clone(),
            response: response.clone(),
            sdp_kind: kind,
        };
        sender
            .try_send(PrackJob {
                event,
                request: prack,
                destination,
            })
            .map_err(|_| error("PRACK preparation queue is full or closed"))?;
        if let Some(mut receiver) = receiver {
            let weak = Arc::downgrade(self);
            platform::spawn(async move {
                while let Some(job) = receiver.recv().await {
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    let id = job.event.dialog_id.clone();
                    match inner.prepare_prack_job(job, &config).await {
                        Ok((tx, offered)) => {
                            let config = config.clone();
                            platform::spawn(async move {
                                let request = tx.original.clone();
                                let result = inner.finish_prack_transaction(tx).await;
                                match result {
                                    Ok(response) => {
                                        if offered
                                            && response.as_ref().is_some_and(|r| {
                                                r.status_code.kind() == StatusCodeKind::Successful
                                                    && !has_sdp(r, &r.body)
                                            })
                                        {
                                            config.handler.on_error(id.clone(), "successful PRACK response omitted the SDP answer".into()).await;
                                        }
                                        config.handler.on_prack_result(request, response).await;
                                    }
                                    Err(e) => config.handler.on_error(id, e.to_string()).await,
                                }
                            });
                        }
                        Err(e) => config.handler.on_error(id, e.to_string()).await,
                    }
                }
            });
        }
        Ok(true)
    }
    async fn prepare_prack_job(
        &self,
        job: PrackJob,
        config: &ReliableProvisionalConfig,
    ) -> Result<(Transaction, bool)> {
        let kind = job.event.sdp_kind;
        let body = platform::timeout(
            self.endpoint_inner.option.t1x64,
            config.handler.on_reliable_response(job.event),
        )
        .await
        .map_err(|_| error("reliable response SDP handler timed out"))??;
        if kind == SdpKind::Offer && !body.as_ref().is_some_and(PrackBody::is_sdp) {
            return Err(error(
                "SDP offer in reliable response needs an answer in PRACK",
            ));
        }
        if body.as_ref().is_some_and(PrackBody::is_sdp)
            && !matches!(kind, SdpKind::Offer | SdpKind::Answer)
        {
            return Err(error(
                "SDP offer is only allowed in PRACK acknowledging an SDP answer",
            ));
        }
        let offered = kind == SdpKind::Answer && body.as_ref().is_some_and(PrackBody::is_sdp);
        let mut request = job.request;
        if let Some(body) = body {
            body.apply(&mut request);
        }
        request.headers.unique_push(Header::CSeq(
            format!("{} PRACK", self.increment_local_seq()).into(),
        ));
        let tx = self
            .start_prack_transaction(request, job.destination)
            .await?;
        Ok((tx, offered))
    }
}

struct Outstanding {
    response: Response,
    kind: SdpKind,
    cancel: CancellationToken,
    timer_started: bool,
    processing: bool,
}
struct ServerState {
    next_rseq: u32,
    outstanding: Option<Outstanding>,
    queue: Vec<Response>,
    final_response: Option<Response>,
    final_sent: bool,
    first_answer: Option<Vec<u8>>,
    offer_answer_complete: bool,
}

/// One incoming INVITE transaction; retained by the dialog for late PRACKs.
pub(crate) struct ReliableServer {
    owner: Weak<DialogInner>,
    pub(crate) request: Request,
    sender: TransactionEventSender,
    config: ReliableProvisionalConfig,
    state: Mutex<ServerState>,
}
impl ReliableServer {
    pub(crate) fn new(
        owner: &Arc<DialogInner>,
        request: Request,
        sender: TransactionEventSender,
        config: ReliableProvisionalConfig,
    ) -> Arc<Self> {
        let seed = crate::transaction::make_uuid_v4();
        let next_rseq = (u32::from_str_radix(&seed[..8], 16).unwrap_or(1) & 0x7fff_ffff).max(1);
        Arc::new(Self {
            owner: Arc::downgrade(owner),
            request,
            sender,
            config,
            state: Mutex::new(ServerState {
                next_rseq,
                outstanding: None,
                queue: Vec::new(),
                final_response: None,
                final_sent: false,
                first_answer: None,
                offer_answer_complete: false,
            }),
        })
    }

    /// Called by the owning transaction, never while a network send is in flight.
    pub(crate) fn prepare(&self, mut response: Response) -> Result<Option<Response>> {
        let mut s = self.state.lock();
        if response.status_code == StatusCode::Trying {
            response
                .headers
                .retain(|h| !h.name().eq_ignore_ascii_case("RSeq"));
            if response.header_contains_token("Require", "100rel") {
                return Err(error("100 Trying cannot be reliable"));
            }
            return Ok(Some(response));
        }
        if response.status_code.kind() != StatusCodeKind::Provisional {
            if s.final_sent {
                return Ok(Some(response));
            }
            if response.status_code.kind() == StatusCodeKind::Successful
                && s.outstanding
                    .as_ref()
                    .is_some_and(|o| has_sdp(&o.response, &o.response.body) || o.processing)
            {
                s.final_response = Some(response);
                s.queue.clear();
                return Ok(None);
            }
            s.final_sent = true;
            s.queue.clear();
            s.final_response = None;
            if let Some(o) = &s.outstanding {
                o.cancel.cancel();
            }
            return Ok(Some(response));
        }
        if s.final_sent {
            return Ok(None);
        }
        // Only the stored exact response is a retransmission. Caller-supplied
        // RSeq cannot bypass the sequence/offer-answer machinery.
        if response
            .headers
            .iter()
            .any(|h| h.name().eq_ignore_ascii_case("RSeq"))
        {
            return Ok(s
                .outstanding
                .as_ref()
                .filter(|o| !o.processing && o.response == response)
                .map(|_| response));
        }
        if s.final_response.is_some() {
            return Err(error("final INVITE response already queued"));
        }
        if s.outstanding.is_some() {
            if s.queue.len() >= 32 {
                return Err(error("too many queued reliable responses"));
            }
            s.queue.push(response);
            return Ok(None);
        }
        let sdp = has_sdp(&response, &response.body);
        let kind = if has_sdp(&self.request, &self.request.body) {
            if sdp {
                if let Some(answer) = &s.first_answer {
                    if *answer != response.body {
                        return Err(error("subsequent reliable response changed the SDP answer"));
                    }
                    SdpKind::Ignored
                } else {
                    s.first_answer = Some(response.body.clone());
                    s.offer_answer_complete = true;
                    SdpKind::Answer
                }
            } else {
                SdpKind::None
            }
        } else if !s.offer_answer_complete {
            if !sdp {
                return Err(error(
                    "offerless INVITE requires an SDP offer in the first reliable response",
                ));
            }
            SdpKind::Offer
        } else {
            if sdp {
                return Err(error(
                    "new SDP offer cannot be sent in a subsequent reliable response",
                ));
            }
            SdpKind::None
        };
        let rseq = s.next_rseq;
        if rseq == 0 {
            return Err(error("RSeq space exhausted"));
        }
        s.next_rseq = rseq.checked_add(1).unwrap_or(0);
        add_option(&mut response, "Require", "100rel");
        response
            .headers
            .unique_push(Header::RSeq(rseq.to_string().into()));
        s.outstanding = Some(Outstanding {
            response: response.clone(),
            kind,
            cancel: CancellationToken::new(),
            timer_started: false,
            processing: false,
        });
        Ok(Some(response))
    }

    pub(crate) fn sent(self: &Arc<Self>, response: &Response) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        // Commit a target refresh only after the accepting response reached
        // the transport, including a previously queued 2xx or reliable 1xx.
        if DialogInner::accepts_target_refresh(&self.request.method, response) {
            if let (Ok(Some(target)), Ok(cseq)) = (
                DialogInner::parse_target_refresh_contact(&self.request),
                self.request.cseq_header().and_then(|h| h.seq()),
            ) {
                owner.accept_target_refresh(cseq, &target);
            }
        }
        let final_response = response.status_code.kind() != StatusCodeKind::Provisional;
        if !final_response
            && self.state.lock().outstanding.as_ref().is_some_and(|o| {
                o.timer_started && o.response.rseq_value() == response.rseq_value()
            })
        {
            return;
        }
        if final_response {
            let weak_owner = self.owner.clone();
            let weak_server = Arc::downgrade(self);
            let cseq = self
                .request
                .cseq_header()
                .and_then(|h| h.seq())
                .unwrap_or(0);
            let delay = owner.endpoint_inner.option.t1x64;
            platform::spawn(async move {
                platform::sleep(delay).await;
                if let (Some(owner), Some(server)) = (weak_owner.upgrade(), weak_server.upgrade()) {
                    let mut servers = owner.reliable_servers.lock();
                    if servers.get(&cseq).is_some_and(|s| Arc::ptr_eq(s, &server)) {
                        servers.remove(&cseq);
                    }
                }
            });
        }
        if self
            .request
            .to_header()
            .ok()
            .and_then(|h| h.tag().ok())
            .flatten()
            .is_none()
        {
            let id = owner.id.lock().clone();
            match response.status_code.kind() {
                StatusCodeKind::Provisional if response.status_code != StatusCode::Trying => {
                    owner.transition(DialogState::Early(id, response.clone()))
                }
                StatusCodeKind::Successful => {
                    owner.transition(DialogState::WaitAck(id, response.clone()))
                }
                StatusCodeKind::Provisional => {}
                _ => owner.transition(DialogState::Terminated(
                    id,
                    TerminatedReason::UasOther(response.status_code.clone()),
                )),
            }
        }
        let token = {
            let mut s = self.state.lock();
            if s.final_sent {
                return;
            }
            let Some(o) = &mut s.outstanding else {
                return;
            };
            if o.timer_started || o.response.rseq_value() != response.rseq_value() {
                return;
            }
            o.timer_started = true;
            o.cancel.clone()
        };
        let weak = Arc::downgrade(self);
        let t1 = owner.endpoint_inner.option.t1;
        let deadline = owner.endpoint_inner.option.t1x64;
        platform::spawn(async move {
            let mut elapsed = Duration::ZERO;
            let mut interval = t1;
            loop {
                let delay = interval.min(deadline.saturating_sub(elapsed));
                let wait = core::pin::pin!(platform::sleep(delay));
                let cancel = core::pin::pin!(token.cancelled());
                if matches!(
                    platform::select2(wait, cancel).await,
                    platform::Either::B(_)
                ) {
                    break;
                }
                elapsed += delay;
                let Some(server) = weak.upgrade() else {
                    break;
                };
                if elapsed >= deadline {
                    server.expire().await;
                    break;
                }
                let response = {
                    let s = server.state.lock();
                    if s.final_sent {
                        break;
                    }
                    s.outstanding
                        .as_ref()
                        .filter(|o| !o.processing)
                        .map(|o| o.response.clone())
                };
                let Some(response) = response else {
                    break;
                };
                if server
                    .sender
                    .send(TransactionEvent::Respond(response))
                    .is_err()
                {
                    break;
                }
                interval = interval.saturating_mul(2); // RFC 3262: no T2 cap.
            }
        });
    }

    async fn expire(&self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        {
            let mut s = self.state.lock();
            if s.final_sent || s.outstanding.as_ref().is_none_or(|o| o.processing) {
                return;
            }
            s.outstanding = None;
            s.queue.clear();
            s.final_response = None;
        }
        let response = owner.make_response(&self.request, StatusCode::ServerTimeOut, None, None);
        self.sender.send(TransactionEvent::Respond(response)).ok();
        let id = owner.id.lock().clone();
        self.config
            .handler
            .on_error(id, "PRACK not received within 64*T1".into())
            .await;
    }

    pub(crate) fn fail(&self, message: String) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let reject = {
            let mut state = self.state.lock();
            if let Some(outstanding) = state.outstanding.take() {
                outstanding.cancel.cancel();
            }
            state.queue.clear();
            state.final_response = None;
            !state.final_sent
        };
        if reject {
            self.sender
                .send(TransactionEvent::Respond(owner.make_response(
                    &self.request,
                    StatusCode::ServerInternalError,
                    None,
                    None,
                )))
                .ok();
        }
        let id = owner.id.lock().clone();
        let handler = self.config.handler.clone();
        platform::spawn(async move {
            handler.on_error(id, message).await;
        });
    }

    pub(crate) fn pending(&self) -> bool {
        self.state.lock().outstanding.is_some()
    }

    pub(crate) async fn handle_prack(&self, tx: &mut Transaction) -> Result<()> {
        let Some((rseq, cseq, method)) = crate::sip::message::rack_parts(&tx.original) else {
            return tx.reply(StatusCode::BadRequest).await;
        };
        let Some(owner) = self.owner.upgrade() else {
            return tx.reply(StatusCode::CallTransactionDoesNotExist).await;
        };
        let id = owner.id.lock().clone();
        let matches = DialogId::try_from((&tx.original, TransactionRole::Server))
            .ok()
            .as_ref()
            == Some(&id)
            && method == "INVITE"
            && self.request.cseq_header()?.seq()? == cseq;
        let selected = {
            let mut s = self.state.lock();
            if matches {
                s.outstanding
                    .as_mut()
                    .filter(|o| !o.processing && o.response.rseq_value() == Some(rseq))
                    .map(|o| {
                        let sdp = has_sdp(&tx.original, &tx.original.body);
                        let kind = match (o.kind, sdp) {
                            (SdpKind::Offer, true) => Some(SdpKind::Answer),
                            (SdpKind::Offer, false) => None,
                            (SdpKind::Answer, true) => Some(SdpKind::Offer),
                            (_, false) => Some(SdpKind::None),
                            _ => None,
                        };
                        if kind.is_some() {
                            o.processing = true;
                            o.cancel.cancel();
                        }
                        (o.response.clone(), kind)
                    })
            } else {
                None
            }
        };
        let Some((response, kind)) = selected else {
            return tx.reply(StatusCode::CallTransactionDoesNotExist).await;
        };
        let Some(kind) = kind else {
            return tx.reply(StatusCode::BadRequest).await;
        };
        let event = IncomingPrack {
            dialog_id: id.clone(),
            invite: self.request.clone(),
            response,
            prack: tx.original.clone(),
            sdp_kind: kind,
        };
        let answer = platform::timeout(
            owner.endpoint_inner.option.t1x64,
            self.config.handler.on_prack(event),
        )
        .await;
        let answer = match answer {
            Ok(Ok(body))
                if kind != SdpKind::Offer || body.as_ref().is_some_and(PrackBody::is_sdp) =>
            {
                body
            }
            _ => {
                self.fail("PRACK SDP handler failed or did not supply the required answer".into());
                return tx.reply(StatusCode::ServerInternalError).await;
            }
        };
        if kind != SdpKind::Offer && answer.as_ref().is_some_and(PrackBody::is_sdp) {
            self.fail("unexpected SDP supplied for PRACK response".into());
            return tx.reply(StatusCode::ServerInternalError).await;
        }
        let (headers, body) = match answer {
            Some(body) => (
                vec![Header::ContentType(body.content_type.into())],
                Some(body.body),
            ),
            None => (vec![], None),
        };
        if let Err(e) = tx.reply_with(StatusCode::OK, headers, body).await {
            self.fail(format!("could not send PRACK response: {e}"));
            return Err(e);
        }
        let next = {
            let mut s = self.state.lock();
            s.outstanding = None;
            if kind == SdpKind::Answer {
                s.offer_answer_complete = true;
            }
            if s.final_sent {
                None
            } else if let Some(final_response) = s.final_response.take() {
                Some(final_response)
            } else if !s.queue.is_empty() {
                Some(s.queue.remove(0))
            } else {
                None
            }
        };
        if let Some(response) = next {
            self.sender.send(TransactionEvent::Respond(response))?;
        }
        Ok(())
    }
}
