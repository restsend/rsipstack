//! Opt-in RFC 4028 session timers for INVITE dialogs.
//!
//! Configure [`DialogLayer::set_session_timer`](super::dialog_layer::DialogLayer::set_session_timer)
//! before creating dialogs. The stack negotiates each leg independently, retries
//! bounded 422 challenges, and owns one cancellable timer task per enabled dialog.
//! Only successful INVITE/UPDATE exchanges extend the deadline. A session refresh
//! is not a billing-duration limit or an OPTIONS keepalive.
//!
//! Automatic refresh prefers a bodyless UPDATE when the peer advertises UPDATE.
//! Otherwise it sends a re-INVITE with the last successfully negotiated local SDP.
//! Applications which generate their SDP elsewhere can supply [`RefreshSdp`].
//! They still handle incoming offers through the normal dialog events; only
//! bodyless UPDATE refreshes are answered automatically.
//!
//! Timer configuration and deadlines are not part of `DialogSnapshot`. Restoring
//! a SIP dialog does not establish a new timer agreement: applications must keep
//! their recovery policy and renegotiate (or end the call) after a restart.

use super::{dialog::DialogInner, invite_dialog::InviteDialog, reinvite::AckBody};
#[cfg(not(feature = "platform-tokio"))]
use crate::platform::Instant;
use crate::{
    platform::{select3, sync::Mutex, CancellationToken, Which3},
    prelude::*,
    sip::{
        Header, HeadersExt, Method, Request, Response, StatusCode, StatusCodeKind, ToTypedHeader,
    },
    transaction::{
        key::{TransactionKey, TransactionRole},
        Transaction,
    },
    Result,
};
use alloc::sync::Weak;
use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
#[cfg(feature = "platform-tokio")]
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RefreshMethod {
    /// UPDATE only when advertised by the peer, otherwise re-INVITE.
    #[default]
    Automatic,
    /// Require peer UPDATE support; do not send an unsupported method.
    Update,
    Reinvite,
}

/// Produces a current SDP offer without sending any SIP messages. Implementations
/// must be cancellation-safe: the session deadline can cancel this future.
#[async_trait::async_trait]
pub trait RefreshSdp: Send + Sync {
    async fn offer(&self) -> Result<AckBody>;

    /// Observe a successful automatic re-INVITE's answer, after ACK. Return an
    /// error if the negotiated media cannot be used; the session is then ended.
    async fn answer(&self, _response: &Response) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct SessionTimerConfig {
    /// Desired interval, in seconds; default 1800, never below `min_se`.
    pub expires: u32,
    /// Minimum accepted interval, in seconds; RFC 4028 requires at least 90.
    pub min_se: u32,
    /// Prefer the local endpoint as refresher when negotiation allows a choice.
    /// An explicit choice by an incoming UAC is always honored.
    pub prefer_local: bool,
    pub refresh_method: RefreshMethod,
    pub sdp: Option<Arc<dyn RefreshSdp>>,
}
impl Default for SessionTimerConfig {
    fn default() -> Self {
        Self {
            expires: 1800,
            min_se: 90,
            prefer_local: true,
            refresh_method: RefreshMethod::Automatic,
            sdp: None,
        }
    }
}
impl SessionTimerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.min_se < 90 || self.expires < self.min_se {
            return Err(error("session interval must be >= Min-SE >= 90 seconds"));
        }
        Ok(())
    }
    pub(super) fn initial(&self, request: &mut Request) {
        super::reliable::add_option(request, "Supported", "timer");
        advertise_update(request);
        request
            .headers
            .unique_push(Header::MinSE(self.min_se.to_string().into()));
        let value = if self.prefer_local {
            format!("{};refresher=uac", self.expires)
        } else {
            self.expires.to_string()
        };
        request
            .headers
            .unique_push(Header::SessionExpires(value.into()));
    }
}

#[derive(Clone, Debug)]
pub struct SessionTimerStatus {
    pub interval: Option<u32>,
    pub local_refresher: bool,
    pub remaining: Duration,
    pub refreshes: usize,
    pub expirations: usize,
    pub worker_running: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Agreement {
    interval: u32,
    local: bool,
}
#[derive(Clone, Copy)]
struct Active {
    agreement: Agreement,
    expires: Instant,
    due: Instant,
    generation: u64,
}
struct State {
    active: Option<Active>,
    generation: u64,
    changed: CancellationToken,
    min_se: u32,
    client_seq: Option<u32>,
    server_seq: Option<u32>,
    peer_update: bool,
    local_sdp: Option<AckBody>,
    local_options: Option<Vec<Header>>,
}

pub(crate) struct SessionTimer {
    dialog: Weak<DialogInner>,
    config: SessionTimerConfig,
    state: Mutex<State>,
    stop: CancellationToken,
    running: AtomicBool,
    refreshes: AtomicUsize,
    expirations: AtomicUsize,
}

fn error(message: &str) -> crate::Error {
    crate::Error::Error(message.into())
}
fn seconds(value: &str) -> Result<u32> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(error("invalid session timer delta-seconds"));
    }
    value
        .parse()
        .map_err(|_| error("session timer delta-seconds overflow"))
}
fn single<'a>(message: &'a impl HeadersExt, name: &str) -> Result<Option<&'a str>> {
    let mut values = message
        .headers()
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case(name));
    let value = values.next().map(|h| h.value());
    if values.next().is_some() {
        return Err(error("duplicate session timer header"));
    }
    Ok(value)
}
fn min_se(message: &impl HeadersExt) -> Result<Option<u32>> {
    single(message, "Min-SE")?
        .map(|value| {
            let n = seconds(value.split(';').next().unwrap_or_default())?;
            if n < 90 {
                return Err(error("Min-SE must be at least 90"));
            }
            Ok(n)
        })
        .transpose()
}
fn session_expires(message: &impl HeadersExt) -> Result<Option<(u32, Option<bool>)>> {
    single(message, "Session-Expires")?
        .map(|value| {
            let mut parts = value.split(';');
            let n = seconds(parts.next().unwrap_or_default())?;
            let mut refresher = None;
            for part in parts {
                let (name, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
                if name.trim().eq_ignore_ascii_case("refresher") {
                    if refresher.is_some() {
                        return Err(error("duplicate refresher parameter"));
                    }
                    refresher = Some(match value.trim().to_ascii_lowercase().as_str() {
                        "uac" => true,
                        "uas" => false,
                        _ => return Err(error("invalid refresher parameter")),
                    });
                }
            }
            Ok((n, refresher))
        })
        .transpose()
}
fn advertise_update(message: &mut impl crate::sip::HasHeaders) {
    if !has_token(message, "Allow", "UPDATE") {
        message
            .headers_mut()
            .push(Header::Allow("INVITE, ACK, CANCEL, BYE, UPDATE".into()));
    }
}
fn has_token(message: &impl crate::sip::HasHeaders, name: &str, token: &str) -> bool {
    message.headers().iter().any(|h| {
        h.name().eq_ignore_ascii_case(name)
            && h.value()
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(token))
    })
}
fn supported(message: &impl HeadersExt) -> bool {
    message.header_contains_token("Supported", "timer")
        || message.header_contains_token("Require", "timer")
}
fn refresh(method: &Method) -> bool {
    matches!(method, Method::Invite | Method::Update)
}
fn option_header(header: &Header) -> bool {
    ["Supported", "Require", "Proxy-Require"]
        .iter()
        .any(|name| header.name().eq_ignore_ascii_case(name))
}
fn option_headers(message: &impl HeadersExt) -> Vec<Header> {
    message
        .headers()
        .iter()
        .filter(|h| option_header(h))
        .cloned()
        .collect()
}
fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_default()
}

impl SessionTimer {
    pub(super) fn install(inner: &Arc<DialogInner>, config: SessionTimerConfig) {
        let token = inner.cancel_token.child_token();
        let timer = Arc::new(Self {
            dialog: Arc::downgrade(inner),
            state: Mutex::new(State {
                active: None,
                generation: 0,
                changed: CancellationToken::new(),
                min_se: config.min_se,
                client_seq: None,
                server_seq: None,
                peer_update: false,
                local_sdp: None,
                local_options: (inner.role == TransactionRole::Client)
                    .then(|| option_headers(&*inner.initial_request.lock())),
            }),
            config,
            stop: token,
            running: AtomicBool::new(true),
            refreshes: AtomicUsize::new(0),
            expirations: AtomicUsize::new(0),
        });
        *inner.session_timer.lock() = Some(timer.clone());
        let shutdown = inner.endpoint_inner.shutdown_token();
        crate::platform::spawn(async move {
            struct Finished(Arc<SessionTimer>);
            impl Drop for Finished {
                fn drop(&mut self) {
                    self.0.stop();
                    self.0.running.store(false, Ordering::Release);
                }
            }
            let _finished = Finished(timer.clone());
            crate::platform::select2(
                core::pin::pin!(timer.run()),
                core::pin::pin!(shutdown.cancelled()),
            )
            .await;
        });
    }
    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }
    pub(super) fn status(&self) -> SessionTimerStatus {
        let state = self.state.lock();
        SessionTimerStatus {
            interval: state.active.map(|a| a.agreement.interval),
            local_refresher: state.active.is_some_and(|a| a.agreement.local),
            remaining: state
                .active
                .map_or(Duration::ZERO, |a| remaining(a.expires)),
            refreshes: self.refreshes.load(Ordering::Relaxed),
            expirations: self.expirations.load(Ordering::Relaxed),
            worker_running: self.running.load(Ordering::Acquire),
        }
    }
    pub(super) fn outgoing(&self, request: &mut Request) {
        if request.method == Method::Ack {
            return;
        }
        super::reliable::add_option(request, "Supported", "timer");
        advertise_update(request);
        if !refresh(&request.method) {
            return;
        }
        let mut state = self.state.lock();
        let options = state
            .local_options
            .get_or_insert_with(|| option_headers(request));
        request.headers.retain(|h| !option_header(h));
        request.headers.extend(options.clone());
        let interval = state
            .active
            .map_or(self.config.expires, |a| a.agreement.interval)
            .max(state.min_se);
        let local = state
            .active
            .map_or(self.config.prefer_local, |a| a.agreement.local);
        request
            .headers
            .unique_push(Header::MinSE(state.min_se.to_string().into()));
        let value = if state.active.is_none() && !local {
            interval.to_string()
        } else {
            format!("{interval};refresher={}", if local { "uac" } else { "uas" })
        };
        request
            .headers
            .unique_push(Header::SessionExpires(value.into()));
    }
    fn server_agreement(&self, request: &Request) -> Result<core::result::Result<Agreement, u32>> {
        let requested = session_expires(request)?;
        let floor = min_se(request)?.unwrap_or(90).max(self.config.min_se);
        if requested.is_some_and(|(n, _)| n < floor) {
            return Ok(Err(floor));
        }
        let interval = requested
            .map_or(self.config.expires, |s| s.0)
            .min(self.config.expires.max(floor));
        let local = if !supported(request) {
            if requested.is_some_and(|(_, who)| who.is_some()) {
                return Err(error("refresher without timer support"));
            }
            true
        } else {
            requested
                .and_then(|(_, uac)| uac)
                .map_or(self.config.prefer_local, |uac| !uac)
        };
        Ok(Ok(Agreement {
            interval: interval.max(floor),
            local,
        }))
    }
    pub(super) fn rejection(&self, request: &Request) -> Option<(StatusCode, Vec<Header>)> {
        if !refresh(&request.method) {
            return None;
        }
        if let Ok(Some(min)) = min_se(request) {
            let mut state = self.state.lock();
            state.min_se = state.min_se.max(min);
        }
        match self.server_agreement(request) {
            Ok(Ok(_)) => None,
            Ok(Err(min)) => Some((
                StatusCode::from(422),
                vec![Header::MinSE(min.to_string().into())],
            )),
            Err(_) => Some((StatusCode::BadRequest, vec![])),
        }
    }
    pub(crate) fn prepare_response(
        &self,
        request: &Request,
        response: &mut Response,
    ) -> Result<()> {
        if !refresh(&request.method) || response.status_code.kind() != StatusCodeKind::Successful {
            return Ok(());
        }
        let agreement = self
            .server_agreement(request)?
            .map_err(|_| error("session interval too small"))?;
        response.headers.unique_push(Header::SessionExpires(
            format!(
                "{};refresher={}",
                agreement.interval,
                if agreement.local { "uas" } else { "uac" }
            )
            .into(),
        ));
        if supported(request) {
            super::reliable::add_option(response, "Require", "timer");
        }
        super::reliable::add_option(response, "Supported", "timer");
        advertise_update(response);
        Ok(())
    }
    pub(crate) fn sent(&self, request: &Request, response: &Response) {
        if !refresh(&request.method) || response.status_code.kind() != StatusCodeKind::Successful {
            return;
        }
        if let Ok(Some((interval, Some(uac)))) = session_expires(response) {
            self.apply(
                request,
                response,
                false,
                Some(Agreement {
                    interval,
                    local: !uac,
                }),
            );
        }
    }
    pub(super) fn received(&self, request: &Request, response: &Response) -> Result<()> {
        if !refresh(&request.method) || response.status_code.kind() != StatusCodeKind::Successful {
            return Ok(());
        }
        let negotiated = session_expires(response)?;
        if negotiated.is_none() && response.header_contains_token("Require", "timer") {
            return Err(error("Require: timer without Session-Expires"));
        }
        let agreement = negotiated
            .map(|(interval, uac)| {
                if interval < 90 {
                    return Err(error("unsafe session interval in response"));
                }
                let local = uac.ok_or_else(|| error("response has no refresher"))?;
                Ok(Agreement { interval, local })
            })
            .transpose()?;
        self.apply(request, response, true, agreement);
        Ok(())
    }
    fn apply(
        &self,
        request: &Request,
        response: &Response,
        client: bool,
        agreement: Option<Agreement>,
    ) {
        let Ok(cseq) = request.cseq_header().and_then(|h| h.seq()) else {
            return;
        };
        let mut state = self.state.lock();
        if self.stop.is_cancelled() {
            return;
        }
        let last = if client {
            &mut state.client_seq
        } else {
            &mut state.server_seq
        };
        if last.is_some_and(|old| cseq <= old) {
            return;
        }
        *last = Some(cseq);
        if let Ok(Some(min)) = min_se(request) {
            state.min_se = state.min_se.max(min);
        }
        let (peer_update, body, content_type) = if client {
            (
                has_token(response, "Allow", "UPDATE"),
                &request.body,
                single(request, "Content-Type").ok().flatten(),
            )
        } else {
            (
                has_token(request, "Allow", "UPDATE"),
                &response.body,
                single(response, "Content-Type").ok().flatten(),
            )
        };
        state.peer_update |= peer_update;
        if !body.is_empty()
            && content_type.is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("application/sdp")
            })
        {
            state.local_sdp = Some(AckBody::sdp(body.clone()));
        }
        state.generation += 1;
        let now = Instant::now();
        state.active = agreement.map(|agreement| {
            let interval = Duration::from_secs(agreement.interval as u64);
            let due = if agreement.local {
                interval / 2
            } else {
                interval - Duration::from_secs(32).min(interval / 3)
            };
            Active {
                agreement,
                expires: now + interval,
                due: now + due,
                generation: state.generation,
            }
        });
        state.changed.cancel();
        state.changed = CancellationToken::new();
    }
    pub(super) fn retry(
        &self,
        inner: &Arc<DialogInner>,
        tx: &Transaction,
        response: &Response,
        attempts: &mut u8,
    ) -> Result<Option<Transaction>> {
        if response.status_code.code() != 422 || !refresh(&tx.original.method) || *attempts >= 3 {
            return Ok(None);
        }
        let Some(min) = min_se(response)? else {
            return Ok(None);
        };
        let mut state = self.state.lock();
        if min <= state.min_se {
            return Ok(None);
        }
        state.min_se = min;
        drop(state);
        *attempts += 1;
        let mut request = tx.original.clone();
        request
            .cseq_header_mut()?
            .mut_seq(inner.increment_local_seq())?;
        request.via_header_mut()?.update_first_value(|v| {
            let mut via = v.typed()?;
            via.params
                .retain(|p| !matches!(p, crate::sip::Param::Branch(_)));
            via.params.push(crate::transaction::make_via_branch());
            Ok(via.into())
        })?;
        // Authentication must be recomputed for the new request/CSeq (auth-int
        // may cover the body). A challenge on this retry uses the normal path.
        request
            .headers
            .retain(|h| !matches!(h, Header::Authorization(_) | Header::ProxyAuthorization(_)));
        self.outgoing(&mut request);
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut next = Transaction::new_client(
            key,
            request,
            tx.endpoint_inner.clone(),
            tx.connection.clone(),
        );
        next.destination = tx.destination.clone();
        next.defer_success_ack = tx.defer_success_ack;
        next.force_success_ack = tx.force_success_ack;
        Ok(Some(next))
    }
    async fn expire(&self, generation: Option<u64>) {
        {
            let state = self.state.lock();
            if generation
                .is_some_and(|generation| state.active.is_none_or(|a| a.generation != generation))
                || self.stop.is_cancelled()
            {
                return;
            }
            self.stop.cancel();
        }
        self.expirations.fetch_add(1, Ordering::Relaxed);
        if let Some(inner) = self.dialog.upgrade() {
            let dialog = InviteDialog::from_inner(inner);
            if let Err(error) = dialog
                .bye_with_reason("SIP;cause=408;text=\"Session timer expired\"".into())
                .await
            {
                tracing::warn!(%error, "session timer teardown failed");
            }
        }
    }
    async fn deadline(&self) -> u64 {
        loop {
            let (active, changed) = {
                let state = self.state.lock();
                (state.active, state.changed.clone())
            };
            let delay = active.map_or(Duration::from_secs(u32::MAX as u64), |a| {
                remaining(a.expires)
            });
            if matches!(
                crate::platform::select2(
                    core::pin::pin!(changed.cancelled()),
                    core::pin::pin!(crate::platform::sleep(delay))
                )
                .await,
                crate::platform::Either::B(_)
            ) {
                if let Some(active) = active {
                    return active.generation;
                }
            }
        }
    }
    async fn send_refresh(&self) -> Result<Option<Response>> {
        let inner = self
            .dialog
            .upgrade()
            .ok_or_else(|| error("dialog removed"))?;
        let ack = inner.initial_ack.lock().clone();
        if let Some(ack) = ack {
            ack.done.cancelled().await;
        }
        let dialog = InviteDialog::from_inner(inner);
        let (update, cached) = {
            let state = self.state.lock();
            (state.peer_update, state.local_sdp.clone())
        };
        let method = match self.config.refresh_method {
            RefreshMethod::Automatic if update => Method::Update,
            RefreshMethod::Update if !update => {
                return Err(error("peer has not advertised UPDATE"))
            }
            RefreshMethod::Update => Method::Update,
            _ => Method::Invite,
        };
        self.refreshes.fetch_add(1, Ordering::Relaxed);
        if method == Method::Update {
            return dialog.update(None, None).await;
        }
        let body = match &self.config.sdp {
            Some(provider) => provider.offer().await?,
            None => cached.ok_or_else(|| {
                error("re-INVITE refresh requires negotiated local SDP or RefreshSdp")
            })?,
        };
        if body.body.is_empty() {
            return Err(error("empty session refresh SDP offer"));
        }
        let request = dialog.prepare_reinvite(
            Some(vec![Header::ContentType(body.content_type.into())]),
            Some(body.body),
        )?;
        let response = dialog.send_reinvite(request, Default::default()).await?;
        if let (Some(provider), Some(response)) = (&self.config.sdp, &response) {
            if response.status_code.kind() == StatusCodeKind::Successful {
                provider.answer(response).await?;
            }
        }
        Ok(response)
    }
    async fn run(self: Arc<Self>) {
        loop {
            let (active, changed) = {
                let state = self.state.lock();
                (state.active, state.changed.clone())
            };
            let delay = active.map_or(Duration::from_secs(u32::MAX as u64), |a| remaining(a.due));
            match select3(
                core::pin::pin!(self.stop.cancelled()),
                core::pin::pin!(changed.cancelled()),
                core::pin::pin!(crate::platform::sleep(delay)),
            )
            .await
            {
                Which3::A(_) => return,
                Which3::B(_) => continue,
                Which3::C(_) => {}
            }
            let Some(active) = active else {
                continue;
            };
            if self
                .state
                .lock()
                .active
                .is_none_or(|a| a.generation != active.generation)
            {
                continue;
            }
            if !active.agreement.local || remaining(active.expires).is_zero() {
                self.expire(Some(active.generation)).await;
                return;
            }
            // The owning re-INVITE task keeps driving ACK after a deadline.
            // The watchdog never extends a deadline merely by starting a request.
            let result = select3(
                core::pin::pin!(self.stop.cancelled()),
                core::pin::pin!(self.send_refresh()),
                core::pin::pin!(self.deadline()),
            )
            .await;
            match result {
                Which3::A(_) => return,
                Which3::C(generation) => {
                    self.expire(Some(generation)).await;
                }
                Which3::B(result) => {
                    let retry = matches!(&result, Ok(Some(r)) if r.status_code.code() == 491)
                        || matches!(
                            &result,
                            Err(crate::Error::DialogError(_, _, StatusCode::RequestPending))
                        );
                    let fatal = matches!(&result, Ok(None) | Err(_)) && !retry
                        || matches!(&result, Ok(Some(r)) if matches!(r.status_code.code(), 408 | 481));
                    if fatal {
                        self.expire(None).await;
                    } else {
                        let mut state = self.state.lock();
                        if let Some(a) = state
                            .active
                            .as_mut()
                            .filter(|a| a.generation == active.generation)
                        {
                            a.due = if retry {
                                // RFC 3261 14.1: disjoint glare windows for the
                                // Call-ID owner and the other endpoint.
                                let owner = self
                                    .dialog
                                    .upgrade()
                                    .is_some_and(|d| d.role == TransactionRole::Client);
                                let mut bytes = [0; 2];
                                crate::transaction::fill_random_bytes(&mut bytes);
                                let ticks = u16::from_ne_bytes(bytes) as u64;
                                let ms = if owner {
                                    2100 + ticks % 1901
                                } else {
                                    ticks % 2001
                                };
                                (Instant::now() + Duration::from_millis(ms)).min(a.expires)
                            } else {
                                a.expires
                            };
                        }
                    }
                }
            }
        }
    }
}

impl InviteDialog {
    pub fn session_timer_status(&self) -> Option<SessionTimerStatus> {
        self.inner
            .session_timer
            .lock()
            .as_ref()
            .map(|timer| timer.status())
    }
}

impl DialogInner {
    pub(super) async fn handle_session_timer(
        self: &Arc<Self>,
        tx: &mut Transaction,
    ) -> Result<bool> {
        if !refresh(&tx.original.method) {
            return Ok(false);
        }
        let timer = self.session_timer.lock().clone();
        let rejection = match &timer {
            Some(timer) => timer.rejection(&tx.original),
            None if tx.original.header_contains_token("Require", "timer") => Some((
                StatusCode::BadExtension,
                vec![Header::Unsupported("timer".into())],
            )),
            None => None,
        };
        if let Some((status, headers)) = rejection {
            let response = self.make_response(&tx.original, status.clone(), Some(headers), None);
            tx.respond(response).await?;
            if !self.is_confirmed() {
                self.transition(super::dialog::DialogState::Terminated(
                    self.id.lock().clone(),
                    super::dialog::TerminatedReason::UasOther(status),
                ));
            }
            return Ok(true);
        }
        *tx.session_timer.lock() = timer.clone();
        if timer.is_some()
            && self.is_confirmed()
            && tx.original.method == Method::Update
            && tx.original.body.is_empty()
        {
            let contact = match Self::parse_target_refresh_contact(&tx.original) {
                Ok(contact) => contact,
                Err(_) => {
                    tx.reply(StatusCode::BadRequest).await?;
                    return Ok(true);
                }
            };
            tx.respond(self.make_response(&tx.original, StatusCode::OK, None, None))
                .await?;
            if let Some(contact) = contact {
                self.accept_target_refresh(tx.original.cseq_header()?.seq()?, &contact);
            }
            return Ok(true);
        }
        Ok(false)
    }
}

impl Drop for DialogInner {
    fn drop(&mut self) {
        if let Some(timer) = self.session_timer.lock().as_ref() {
            timer.stop();
        }
    }
}
