//! Couple re-INVITEs between two already confirmed dialogs.
//!
//! Feed re-INVITE `Updated` events to [`ReinviteBridge::handle`] in spawned
//! tasks, so the application can still handle BYE and other dialog events.
//! Call [`ReinviteBridge::shutdown`] when either call leg ends. Initial call
//! establishment, registration, media transport and whole-call routing remain
//! application responsibilities. One bridge instance serializes negotiation in
//! both directions; it rejects overlap with 491 rather than retrying invisibly.
//!
//! The default policy relays SDP unchanged. Dialog identifiers, route sets,
//! Contact and CSeq remain local to each leg. Offerless re-INVITEs relay the
//! 2xx offer and wait for the matching incoming ACK before answering the other
//! leg. Missing ACK or an unusable answer ends the affected session, using a
//! rejecting SDP answer before BYE. No media rollback is implied by CANCEL or
//! by a failed negotiation after a peer already accepted it.
//!
//! Reliable provisional offer/answer and session-timer negotiation are outside
//! this component's current scope. Construction rejects dialogs with a full
//! 100rel media handler: that handler would otherwise consume the peer's offer
//! independently of the other leg. Requests requiring 100rel or timer are
//! rejected with 420 rather than silently claiming support.
//!
//! ```no_run
//! # async fn example(a: rsipstack::dialog::invite_dialog::InviteDialog,
//! #                  b: rsipstack::dialog::invite_dialog::InviteDialog,
//! #                  event: rsipstack::dialog::dialog::DialogState)
//! #                  -> rsipstack::Result<()> {
//! use rsipstack::dialog::{dialog::DialogState, reinvite_bridge::ReinviteBridge};
//! use rsipstack::sip::Method;
//! let bridge = ReinviteBridge::new(a.clone(), b.clone())?;
//! // Retain one bridge for this pair of dialogs. In an event loop, spawn
//! // this operation instead of blocking receipt of BYE/termination events.
//! if let DialogState::Updated(id, request, handle) = event {
//!     if request.method == Method::Invite {
//!         if let Err(error) = bridge.handle(id, request, handle).await {
//!             bridge.shutdown();
//!             let _ = futures::join!(a.hangup(), b.hangup());
//!             return Err(error);
//!         }
//!     }
//! }
//! # Ok(()) }
//! ```

use super::{
    dialog::TransactionHandle,
    invite_dialog::InviteDialog,
    reinvite::{AckBody, InviteAnswerHandler, ReinviteOptions},
    DialogId,
};
use crate::{
    platform::{mpsc, select2, CancellationToken, Either},
    prelude::*,
    sip::{Header, HeadersExt, Method, Request, Response, StatusCode, StatusCodeKind},
    transaction::key::TransactionRole,
    Result,
};
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeDirection {
    AtoB,
    BtoA,
}
impl BridgeDirection {
    fn reverse(self) -> Self {
        match self {
            Self::AtoB => Self::BtoA,
            Self::BtoA => Self::AtoB,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeBodyRole {
    Offer,
    Answer,
}

/// Application hook for SDP rewriting or a media controller. A transformation
/// must preserve offer/answer semantics. `reject_offer` must be immediate and
/// produce a valid answer rejecting every offered stream.
pub trait ReinviteBridgePolicy: Send + Sync {
    fn transform(
        &self,
        direction: BridgeDirection,
        role: BridgeBodyRole,
        body: AckBody,
    ) -> Result<AckBody>;
    fn reject_offer(&self, offer: &Response) -> AckBody;
}

/// Relays valid SDP without changing media addresses, codecs or directions.
#[derive(Default)]
pub struct PassthroughSdp;
impl ReinviteBridgePolicy for PassthroughSdp {
    fn transform(&self, _: BridgeDirection, _: BridgeBodyRole, body: AckBody) -> Result<AckBody> {
        if !body
            .content_type
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/sdp"))
            || !core::str::from_utf8(&body.body).is_ok_and(|s| s.lines().any(|l| l == "v=0"))
        {
            return Err(error("bridge requires an application/sdp body"));
        }
        Ok(body)
    }
    fn reject_offer(&self, offer: &Response) -> AckBody {
        // RFC 3264 section 6: preserve each media line's position and protocol,
        // set its port to zero, and retain at least one format. No RTP/RTCP is
        // enabled and no offered security or transport attributes are accepted.
        let mut answer =
            String::from("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n");
        if let Ok(sdp) = core::str::from_utf8(&offer.body) {
            for line in sdp.lines().filter_map(|l| l.strip_prefix("m=")) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() >= 4 {
                    answer.push_str(&format!(
                        "m={} 0 {} {}\r\n",
                        fields[0],
                        fields[2],
                        fields[3..].join(" ")
                    ));
                }
            }
        }
        AckBody::sdp(answer.into_bytes())
    }
}

struct Inner {
    a: InviteDialog,
    b: InviteDialog,
    busy: AtomicBool,
    shutdown: CancellationToken,
    policy: Arc<dyn ReinviteBridgePolicy>,
}

#[derive(Clone)]
pub struct ReinviteBridge {
    inner: Arc<Inner>,
}

struct Reservation(Arc<Inner>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::SeqCst);
    }
}
struct StopWatch(CancellationToken);
impl Drop for StopWatch {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl ReinviteBridge {
    pub fn new(a: InviteDialog, b: InviteDialog) -> Result<Self> {
        Self::with_policy(a, b, Arc::new(PassthroughSdp))
    }
    pub fn with_policy(
        a: InviteDialog,
        b: InviteDialog,
        policy: Arc<dyn ReinviteBridgePolicy>,
    ) -> Result<Self> {
        if !a.state().is_confirmed() || !b.state().is_confirmed() || a.id() == b.id() {
            return Err(error("bridge requires two distinct confirmed dialogs"));
        }
        if a.inner.reliable_config.lock().is_some() || b.inner.reliable_config.lock().is_some() {
            return Err(error("reliable-provisional bridging requires a separate media policy; disable 100rel on these bridge legs"));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                a,
                b,
                busy: AtomicBool::new(false),
                shutdown: CancellationToken::new(),
                policy,
            }),
        })
    }

    /// Cancel pending negotiation and reject future requests. The application
    /// still drives each dialog and its whole-call BYE policy.
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    /// Handle an incoming re-INVITE's Updated event. The operation owns a task
    /// once polled, so dropping its awaiter cannot abandon either transaction.
    /// Returns the relayed status; a rejected negotiation normally preserves
    /// the established session. On an error, shut down the bridge and terminate
    /// both call legs: a peer may already have accepted the modification.
    pub async fn handle(
        &self,
        source: DialogId,
        request: Request,
        handle: TransactionHandle,
    ) -> Result<StatusCode> {
        let inner = self.inner.clone();
        let task = crate::platform::spawn_with_result(async move {
            inner.handle(source, request, handle).await
        });
        #[cfg(feature = "platform-tokio")]
        {
            task.await.map_err(|e| error(&e.to_string()))?
        }
        #[cfg(not(feature = "platform-tokio"))]
        {
            task.await
        }
    }
}

impl Inner {
    async fn handle(
        self: Arc<Self>,
        source: DialogId,
        request: Request,
        handle: TransactionHandle,
    ) -> Result<StatusCode> {
        let direction = if source == self.a.id() {
            BridgeDirection::AtoB
        } else if source == self.b.id() {
            BridgeDirection::BtoA
        } else {
            return reply(&handle, StatusCode::CallTransactionDoesNotExist, None, None).await;
        };
        if request.method != Method::Invite
            || DialogId::try_from((&request, TransactionRole::Server))? != source
        {
            return Err(error("bridge requires the source dialog's re-INVITE event"));
        }
        if self.shutdown.is_cancelled() {
            return reply(&handle, StatusCode::CallTransactionDoesNotExist, None, None).await;
        }
        let unsupported: Vec<_> = ["100rel", "timer"]
            .into_iter()
            .filter(|name| request.header_contains_token("require", name))
            .collect();
        if !unsupported.is_empty() {
            return reply(
                &handle,
                StatusCode::BadExtension,
                Some(vec![Header::Unsupported(unsupported.join(", ").into())]),
                None,
            )
            .await;
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return reply(&handle, StatusCode::RequestPending, None, None).await;
        }
        let _reservation = Reservation(self.clone());
        let destination = match direction {
            BridgeDirection::AtoB => &self.b,
            BridgeDirection::BtoA => &self.a,
        };
        if !destination.state().is_confirmed() {
            return reply(&handle, StatusCode::CallTransactionDoesNotExist, None, None).await;
        }
        let incoming_cancel = handle.cancellation();
        if incoming_cancel.is_cancelled() {
            // CANCEL can win before the application dispatches Updated. The
            // default dialog handler may already have sent 487; either way,
            // do not start a new negotiation on the other leg.
            handle.reply(StatusCode::RequestTerminated).await.ok();
            return Ok(StatusCode::RequestTerminated);
        }
        let cancellation = self.shutdown.child_token();
        let done = CancellationToken::new();
        let _watch = StopWatch(done.clone());
        let forward_cancel = cancellation.clone();
        crate::platform::spawn(async move {
            if matches!(
                select2(
                    core::pin::pin!(incoming_cancel.cancelled()),
                    core::pin::pin!(done.cancelled())
                )
                .await,
                Either::A(_)
            ) {
                forward_cancel.cancel();
            }
        });
        let offered = !request.body.is_empty();
        let payload = if offered {
            match self
                .policy
                .transform(direction, BridgeBodyRole::Offer, request_body(&request))
            {
                Ok(body) => Some(body),
                Err(_) => return reply(&handle, StatusCode::NotAcceptableHere, None, None).await,
            }
        } else {
            None
        };
        let outgoing = match destination
            .prepare_reinvite(payload.as_ref().map(body_headers), payload.map(|p| p.body))
        {
            Ok(request) => request,
            Err(_) => {
                return reply(&handle, StatusCode::CallTransactionDoesNotExist, None, None).await
            }
        };
        let answered = Arc::new(AtomicBool::new(false));
        let handler = (!offered).then(|| {
            Arc::new(RelayAnswer {
                handle: handle.clone(),
                policy: self.policy.clone(),
                direction,
                answered: answered.clone(),
                shutdown: self.shutdown.clone(),
            }) as Arc<dyn InviteAnswerHandler>
        });
        #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
        let (provisionals, mut progress) = mpsc::unbounded_channel();
        let mut pending = core::pin::pin!(destination.send_reinvite(
            outgoing,
            ReinviteOptions {
                cancellation: cancellation.clone(),
                answer_handler: handler,
                provisional_responses: Some(provisionals),
            }
        ));
        let mut relay_failure = None;
        let result = loop {
            match select2(&mut pending, core::pin::pin!(progress.recv())).await {
                Either::A(result) => break result,
                Either::B(Some(response)) => {
                    if relay_failure.is_some() {
                        continue;
                    }
                    // 100rel is terminated independently on the outgoing leg.
                    // Do not advertise reliability that this incoming leg did
                    // not negotiate. A reliable SDP exchange needs PRACK policy.
                    if response.header_contains_token("require", "100rel") {
                        continue;
                    }
                    let payload = (!response.body.is_empty()).then(|| response_body(&response));
                    let payload = match payload {
                        Some(body) => match self.policy.transform(
                            direction.reverse(),
                            if offered {
                                BridgeBodyRole::Answer
                            } else {
                                BridgeBodyRole::Offer
                            },
                            body,
                        ) {
                            Ok(body) => Some(body),
                            Err(error) => {
                                relay_failure = Some(error);
                                cancellation.cancel();
                                continue;
                            }
                        },
                        None => None,
                    };
                    if let Err(error) = reply(
                        &handle,
                        response.status_code,
                        payload.as_ref().map(body_headers),
                        payload.map(|p| p.body),
                    )
                    .await
                    {
                        relay_failure = Some(error);
                        cancellation.cancel();
                    }
                }
                Either::B(None) => break pending.await,
            }
        };
        if let Some(error) = relay_failure {
            self.shutdown.cancel();
            reply(&handle, StatusCode::BadGateway, None, None)
                .await
                .ok();
            if result.as_ref().is_ok_and(|r| {
                r.as_ref()
                    .is_some_and(|r| r.status_code.kind() == StatusCodeKind::Successful)
            }) {
                destination.bye().await.ok();
            }
            return Err(error);
        }
        let response = match result {
            Ok(Some(response)) => response,
            other => {
                if !answered.load(Ordering::SeqCst) {
                    let status = match &other {
                        Err(crate::Error::DialogError(_, _, StatusCode::RequestPending)) => {
                            StatusCode::RequestPending
                        }
                        _ => StatusCode::BadGateway,
                    };
                    return reply(&handle, status, None, None).await;
                }
                return Err(other.err().unwrap_or_else(|| {
                    error("outgoing re-INVITE ended without a final response")
                }));
            }
        };
        let status = response.status_code.clone();
        if !answered.load(Ordering::SeqCst) {
            let payload = if status.kind() == StatusCodeKind::Successful {
                match self.policy.transform(
                    direction.reverse(),
                    BridgeBodyRole::Answer,
                    response_body(&response),
                ) {
                    Ok(body) => Some(body),
                    Err(error) => {
                        self.shutdown.cancel();
                        reply(&handle, StatusCode::BadGateway, None, None)
                            .await
                            .ok();
                        destination.bye().await.ok();
                        return Err(error);
                    }
                }
            } else if response.body.is_empty() {
                None
            } else {
                Some(response_body(&response))
            };
            let mut headers = payload.as_ref().map(body_headers).unwrap_or_default();
            headers.extend(
                response
                    .headers
                    .iter()
                    .filter(|h| matches!(h, Header::RetryAfter(_) | Header::Warning(_)))
                    .cloned(),
            );
            reply(
                &handle,
                status.clone(),
                Some(headers),
                payload.map(|p| p.body),
            )
            .await?;
        }
        // Keep the bridge reservation until both ACK directions are complete.
        if let Err(error) = handle.wait_ack().await {
            if status.kind() == StatusCodeKind::Successful {
                destination.bye().await.ok();
            }
            return Err(error);
        }
        Ok(status)
    }
}

struct RelayAnswer {
    handle: TransactionHandle,
    policy: Arc<dyn ReinviteBridgePolicy>,
    direction: BridgeDirection,
    answered: Arc<AtomicBool>,
    shutdown: CancellationToken,
}
#[async_trait::async_trait]
impl InviteAnswerHandler for RelayAnswer {
    async fn answer(&self, response: Response) -> Result<AckBody> {
        let offer = self.policy.transform(
            self.direction.reverse(),
            BridgeBodyRole::Offer,
            response_body(&response),
        )?;
        reply(
            &self.handle,
            response.status_code,
            Some(body_headers(&offer)),
            Some(offer.body),
        )
        .await?;
        self.answered.store(true, Ordering::SeqCst);
        let ack = match select2(
            core::pin::pin!(self.handle.wait_ack()),
            core::pin::pin!(self.shutdown.cancelled()),
        )
        .await
        {
            Either::A(result) => result?,
            Either::B(_) => return Err(error("bridge ended while waiting for an ACK answer")),
        };
        self.policy
            .transform(self.direction, BridgeBodyRole::Answer, request_body(&ack))
    }
    fn fallback_answer(&self, response: &Response) -> AckBody {
        self.policy.reject_offer(response)
    }
}

fn error(message: &str) -> crate::Error {
    crate::Error::Error(message.into())
}
async fn reply(
    handle: &TransactionHandle,
    status: StatusCode,
    headers: Option<Vec<Header>>,
    body: Option<Vec<u8>>,
) -> Result<StatusCode> {
    handle
        .respond(status.clone(), headers, body)
        .await
        .map_err(|e| error(&e.to_string()))?;
    Ok(status)
}
fn body_headers(body: &AckBody) -> Vec<Header> {
    vec![Header::ContentType(body.content_type.clone().into())]
}
fn content_type(headers: &crate::sip::Headers) -> String {
    headers
        .iter()
        .find_map(|h| {
            if let Header::ContentType(value) = h {
                Some(value.value().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_default()
}
fn request_body(request: &Request) -> AckBody {
    AckBody {
        content_type: content_type(&request.headers),
        body: request.body.clone(),
    }
}
fn response_body(response: &Response) -> AckBody {
    AckBody {
        content_type: content_type(&response.headers),
        body: response.body.clone(),
    }
}
