//! Application control of re-INVITEs on already established dialogs.
//!
//! Use [`InviteDialog::prepare_reinvite`] to inspect a request before sending,
//! then [`InviteDialog::send_reinvite`] with per-request cancellation and an
//! optional provisional-response observer. A prepared request is single-use;
//! do not send another local request between preparing and sending it. The
//! transaction reserves the dialog's INVITE usage when it starts sending.
//!
//! Requests with an SDP offer use the normal automatic ACK. For an offerless
//! request, implement [`InviteAnswerHandler`]: `answer` receives the 2xx offer
//! and may wait for another dialog's ACK answer. The stack drives transaction
//! timers while it waits, then routes and caches the exact ACK body. A local
//! BYE waits for that ACK attempt; an incoming BYE can still end the dialog.
//! `fallback_answer` must immediately return a valid rejecting answer for the
//! supplied offer. Failure or timeout of `answer` uses that answer and closes
//! the dialog with BYE. SDP parsing and negotiation remain application policy.
//!
//! For an incoming re-INVITE, a [`DialogState::Updated`] event carries a
//! [`TransactionHandle`]. Subscribe with [`TransactionHandle::cancellation`]
//! before waiting on another leg: the stack answers CANCEL, and the application
//! chooses the final INVITE response (including a late 2xx if already accepted).
//! Without a subscriber, CANCEL produces 487. Use
//! [`TransactionHandle::wait_ack`] to receive this transaction's ACK and SDP,
//! rather than inspecting the dialog-wide last ACK. `finished` signals the
//! terminal ACK outcome, before any missing-ACK cleanup BYE completes.
//!
//! Initial INVITE handling, media transport, and a policy for coupling multiple
//! dialogs are separate. Dropping the outgoing awaiter does not stop its SIP
//! transaction; use the cancellation token and still handle its final result.
//!
//! ```no_run
//! # async fn update(dialog: rsipstack::dialog::invite_dialog::InviteDialog,
//! #                 offer: Vec<u8>) -> rsipstack::Result<()> {
//! use rsipstack::dialog::reinvite::ReinviteOptions;
//! use rsipstack::sip::Header;
//! let request = dialog.prepare_reinvite(
//!     Some(vec![Header::ContentType("application/sdp".into())]), Some(offer))?;
//! let response = dialog.send_reinvite(request, ReinviteOptions::default()).await?;
//! // A non-2xx result rejects this negotiation; the established call can continue.
//! # let _ = response;
//! # Ok(()) }
//! ```
use super::dialog::{
    DialogInner, DialogState, InviteAck, TransactionCommand, TransactionCommandReceiver,
    TransactionHandle,
};
use super::invite_dialog::InviteDialog;
use super::DialogId;
use crate::platform::{mpsc::UnboundedSender, sync::Mutex, CancellationToken};
use crate::prelude::*;
use crate::sip::{
    prelude::HeadersExt, Header, Method, Request, Response, SipMessage, StatusCode, StatusCodeKind,
};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
    TransactionTimer,
};
use crate::Result;
use core::sync::atomic::{AtomicBool, Ordering};
use futures::FutureExt;
use tracing::warn;

/// Body supplied by the application for the first successful re-INVITE ACK.
#[derive(Clone, Debug)]
pub struct AckBody {
    pub content_type: String,
    pub body: Vec<u8>,
}
impl AckBody {
    pub fn sdp(body: impl Into<Vec<u8>>) -> Self {
        Self {
            content_type: "application/sdp".into(),
            body: body.into(),
        }
    }
}

/// Supply the SDP answer to an offer received in a re-INVITE's 2xx response.
/// The transaction keeps processing retransmissions while this future waits.
#[async_trait::async_trait]
pub trait InviteAnswerHandler: Send + Sync {
    async fn answer(&self, response: Response) -> Result<AckBody>;

    /// Return an immediate, valid answer rejecting the offered media. Used if
    /// `answer` fails or exceeds 64*T1; the stack sends this ACK and then BYE.
    /// SDP policy belongs to the application, including this failure path.
    fn fallback_answer(&self, response: &Response) -> AckBody;
}

/// Controls for one prepared re-INVITE. Cancellation sends CANCEL after the
/// first provisional response and still waits for the final INVITE response.
#[derive(Clone, Default)]
pub struct ReinviteOptions {
    pub cancellation: CancellationToken,
    pub answer_handler: Option<Arc<dyn InviteAnswerHandler>>,
    /// Validated 101..199 responses, before the final result. A closed observer
    /// does not cancel the SIP transaction.
    pub provisional_responses: Option<UnboundedSender<Response>>,
}

impl InviteDialog {
    /// Build a re-INVITE and reserve its CSeq without sending it. The caller can
    /// inspect the request and persist a snapshot before sending. Authentication
    /// retries, when configured, can allocate additional CSeq values. Send each
    /// prepared request once, before preparing another in-dialog request.
    pub fn prepare_reinvite(
        &self,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<Request> {
        if !self.inner.is_confirmed() {
            return Err(crate::Error::Error(
                "re-INVITE requires a confirmed dialog".into(),
            ));
        }
        self.inner
            .make_request(Method::Invite, None, None, None, headers, body)
    }

    /// Send a prepared re-INVITE. Offerless requests require an answer handler;
    /// requests carrying an offer must not supply one. The handler owns SDP
    /// policy, while the stack owns ACK routing, caching and retransmission.
    /// Once polled, the operation runs in an owning task: dropping this awaiter
    /// does not cancel SIP processing. Use the cancellation token for CANCEL.
    pub async fn send_reinvite(
        &self,
        request: Request,
        options: ReinviteOptions,
    ) -> Result<Option<Response>> {
        if !self.inner.is_confirmed()
            || request.method != Method::Invite
            || request.cseq_header()?.method()? != Method::Invite
            || request.cseq_header()?.seq()? != self.inner.get_local_seq()
            || DialogId::try_from((&request, TransactionRole::Client))? != self.id()
            || request.body.is_empty() != options.answer_handler.is_some()
        {
            return Err(crate::Error::Error(
                "invalid prepared re-INVITE or ACK answer handler".into(),
            ));
        }
        let inner = self.inner.clone();
        let task =
            crate::platform::spawn_with_result(
                async move { inner.do_reinvite(request, options).await },
            );
        #[cfg(feature = "platform-tokio")]
        {
            task.await
                .map_err(|error| crate::Error::Error(error.to_string()))?
        }
        #[cfg(not(feature = "platform-tokio"))]
        {
            task.await
        }
    }
}

pub(super) struct HandleControl {
    pub(super) cancellation: CancellationToken,
    pub(super) observed: AtomicBool,
    pub(super) finished: CancellationToken,
    acknowledged: CancellationToken,
    ack: Mutex<Option<Request>>,
}
impl core::fmt::Debug for HandleControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandleControl")
            .field("finished", &self.finished.is_cancelled())
            .field("acknowledged", &self.acknowledged.is_cancelled())
            .finish_non_exhaustive()
    }
}
impl Default for HandleControl {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            observed: AtomicBool::new(false),
            finished: CancellationToken::new(),
            acknowledged: CancellationToken::new(),
            ack: Mutex::new(None),
        }
    }
}
impl HandleControl {
    fn acknowledge(&self, request: Request) {
        *self.ack.lock() = Some(request);
        self.acknowledged.cancel();
    }
}
pub(super) struct AckGuard(pub(super) Arc<InviteAck>);
impl Drop for AckGuard {
    fn drop(&mut self) {
        self.0.done.cancel();
    }
}

struct Finished(Arc<HandleControl>);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.finished.cancel();
    }
}

impl TransactionHandle {
    /// Subscribe to CANCEL for this re-INVITE. The stack answers CANCEL itself;
    /// the subscriber must supply the INVITE final response, which can be a
    /// late 2xx when the other leg already accepted the negotiation.
    pub fn cancellation(&self) -> CancellationToken {
        self.control.observed.store(true, Ordering::SeqCst);
        self.control.cancellation.clone()
    }
    /// Resolves at the incoming re-INVITE's terminal ACK outcome, before any
    /// missing-ACK cleanup BYE completes.
    pub fn finished(&self) -> CancellationToken {
        self.control.finished.clone()
    }
    /// Wait for this re-INVITE's matching ACK, including any SDP answer.
    /// Valid only for handles delivered by a re-INVITE Updated event.
    pub async fn wait_ack(&self) -> Result<Request> {
        use crate::platform::select2;
        select2(
            core::pin::pin!(self.control.acknowledged.cancelled()),
            core::pin::pin!(self.control.finished.cancelled()),
        )
        .await;
        self.control
            .ack
            .lock()
            .clone()
            .ok_or_else(|| crate::Error::Error("re-INVITE ended without ACK".into()))
    }
}

/// CANCEL belongs to the current INVITE transaction, including after an auth
/// retry. Dropping a watch retires that attempt without dropping its response.
pub(super) struct RequestCancellation {
    pub(super) provisional: CancellationToken,
    pub(super) finished: CancellationToken,
}
impl Drop for RequestCancellation {
    fn drop(&mut self) {
        self.finished.cancel();
    }
}
impl RequestCancellation {
    pub(super) fn new(tx: &Transaction, cancellation: Option<CancellationToken>) -> Self {
        let watch = Self {
            provisional: CancellationToken::new(),
            finished: CancellationToken::new(),
        };
        if let Some(cancel) = cancellation {
            let endpoint = tx.endpoint_inner.clone();
            let mut request = tx.original.clone();
            let destination = tx.destination.clone();
            let connection = tx.connection.clone();
            let ready = watch.provisional.clone();
            let finished = watch.finished.clone();
            crate::platform::spawn(async move {
                use crate::platform::{select2, Either};
                if matches!(
                    select2(
                        core::pin::pin!(cancel.cancelled()),
                        core::pin::pin!(finished.cancelled())
                    )
                    .await,
                    Either::B(_)
                ) {
                    return;
                }
                if matches!(
                    select2(
                        core::pin::pin!(ready.cancelled()),
                        core::pin::pin!(finished.cancelled())
                    )
                    .await,
                    Either::B(_)
                ) {
                    return;
                }
                if finished.is_cancelled() {
                    return;
                }
                let result = async {
                    request.method = Method::Cancel;
                    request.cseq_header_mut()?.mut_method(Method::Cancel)?;
                    request.body.clear();
                    request.headers.retain(|h| {
                        !matches!(h, Header::ContentType(_) | Header::ContentLength(_))
                    });
                    request.headers.push(Header::ContentLength(0.into()));
                    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
                    let mut cancel = Transaction::new_client(key, request, endpoint, connection);
                    cancel.destination = destination;
                    cancel.send().await?;
                    while cancel.receive().await.is_some() {}
                    Ok::<_, crate::Error>(())
                }
                .await;
                if let Err(error) = result {
                    warn!(%error, "re-INVITE CANCEL failed");
                }
            });
        }
        watch
    }
}

impl DialogInner {
    pub(super) async fn process_reinvite(
        &self,
        tx: &mut Transaction,
        notify_confirmed: bool,
    ) -> Result<()> {
        let (handle, commands) = TransactionHandle::new();
        let control = handle.control.clone();
        let _finished = Finished(control.clone());
        // BYE can read the id under the state lock. Release id before transitioning.
        let id = self.id.lock().clone();
        self.transition(DialogState::Updated(id, tx.original.clone(), handle));
        self.process_reinvite_commands(tx, commands, &control)
            .await?;
        let answered = tx
            .last_response
            .as_ref()
            .is_some_and(|r| r.status_code.kind() == StatusCodeKind::Successful);
        let mut acknowledged = false;
        while tx.state != crate::transaction::TransactionState::Terminated {
            let Some(message) = tx.receive().await else {
                break;
            };
            if let SipMessage::Request(request) = message {
                if request.method == Method::Ack {
                    *self.remote_ack.lock() = Some(request.clone());
                    control.acknowledge(request);
                    if notify_confirmed {
                        let id = self.id.lock().clone();
                        self.transition(DialogState::Confirmed(
                            id,
                            tx.last_response.clone().unwrap_or_default(),
                        ));
                    }
                    acknowledged = true;
                    break;
                }
            }
        }
        // Publish the ACK outcome before a timeout cleanup BYE waits on the
        // peer. Applications waiting for SDP must not wait another 64*T1.
        control.finished.cancel();
        self.end_session_without_ack(tx, answered && !acknowledged)
            .await;
        Ok(())
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    async fn process_reinvite_commands(
        &self,
        tx: &mut Transaction,
        mut commands: TransactionCommandReceiver,
        control: &Arc<HandleControl>,
    ) -> Result<()> {
        use crate::platform::{select3, Which3};
        let target = match Self::parse_target_refresh_contact(&tx.original) {
            Ok(target) => target,
            Err(_) => return tx.reply(StatusCode::BadRequest).await,
        };
        let cseq = tx.original.cseq_header()?.seq()?;
        let mut deadline =
            core::pin::pin!(crate::platform::sleep(self.endpoint_inner.option.t1x64));
        loop {
            let selected = {
                let command = commands.recv().boxed();
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
                    let refresh = Self::accepts_target_refresh(&tx.original.method, &response);
                    tx.respond(response).await?;
                    if refresh {
                        if let Some(target) = &target {
                            self.accept_target_refresh(cseq, target);
                        }
                    }
                }
                Which3::A(None) => return tx.reply(StatusCode::NotImplemented).await,
                Which3::B(Some(event)) => match tx.dispatch_event(event).await {
                    Some(Some(SipMessage::Request(request)))
                        if request.method == Method::Cancel =>
                    {
                        control.cancellation.cancel();
                        if !control.observed.load(Ordering::SeqCst) {
                            return tx.reply(StatusCode::RequestTerminated).await;
                        }
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

    pub(super) async fn answer_reinvite(
        &self,
        tx: &mut Transaction,
        response: &Response,
        handler: &Arc<dyn InviteAnswerHandler>,
    ) -> Result<()> {
        use crate::platform::{select3, Which3};
        let mut terminal_event = None;
        let mut answer = core::pin::pin!(handler.answer(response.clone()));
        let mut deadline =
            core::pin::pin!(crate::platform::sleep(self.endpoint_inner.option.t1x64));
        let result = loop {
            let selected = {
                let event = core::pin::pin!(tx.tu_receiver.recv());
                select3(&mut answer, event, &mut deadline).await
            };
            match selected {
                Which3::A(result) => break result,
                Which3::B(Some(event)) => {
                    if matches!(
                        event,
                        TransactionEvent::Timer(TransactionTimer::TimerM(_))
                            | TransactionEvent::Terminate(_)
                    ) {
                        terminal_event = Some(event);
                        break Err(crate::Error::Error("ACK answer timed out".into()));
                    }
                    if matches!(tx.dispatch_event(event).await, Some(None)) {
                        break Err(crate::Error::Error(
                            "re-INVITE expired while waiting for the ACK answer".into(),
                        ));
                    }
                    // A duplicate response must not replace the offer whose
                    // answer the application is currently preparing.
                    tx.last_response = Some(response.clone());
                }
                Which3::B(None) | Which3::C(_) => {
                    break Err(crate::Error::Error("ACK answer timed out".into()))
                }
            }
        };
        let (body, failure) = match result {
            Ok(body) if !body.body.is_empty() => (body, None),
            Ok(_) => (
                handler.fallback_answer(response),
                Some(crate::Error::Error("empty ACK answer".into())),
            ),
            Err(error) => (handler.fallback_answer(response), Some(error)),
        };
        if body.body.is_empty() {
            return Err(crate::Error::Error(
                "offerless re-INVITE requires a nonempty ACK answer".into(),
            ));
        }
        let mut ack = tx.make_ack(response)?;
        ack.body = body.body;
        ack.headers
            .unique_push(Header::ContentType(body.content_type.into()));
        ack.headers
            .unique_push(Header::ContentLength((ack.body.len() as u32).into()));
        tx.last_response = Some(response.clone());
        tx.last_ack = Some(ack);
        tx.send_ack(tx.connection.clone()).await?;
        if let Some(event) = terminal_event {
            tx.tu_sender.send(event).ok();
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
