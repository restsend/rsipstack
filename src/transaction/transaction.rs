use super::key::TransactionKey;
use super::timer::Timer;
use super::{
    IncomingRequest, RequestSender, TransactionState, TransactionTimer, TransactionType, Transport,
};
use crate::transport::transport::TransportReceiver;
use crate::transport::{TransportEvent, TransportLayer};
use crate::{Error, Result};
use rsip::{Method, Request, Response, SipMessage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::select;
use tokio::sync::mpsc::{error, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

pub(super) const T1: Duration = Duration::from_millis(500);
pub(super) const T1X64: Duration = Duration::from_secs(64 * 500);
pub(super) const T4: Duration = Duration::from_secs(4); // server invite only
pub(super) const TIMER_INTERVAL: Duration = Duration::from_millis(20);

pub(super) type TransactionEventReceiver = UnboundedReceiver<TransactionEvent>;
pub(super) type TransactionEventSender = UnboundedSender<TransactionEvent>;
pub(super) enum TransactionEvent {
    Received(SipMessage, Option<Transport>),
    Timer(TransactionTimer),
    Terminate,
}

pub(super) struct TransactionCore {
    pub user_agent: String,
    pub timers: Timer<TransactionTimer>,
    pub transport_layer: TransportLayer,
    pub finished_transactions: Mutex<HashMap<TransactionKey, Option<SipMessage>>>,
    pub transactions: Mutex<HashMap<TransactionKey, TransactionEventSender>>,
    incoming_sender: Mutex<Option<RequestSender>>,
    cancel_token: CancellationToken,
    timer_interval: Duration,
}
pub(super) type TransactionCoreRef = Arc<TransactionCore>;

impl TransactionCore {
    pub fn new(
        user_agent: String,
        transport_layer: TransportLayer,
        cancel_token: CancellationToken,
        timer_interval: Option<Duration>,
    ) -> Arc<Self> {
        Arc::new(TransactionCore {
            user_agent,
            timers: Timer::new(),
            transport_layer,
            transactions: Mutex::new(HashMap::new()),
            finished_transactions: Mutex::new(HashMap::new()),
            timer_interval: timer_interval.unwrap_or(TIMER_INTERVAL),
            cancel_token,
            incoming_sender: Mutex::new(None),
        })
    }

    pub(super) async fn serve(&self) -> Result<()> {
        let (transport_tx, transport_rx) = unbounded_channel();

        select! {
            _ = self.cancel_token.cancelled() => {
            },
            _ = self.process_timer() => {
            },
            _ = self.transport_layer.serve(transport_tx) => {
            },
            _ = self.process_transport_layer(transport_rx) => {
            },
        }
        Ok(())
    }

    // process transport layer, receive message from transport layer
    async fn process_transport_layer(&self, mut transport_rx: TransportReceiver) -> Result<()> {
        while let Some(event) = transport_rx.recv().await {
            match event {
                TransportEvent::IncomingMessage(msg, transport) => {
                    trace!("incoming message {} from {}", msg, transport);
                    self.on_received_message(msg, transport).await?;
                }
                TransportEvent::NewTransport(t) => {
                    trace!("new transport {} ", t);
                }
                TransportEvent::TransportClosed(t) => {
                    trace!("transport closed {} ", t);
                }
                TransportEvent::Terminate => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn process_timer(&self) -> Result<()> {
        while !self.cancel_token.is_cancelled() {
            for t in self.timers.poll(Instant::now()) {
                match t {
                    TransactionTimer::TimerCleanup(key) => {
                        self.transactions.lock().unwrap().remove(&key);
                        self.finished_transactions.lock().unwrap().remove(&key);
                        continue;
                    }
                    _ => {}
                }

                if let Some(tu) = { self.transactions.lock().unwrap().get(t.key()) } {
                    match tu.send(TransactionEvent::Timer(t)) {
                        Ok(_) => {}
                        Err(error::SendError(t)) => match t {
                            TransactionEvent::Timer(t) => {
                                self.detach_transaction(t.key(), None);
                            }
                            _ => {}
                        },
                    }
                }
            }
            sleep(self.timer_interval).await;
        }
        Ok(())
    }

    pub(super) fn attach_incoming_sender(&self, sender: Option<RequestSender>) {
        *self.incoming_sender.lock().unwrap() = sender;
    }

    // receive message from transport layer
    pub(super) async fn on_received_message(
        &self,
        msg: SipMessage,
        transport: Transport,
    ) -> Result<()> {
        if let SipMessage::Request(ref req) = msg {
            if req.method != Method::Ack {
                if self.incoming_sender.lock().unwrap().is_none() {
                    let resp = self.make_response(req, rsip::StatusCode::ServerInternalError, None);
                    transport.send(resp.into()).await?;
                    return Err(Error::TransactionError(
                        "incoming_sender not set".to_string(),
                        TransactionKey::Invalid,
                    ));
                }
                let event = IncomingRequest {
                    request: msg.try_into()?,
                    transport: transport,
                };
                self.incoming_sender
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|s| s.send(Some(event)));
                return Ok(());
            }
        }

        let key = match &msg {
            SipMessage::Request(req) => TransactionKey::try_from(req)?,
            SipMessage::Response(resp) => TransactionKey::try_from(resp)?,
        };

        let last_message = self
            .finished_transactions
            .lock()
            .unwrap()
            .get(&key)
            .map(|m| m.clone())
            .flatten();

        if let Some(last_message) = last_message {
            transport.send(last_message).await?;
            return Ok(());
        }

        if let Some(tu) = { self.transactions.lock().unwrap().get(&key) } {
            tu.send(TransactionEvent::Received(msg, Some(transport)))
                .map_err(|e| Error::TransactionError(e.to_string(), key))?;
        }
        Ok(())
    }

    fn attach_transaction(&self, key: &TransactionKey, tu_sender: TransactionEventSender) {
        self.transactions
            .lock()
            .unwrap()
            .insert(key.clone(), tu_sender);
    }

    fn detach_transaction(&self, key: &TransactionKey, last_message: Option<SipMessage>) {
        self.transactions.lock().unwrap().remove(key);

        if let Some(msg) = last_message {
            if self.finished_transactions.lock().unwrap().contains_key(key) {
                return;
            }

            let timer_k_duration = if let SipMessage::Request(_) = msg {
                T4
            } else {
                T1X64
            };

            self.timers.timeout(
                timer_k_duration,
                TransactionTimer::TimerCleanup(key.clone()), // maybe use TimerK ???
            );

            self.finished_transactions
                .lock()
                .unwrap()
                .insert(key.clone(), Some(msg));
        }
    }
}

pub struct Transaction {
    pub transaction_type: TransactionType,
    pub key: TransactionKey,
    pub original: Request,
    pub state: TransactionState,
    pub(super) core: TransactionCoreRef,
    pub(super) transport: Option<Transport>,
    pub(super) last_response: Option<Response>,
    pub(super) last_ack: Option<Request>,
    pub(super) tu_receiver: TransactionEventReceiver,
    pub(super) tu_sender: TransactionEventSender,
    pub(super) timer_a: Option<u64>,
    pub(super) timer_b: Option<u64>,
    pub(super) timer_d: Option<u64>,
    pub(super) timer_k: Option<u64>, // server invite only
}

impl Transaction {
    fn new(
        transaction_type: TransactionType,
        key: TransactionKey,
        original: Request,
        transport: Option<Transport>,
        core: TransactionCoreRef,
    ) -> Self {
        let (tu_sender, tu_receiver) = unbounded_channel();
        Self {
            transaction_type,
            core,
            transport,
            key,
            original,
            state: TransactionState::Calling,
            last_response: None,
            last_ack: None,
            timer_a: None,
            timer_b: None,
            timer_d: None,
            timer_k: None,
            tu_receiver,
            tu_sender,
        }
    }

    pub(super) fn new_client(
        key: TransactionKey,
        original: Request,
        core: TransactionCoreRef,
        transport: Option<Transport>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite => TransactionType::ClientInvite,
            _ => TransactionType::ClientNonInvite,
        };
        Transaction::new(tx_type, key, original, transport, core)
    }

    pub(super) fn new_server(
        key: TransactionKey,
        original: Request,
        core: TransactionCoreRef,
        transport: Option<Transport>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite => TransactionType::ServerInvite,
            _ => TransactionType::ServerNonInvite,
        };
        Transaction::new(tx_type, key, original, transport, core)
    }
    // send client request
    pub async fn send(&mut self) -> Result<()> {
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => {}
            _ => {
                return Err(Error::TransactionError(
                    "send is only valid for client transactions".to_string(),
                    self.key.clone(),
                ));
            }
        }

        if let None = self.transport {
            let transport = self.core.transport_layer.lookup(&self.original.uri).await?;
            self.transport.replace(transport.clone());
        }

        let transport = self.transport.as_ref().ok_or(Error::TransactionError(
            "no transport found".to_string(),
            self.key.clone(),
        ))?;

        transport.send(self.original.to_owned().into()).await?;
        self.core
            .attach_transaction(&self.key, self.tu_sender.clone());
        self.transition(TransactionState::Trying).map(|_| ())
    }

    // send server response
    pub async fn respond(&mut self, response: Response) -> Result<()> {
        match self.transaction_type {
            TransactionType::ServerInvite | TransactionType::ServerNonInvite => {}
            _ => {
                return Err(Error::TransactionError(
                    "respond is only valid for server transactions".to_string(),
                    self.key.clone(),
                ));
            }
        }

        let transport = self.transport.as_ref().ok_or(Error::TransactionError(
            "no transport found".to_string(),
            self.key.clone(),
        ))?;
        transport.send(response.to_owned().into()).await?;

        let new_state = match response.status_code.kind() {
            rsip::StatusCodeKind::Provisional => match response.status_code {
                rsip::StatusCode::Trying => TransactionState::Trying,
                _ => TransactionState::Proceeding,
            },
            _ => match self.transaction_type {
                TransactionType::ServerInvite => TransactionState::Completed,
                _ => TransactionState::Terminated,
            },
        };
        self.last_response.replace(response);
        self.transition(new_state).map(|_| ())
    }

    pub async fn send_trying(&mut self) -> Result<()> {
        if self.transaction_type != TransactionType::ServerInvite {
            return Err(Error::TransactionError(
                "send_trying is only valid for server invite transactions".to_string(),
                self.key.clone(),
            ));
        }
        self.respond(
            self.core
                .make_response(&self.original, rsip::StatusCode::Trying, None),
        )
        .await
    }

    pub async fn send_ack(&mut self, ack: Request) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_ack is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        let transport = self.transport.as_ref().ok_or(Error::TransactionError(
            "no transport found".to_string(),
            self.key.clone(),
        ))?;

        transport.send(ack.to_owned().into()).await?;
        self.last_ack.replace(ack);
        self.transition(TransactionState::Terminated).map(|_| ())
    }

    pub async fn receive(&mut self) -> Option<SipMessage> {
        while let Some(event) = self.tu_receiver.recv().await {
            match event {
                TransactionEvent::Received(msg, transport) => {
                    if let Some(msg) = match msg {
                        SipMessage::Request(req) => self.on_received_request(req, transport).await,
                        SipMessage::Response(resp) => self.on_received_response(resp).await,
                    } {
                        return Some(msg);
                    }
                }
                TransactionEvent::Timer(t) => {
                    self.on_timer(t).await.ok();
                }
                TransactionEvent::Terminate => {
                    return None;
                }
            }
        }
        None
    }

    fn inform_tu_response(&mut self, response: Response) -> Result<()> {
        self.tu_sender
            .send(TransactionEvent::Received(
                SipMessage::Response(response),
                None,
            ))
            .map_err(|e| Error::TransactionError(e.to_string(), self.key.clone()))
    }

    async fn on_received_request(
        &mut self,
        req: Request,
        transport: Option<Transport>,
    ) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => return None,
            _ => {}
        }
        if self.transport.is_none() && transport.is_some() {
            self.transport.replace(transport.unwrap());
        }
        match self.state {
            TransactionState::Calling => {
                return Some(SipMessage::Request(req));
            }
            TransactionState::Trying | TransactionState::Proceeding => {
                // retransmission of last response
                if let Some(last_response) = &self.last_response {
                    self.respond(last_response.to_owned()).await.ok();
                } else {
                    warn!("received request before sending response");
                    return Some(SipMessage::Request(req));
                }
            }
            TransactionState::Completed => {
                if req.method == Method::Ack {
                    self.transition(TransactionState::Confirmed).ok();
                    return Some(SipMessage::Request(req));
                }
            }
            _ => {}
        }
        None
    }

    async fn on_received_response(&mut self, resp: Response) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ServerInvite | TransactionType::ServerNonInvite => return None,
            _ => {}
        }
        match self.state {
            TransactionState::Calling | TransactionState::Trying => {
                match resp.status_code.kind() {
                    rsip::StatusCodeKind::Provisional => {
                        self.transition(TransactionState::Proceeding).ok();
                    }
                    rsip::StatusCodeKind::Successful => {
                        self.last_response.replace(resp.clone());
                        if self.transaction_type == TransactionType::ClientInvite {
                            self.transition(TransactionState::Confirmed).ok();
                        } else {
                            self.transition(TransactionState::Terminated).ok();
                        }
                    }
                    _ => {
                        self.last_response.replace(resp.clone());
                        self.transition(TransactionState::Terminated).ok();
                    }
                }
                return Some(SipMessage::Response(resp));
            }
            TransactionState::Proceeding => {
                if resp.status_code.kind() == rsip::StatusCodeKind::Successful {
                    self.transition(TransactionState::Completed).ok();
                }
                return Some(SipMessage::Response(resp));
            }
            TransactionState::Completed => {
                if resp.status_code.kind() == rsip::StatusCodeKind::Successful {
                    self.transition(TransactionState::Terminated).ok();
                }
                return Some(SipMessage::Response(resp));
            }
            _ => {}
        }
        None
    }

    async fn on_timer(&mut self, timer: TransactionTimer) -> Result<()> {
        match self.state {
            TransactionState::Trying => {
                if let TransactionTimer::TimerA(key, duration) = timer {
                    // Resend the INVITE request
                    if let Some(transport) = &self.transport {
                        transport.send(self.original.to_owned().into()).await?;
                    }
                    // Restart Timer A with an upper limit
                    let duration = (duration * 2).min(T1X64);
                    let timer_a = self
                        .core
                        .timers
                        .timeout(duration, TransactionTimer::TimerA(key, duration));
                    self.timer_a.replace(timer_a);
                } else if let TransactionTimer::TimerB(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                    // Inform TU about timeout
                    let timeout_response = self.core.make_response(
                        &self.original,
                        rsip::StatusCode::RequestTimeout,
                        None,
                    );
                    self.inform_tu_response(timeout_response)?;
                }
            }
            TransactionState::Proceeding => {
                if let TransactionTimer::TimerB(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                    // Inform TU about timeout
                    let timeout_response = self.core.make_response(
                        &self.original,
                        rsip::StatusCode::RequestTimeout,
                        None,
                    );
                    self.inform_tu_response(timeout_response)?;
                }
            }
            TransactionState::Completed => {
                if let TransactionTimer::TimerD(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                }
            }
            TransactionState::Confirmed => {
                if let TransactionTimer::TimerK(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn transition(&mut self, state: TransactionState) -> Result<TransactionState> {
        if self.state == state {
            return Ok(self.state.clone());
        }
        match state {
            TransactionState::Calling => {
                // not state can transition to Calling
            }
            TransactionState::Trying => {
                let transport = self.transport.as_ref().ok_or(Error::TransactionError(
                    "no transport found".to_string(),
                    self.key.clone(),
                ))?;

                if !transport.is_reliable() {
                    self.timer_a.take().map(|id| self.core.timers.cancel(id));
                    self.timer_a.replace(
                        self.core
                            .timers
                            .timeout(T1, TransactionTimer::TimerA(self.key.clone(), T1)),
                    );
                }
                self.timer_b.take().map(|id| self.core.timers.cancel(id));
                self.timer_b.replace(
                    self.core
                        .timers
                        .timeout(T1X64, TransactionTimer::TimerB(self.key.clone())),
                );
            }
            TransactionState::Proceeding => {
                self.timer_a.take().map(|id| self.core.timers.cancel(id));
                // start Timer B
                let timer_b = self
                    .core
                    .timers
                    .timeout(T1X64, TransactionTimer::TimerB(self.key.clone()));
                self.timer_b.replace(timer_b);
            }
            TransactionState::Completed => {
                self.timer_a.take().map(|id| self.core.timers.cancel(id));
                self.timer_b.take().map(|id| self.core.timers.cancel(id));
                // start Timer D
                let timer_d = self
                    .core
                    .timers
                    .timeout(T1X64, TransactionTimer::TimerD(self.key.clone()));
                self.timer_d.replace(timer_d);
            }
            TransactionState::Confirmed => {
                self.cleanup_timer();
                // start Timer K, wait for ACK
                let timer_k = self
                    .core
                    .timers
                    .timeout(T4, TransactionTimer::TimerK(self.key.clone()));
                self.timer_k.replace(timer_k);
            }
            TransactionState::Terminated => {
                self.cleanup();
                self.tu_sender.send(TransactionEvent::Terminate).ok(); // tell TU to terminate
            }
        }
        trace!("{} transition: {:?} -> {:?}", self.key, self.state, state);
        self.state = state;
        Ok(self.state.clone())
    }

    fn cleanup_timer(&mut self) {
        self.timer_a.take().map(|id| self.core.timers.cancel(id));
        self.timer_b.take().map(|id| self.core.timers.cancel(id));
        self.timer_d.take().map(|id| self.core.timers.cancel(id));
        self.timer_k.take().map(|id| self.core.timers.cancel(id));
    }

    fn cleanup(&mut self) {
        if self.state == TransactionState::Calling {
            return;
        }
        self.cleanup_timer();
        let last_message = {
            match self.transaction_type {
                TransactionType::ClientInvite => {
                    self.last_ack.take().map(|r| SipMessage::Request(r))
                }
                TransactionType::ServerNonInvite => {
                    self.last_response.take().map(|r| SipMessage::Response(r))
                }
                _ => None,
            }
        };
        self.core.detach_transaction(&self.key, last_message);
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.cleanup();
    }
}
