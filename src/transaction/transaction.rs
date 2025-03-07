use super::endpoint::EndpointInnerRef;
use super::key::TransactionKey;
use super::{SipConnection, TransactionState, TransactionTimer, TransactionType};
use crate::transaction::make_tag;
use crate::transport::SipAddr;
use crate::{Error, Result};
use rsip::prelude::HeadersExt;
use rsip::headers::ContentLength;
use rsip::message::HasHeaders;
use rsip::{Header, Method, Request, Response, SipMessage, StatusCode};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, instrument, span, Level, Span};

pub type TransactionEventReceiver = UnboundedReceiver<TransactionEvent>;
pub type TransactionEventSender = UnboundedSender<TransactionEvent>;
pub enum TransactionEvent {
    Received(SipMessage, Option<SipConnection>),
    Timer(TransactionTimer),
    Respond(Response),
    Terminate,
}

pub struct Transaction {
    pub transaction_type: TransactionType,
    pub key: TransactionKey,
    pub original: Request,
    pub destination: Option<SipAddr>,
    pub state: TransactionState,
    pub endpoint_inner: EndpointInnerRef,
    pub connection: Option<SipConnection>,
    pub last_response: Option<Response>,
    pub last_ack: Option<Request>,
    pub tu_receiver: TransactionEventReceiver,
    pub tu_sender: TransactionEventSender,
    pub timer_a: Option<u64>,
    pub timer_b: Option<u64>,
    pub timer_d: Option<u64>,
    pub timer_k: Option<u64>, // server invite only
    pub timer_g: Option<u64>, // server invite only
    span: Span,
    is_cleaned_up: bool,
}

impl Transaction {
    fn new(
        transaction_type: TransactionType,
        key: TransactionKey,
        original: Request,
        connection: Option<SipConnection>,
        endpoint_inner: EndpointInnerRef,
    ) -> Self {
        let (tu_sender, tu_receiver) = unbounded_channel();
        let span = span!(Level::INFO, "transaction", key = %key);
        info!("transaction created {:?} {}", transaction_type, key);
        let tx = Self {
            transaction_type,
            endpoint_inner,
            connection,
            key,
            original,
            destination: None,
            state: TransactionState::Calling,
            last_response: None,
            last_ack: None,
            timer_a: None,
            timer_b: None,
            timer_d: None,
            timer_k: None,
            timer_g: None,
            tu_receiver,
            tu_sender,
            span,
            is_cleaned_up: false,
        };
        tx.endpoint_inner
            .attach_transaction(&tx.key, tx.tu_sender.clone());
        tx
    }

    pub fn new_client(
        key: TransactionKey,
        original: Request,
        endpoint_inner: EndpointInnerRef,
        connection: Option<SipConnection>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite => TransactionType::ClientInvite,
            _ => TransactionType::ClientNonInvite,
        };
        Transaction::new(tx_type, key, original, connection, endpoint_inner)
    }

    pub fn new_server(
        key: TransactionKey,
        original: Request,
        endpoint_inner: EndpointInnerRef,
        connection: Option<SipConnection>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite | Method::Ack => TransactionType::ServerInvite,
            _ => TransactionType::ServerNonInvite,
        };
        Transaction::new(tx_type, key, original, connection, endpoint_inner)
    }
    // send client request
    #[instrument(skip(self))]
    pub async fn send(&mut self) -> Result<()> {
        let span = self.span.clone();
        let _enter = span.enter();
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => {}
            _ => {
                return Err(Error::TransactionError(
                    "send is only valid for client transactions".to_string(),
                    self.key.clone(),
                ));
            }
        }

        if let None = self.connection {
            let connection = self
                .endpoint_inner
                .transport_layer
                .lookup(&self.original.uri)
                .await?;
            self.connection.replace(connection.clone());
        }

        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;
        let content_length_header = Header::ContentLength(ContentLength::from(self.original.body().len() as u32));
        self.original.headers_mut().unique_push(content_length_header);
        connection
            .send(self.original.to_owned().into(), self.destination.as_ref())
            .await?;
        self.transition(TransactionState::Trying).map(|_| ())
    }

    pub async fn reply_with(
        &mut self,
        status_code: StatusCode,
        headers: Vec<rsip::Header>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut resp = self
            .endpoint_inner
            .make_response(&self.original, status_code, body);
        resp.headers.extend(headers);
        match resp.status_code.kind() {
            rsip::StatusCodeKind::Provisional => {}
            _ => {
                let to = self.original.to_header()?;
                if to.tag()?.is_none() {
                    self.original
                        .headers
                        .unique_push(to.clone().with_tag(make_tag())?.into());
                }
            }
        }
        self.respond(resp).await
    }
    /// Quick reply with status code
    #[instrument(skip(self))]
    pub async fn reply(&mut self, status_code: StatusCode) -> Result<()> {
        self.reply_with(status_code, vec![], None).await
    }
    // send server response
    #[instrument(skip(self, response))]
    pub async fn respond(&mut self, response: Response) -> Result<()> {
        let span = self.span.clone();
        let _enter = span.or_current();
        match self.transaction_type {
            TransactionType::ServerInvite | TransactionType::ServerNonInvite => {}
            _ => {
                return Err(Error::TransactionError(
                    "respond is only valid for server transactions".to_string(),
                    self.key.clone(),
                ));
            }
        }

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
        // check an transition to new state
        self.can_transition(&new_state)?;

        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;
        debug!("responding with {}", response);
        connection
            .send(response.to_owned().into(), self.destination.as_ref())
            .await?;
        self.last_response.replace(response);
        self.transition(new_state).map(|_| ())
    }

    fn can_transition(&self, target: &TransactionState) -> Result<()> {
        match (&self.state, target) {
            (&TransactionState::Calling, &TransactionState::Trying)
            | (&TransactionState::Calling, &TransactionState::Proceeding)
            | (&TransactionState::Calling, &TransactionState::Completed)
            | (&TransactionState::Calling, &TransactionState::Terminated)
            | (&TransactionState::Trying, &TransactionState::Trying) // retransmission
            | (&TransactionState::Trying, &TransactionState::Proceeding)
            | (&TransactionState::Trying, &TransactionState::Completed)
            | (&TransactionState::Trying, &TransactionState::Confirmed)
            | (&TransactionState::Trying, &TransactionState::Terminated)
            | (&TransactionState::Proceeding, &TransactionState::Completed)
            | (&TransactionState::Proceeding, &TransactionState::Confirmed)
            | (&TransactionState::Proceeding, &TransactionState::Terminated)
            | (&TransactionState::Completed, &TransactionState::Confirmed)
            | (&TransactionState::Completed, &TransactionState::Terminated)
            | (&TransactionState::Confirmed, &TransactionState::Terminated) => Ok(()),
            _ => {
                return Err(Error::TransactionError(
                    format!(
                        "invalid state transition from {:?} to {:?}",
                        self.state, target
                    ),
                    self.key.clone(),
                ));
            }
        }
    }
    #[instrument(skip(self, cancel))]
    pub async fn send_cancel(&mut self, cancel: Request) -> Result<()> {
        let span = self.span.clone();
        let _enter = span.or_current();
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_cancel is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Calling | TransactionState::Trying | TransactionState::Proceeding => {
                if let Some(connection) = &self.connection {
                    connection
                        .send(cancel.to_owned().into(), self.destination.as_ref())
                        .await?;
                }
                self.transition(TransactionState::Terminated).map(|_| ())
            }
            _ => {
                return Err(Error::TransactionError(
                    format!("invalid state for sending CANCEL {:?}", self.state),
                    self.key.clone(),
                ));
            }
        }
    }
    #[instrument(skip(self, ack))]
    pub async fn send_ack(&mut self, ack: Request) -> Result<()> {
        let span = self.span.clone();
        let _enter = span.or_current();
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_ack is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;

        match self.state {
            TransactionState::Completed => {} // must be in completed state, to send ACK
            _ => {
                return Err(Error::TransactionError(
                    format!("invalid state for sending ACK {:?}", self.state),
                    self.key.clone(),
                ));
            }
        }

        connection
            .send(ack.to_owned().into(), self.destination.as_ref())
            .await?;
        self.last_ack.replace(ack);
        // client send ack and transition to Terminated
        self.transition(TransactionState::Terminated).map(|_| ())
    }

    pub async fn receive(&mut self) -> Option<SipMessage> {
        let span = self.span.clone();
        let _enter = span.enter();
        while let Some(event) = self.tu_receiver.recv().await {
            match event {
                TransactionEvent::Received(msg, connection) => {
                    if let Some(msg) = match msg {
                        SipMessage::Request(req) => self.on_received_request(req, connection).await,
                        SipMessage::Response(resp) => self.on_received_response(resp).await,
                    } {
                        return Some(msg);
                    }
                }
                TransactionEvent::Timer(t) => {
                    self.on_timer(t).await.ok();
                }
                TransactionEvent::Respond(response) => {
                    self.respond(response).await.ok();
                }
                TransactionEvent::Terminate => {
                    info!("received terminate event");
                    return None;
                }
            }
        }
        None
    }

    pub async fn send_trying(&mut self) -> Result<()> {
        let span = self.span.clone();
        let _enter = span.or_current();
        let response =
            self.endpoint_inner
                .make_response(&self.original, rsip::StatusCode::Trying, None);
        self.respond(response).await
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
    }
}

impl Transaction {
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
        connection: Option<SipConnection>,
    ) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => return None,
            _ => {}
        }

        if self.connection.is_none() && connection.is_some() {
            self.connection = connection;
        }

        if req.method == Method::Cancel {
            match self.state {
                TransactionState::Proceeding
                | TransactionState::Trying
                | TransactionState::Completed => {
                    if let Some(connection) = &self.connection {
                        let resp = self
                            .endpoint_inner
                            .make_response(&req, StatusCode::OK, None);
                        connection
                            .send(resp.into(), self.destination.as_ref())
                            .await
                            .ok();
                    }
                    return Some(req.into()); // into dialog
                }
                _ => {
                    if let Some(connection) = &self.connection {
                        let resp = self.endpoint_inner.make_response(
                            &req,
                            StatusCode::CallTransactionDoesNotExist,
                            None,
                        );
                        connection
                            .send(resp.into(), self.destination.as_ref())
                            .await
                            .ok();
                    }
                }
            };
            return None;
        }

        match self.state {
            TransactionState::Trying | TransactionState::Proceeding => {
                // retransmission of last response
                if let Some(last_response) = &self.last_response {
                    self.respond(last_response.to_owned()).await.ok();
                }
            }
            TransactionState::Completed => {
                if req.method == Method::Ack {
                    self.transition(TransactionState::Confirmed).ok();
                    return Some(req.into());
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

        let new_state = match resp.status_code.kind() {
            rsip::StatusCodeKind::Provisional => {
                if resp.status_code == rsip::StatusCode::Trying {
                    TransactionState::Trying
                } else {
                    TransactionState::Proceeding
                }
            }
            _ => {
                if self.transaction_type == TransactionType::ClientInvite {
                    TransactionState::Completed
                } else {
                    TransactionState::Terminated
                }
            }
        };

        self.can_transition(&new_state).ok()?;
        if self.state == new_state {
            // ignore duplicate response
            return None;
        }

        self.last_response.replace(resp.clone());
        self.transition(new_state).ok();
        return Some(SipMessage::Response(resp));
    }

    async fn on_timer(&mut self, timer: TransactionTimer) -> Result<()> {
        match self.state {
            TransactionState::Trying => {
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if let TransactionTimer::TimerA(key, duration) = timer {
                        // Resend the INVITE request
                        if let Some(connection) = &self.connection {
                            connection
                                .send(self.original.to_owned().into(), self.destination.as_ref())
                                .await?;
                        }
                        // Restart Timer A with an upper limit
                        let duration = (duration * 2).min(self.endpoint_inner.t1x64);
                        let timer_a = self
                            .endpoint_inner
                            .timers
                            .timeout(duration, TransactionTimer::TimerA(key, duration));
                        self.timer_a.replace(timer_a);
                    } else if let TransactionTimer::TimerB(_) = timer {
                        // Inform TU about timeout
                        let timeout_response = self.endpoint_inner.make_response(
                            &self.original,
                            rsip::StatusCode::RequestTimeout,
                            None,
                        );
                        self.inform_tu_response(timeout_response)?;
                    }
                }
            }
            TransactionState::Proceeding => {
                if let TransactionTimer::TimerB(_) = timer {
                    // Inform TU about timeout
                    let timeout_response = self.endpoint_inner.make_response(
                        &self.original,
                        rsip::StatusCode::RequestTimeout,
                        None,
                    );
                    self.inform_tu_response(timeout_response)?;
                }
            }
            TransactionState::Completed => {
                if let TransactionTimer::TimerG(key, duration) = timer {
                    // resend the response
                    if let Some(last_response) = &self.last_response {
                        if let Some(connection) = &self.connection {
                            connection
                                .send(last_response.to_owned().into(), self.destination.as_ref())
                                .await?;
                        }
                    }
                    // restart Timer G with an upper limit
                    let duration = (duration * 2).min(self.endpoint_inner.t1x64);
                    let timer_g = self
                        .endpoint_inner
                        .timers
                        .timeout(duration, TransactionTimer::TimerG(key, duration));
                    self.timer_g.replace(timer_g);
                } else if let TransactionTimer::TimerD(_) = timer {
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
                let connection = self.connection.as_ref().ok_or(Error::TransactionError(
                    "no connection found".to_string(),
                    self.key.clone(),
                ))?;

                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if !connection.is_reliable() {
                        self.timer_a
                            .take()
                            .map(|id| self.endpoint_inner.timers.cancel(id));
                        self.timer_a.replace(self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.t1,
                            TransactionTimer::TimerA(self.key.clone(), self.endpoint_inner.t1),
                        ));
                    }
                }

                self.timer_b
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_b.replace(self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.t1x64,
                    TransactionTimer::TimerB(self.key.clone()),
                ));
            }
            TransactionState::Proceeding => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                // start Timer B
                let timer_b = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.t1x64,
                    TransactionTimer::TimerB(self.key.clone()),
                );
                self.timer_b.replace(timer_b);
            }
            TransactionState::Completed => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_b
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));

                if self.transaction_type == TransactionType::ServerInvite {
                    // start Timer G for server invite only
                    let connection = self.connection.as_ref().ok_or(Error::TransactionError(
                        "no connection found".to_string(),
                        self.key.clone(),
                    ))?;
                    if !connection.is_reliable() {
                        let timer_g = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.t1,
                            TransactionTimer::TimerG(self.key.clone(), self.endpoint_inner.t1),
                        );
                        self.timer_g.replace(timer_g);
                    }
                }

                // start Timer D
                let timer_d = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.t1x64,
                    TransactionTimer::TimerD(self.key.clone()),
                );
                self.timer_d.replace(timer_d);
            }
            TransactionState::Confirmed => {
                self.cleanup_timer();
                // start Timer K, wait for ACK
                let timer_k = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.t4,
                    TransactionTimer::TimerK(self.key.clone()),
                );
                self.timer_k.replace(timer_k);
            }
            TransactionState::Terminated => {
                self.cleanup();
                self.tu_sender.send(TransactionEvent::Terminate).ok(); // tell TU to terminate
            }
        }
        debug!("transition: {:?} -> {:?}", self.state, state);
        self.state = state;
        Ok(self.state.clone())
    }

    fn cleanup_timer(&mut self) {
        self.timer_a
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_b
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_d
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_k
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_g
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
    }

    fn cleanup(&mut self) {
        if self.is_cleaned_up {
            return;
        }
        self.is_cleaned_up = true;
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
        self.endpoint_inner
            .detach_transaction(&self.key, last_message);
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.cleanup();
        let _enter = self.span.enter();
        info!("transaction dropped");
    }
}
