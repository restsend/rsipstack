use super::endpoint::EndpointInnerRef;
use super::key::TransactionKey;
use super::{SipConnection, TransactionState, TransactionTimer, TransactionType};
use crate::dialog::DialogId;
use crate::rsip_ext::{destination_from_request, RsipResponseExt};
use crate::transaction::make_tag;
use crate::transport::SipAddr;
use crate::{Error, Result};
use rsip::headers::ContentLength;
use rsip::message::HasHeaders;
use rsip::prelude::HeadersExt;
use rsip::{Header, Method, Request, Response, SipMessage, StatusCode, StatusCodeKind};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, trace};

pub type TransactionEventReceiver = UnboundedReceiver<TransactionEvent>;
pub type TransactionEventSender = UnboundedSender<TransactionEvent>;

/// SIP Transaction Events
///
/// `TransactionEvent` represents the various events that can occur during
/// a SIP transaction's lifecycle. These events drive the transaction state machine
/// and coordinate between the transaction layer and transaction users.
///
/// # Events
///
/// * `Received` - A SIP message was received for this transaction
/// * `Timer` - A transaction timer has fired
/// * `Respond` - Request to send a response (server transactions only)
/// * `Terminate` - Request to terminate the transaction
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transaction::transaction::TransactionEvent;
/// use rsip::SipMessage;
///
/// # fn handle_event(event: TransactionEvent) {
/// match event {
///     TransactionEvent::Received(msg, conn) => {
///         // Process received SIP message
///     },
///     TransactionEvent::Timer(timer) => {
///         // Handle timer expiration
///     },
///     TransactionEvent::Respond(response) => {
///         // Send response
///     },
///     TransactionEvent::Terminate(key) => {
///         // Clean up transaction
///     }
/// }
/// # }
/// ```
pub enum TransactionEvent {
    Received(SipMessage, Option<SipConnection>),
    Timer(TransactionTimer),
    Respond(Response),
    Terminate(TransactionKey),
}

/// SIP Transaction
///
/// `Transaction` implements the SIP transaction layer as defined in RFC 3261.
/// A transaction consists of a client transaction (sends requests) or server
/// transaction (receives requests) that handles the reliable delivery of SIP
/// messages and manages retransmissions and timeouts.
///
/// # Key Features
///
/// * Automatic retransmission handling
/// * Timer management per RFC 3261
/// * State machine implementation
/// * Reliable message delivery
/// * Connection management
///
/// # Transaction Types
///
/// * `ClientInvite` - Client INVITE transaction
/// * `ClientNonInvite` - Client non-INVITE transaction  
/// * `ServerInvite` - Server INVITE transaction
/// * `ServerNonInvite` - Server non-INVITE transaction
///
/// # State Machine
///
/// Transactions follow the state machines defined in RFC 3261:
/// * Calling → Trying → Proceeding → Completed → Terminated
/// * Additional states for INVITE transactions: Confirmed
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transaction::{
///     transaction::Transaction,
///     key::{TransactionKey, TransactionRole}
/// };
/// use rsip::SipMessage;
///
/// # async fn example() -> rsipstack::Result<()> {
/// # let endpoint_inner = todo!();
/// # let connection = None;
/// // Create a mock request
/// let request = rsip::Request {
///     method: rsip::Method::Register,
///     uri: rsip::Uri::try_from("sip:example.com")?,
///     headers: vec![
///         rsip::Header::Via("SIP/2.0/UDP example.com:5060;branch=z9hG4bKnashds".into()),
///         rsip::Header::CSeq("1 REGISTER".into()),
///         rsip::Header::From("Alice <sip:alice@example.com>;tag=1928301774".into()),
///         rsip::Header::CallId("a84b4c76e66710@pc33.atlanta.com".into()),
///     ].into(),
///     version: rsip::Version::V2,
///     body: Default::default(),
/// };
/// let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
///
/// // Create a client transaction
/// let mut transaction = Transaction::new_client(
///     key,
///     request,
///     endpoint_inner,
///     connection
/// );
///
/// // Send the request
/// transaction.send().await?;
///
/// // Receive responses
/// while let Some(message) = transaction.receive().await {
///     match message {
///         SipMessage::Response(response) => {
///             // Handle response
///         },
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Timer Handling
///
/// The transaction automatically manages SIP timers:
/// * Timer A: Retransmission timer for unreliable transports
/// * Timer B: Transaction timeout timer
/// * Timer D: Wait time for response retransmissions
/// * Timer E: Non-INVITE retransmission timer
/// * Timer F: Non-INVITE transaction timeout
/// * Timer G: INVITE response retransmission timer
/// * Timer K: Wait time for ACK
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
    pub timer_c: Option<u64>,
    pub timer_d: Option<u64>,
    pub timer_k: Option<u64>, // server invite only
    pub timer_g: Option<u64>, // server invite only
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
        let state = if matches!(
            transaction_type,
            TransactionType::ServerInvite | TransactionType::ServerNonInvite
        ) {
            TransactionState::Trying
        } else {
            TransactionState::Nothing
        };
        trace!(%key, %state, "transaction created");
        let tx = Self {
            transaction_type,
            endpoint_inner,
            connection,
            key,
            original,
            destination: None,
            state,
            last_response: None,
            last_ack: None,
            timer_a: None,
            timer_b: None,
            timer_c: None,
            timer_d: None,
            timer_k: None,
            timer_g: None,
            tu_receiver,
            tu_sender,
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

        if self.connection.is_none() {
            let target_uri = match &self.destination {
                Some(addr) => addr,
                None => {
                    if let Some(locator) = self.endpoint_inner.locator.as_ref() {
                        &locator.locate(&self.original.uri).await?
                    } else {
                        &SipAddr::try_from(&self.original.uri)?
                    }
                }
            };

            let (connection, resolved_addr) = self
                .endpoint_inner
                .transport_layer
                .lookup(target_uri, Some(&self.key))
                .await?;
            // For UDP, we need to store the resolved destination address
            if !connection.is_reliable() {
                self.destination.replace(resolved_addr);
            }
            self.connection.replace(connection);
        }

        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;
        let content_length_header =
            Header::ContentLength(ContentLength::from(self.original.body().len() as u32));
        self.original
            .headers_mut()
            .unique_push(content_length_header);

        let message = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(self.original.to_owned().into())
        } else {
            self.original.to_owned().into()
        };

        connection.send(message, self.destination.as_ref()).await?;
        self.transition(TransactionState::Calling).map(|_| ())
    }

    pub async fn reply_with(
        &mut self,
        status_code: StatusCode,
        headers: Vec<rsip::Header>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        match status_code.kind() {
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
        let mut resp = self
            .endpoint_inner
            .make_response(&self.original, status_code, body);
        resp.headers.extend(headers);
        self.respond(resp).await
    }
    /// Quick reply with status code
    pub async fn reply(&mut self, status_code: StatusCode) -> Result<()> {
        self.reply_with(status_code, vec![], None).await
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

        let response = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(response.clone().to_owned().into())
        } else {
            response.to_owned().into()
        };
        trace!(key = %self.key, "responding with {}", response);

        match response.clone() {
            SipMessage::Response(resp) => self.last_response.replace(resp),
            _ => None,
        };
        connection.send(response, self.destination.as_ref()).await?;
        self.transition(new_state).map(|_| ())
    }

    fn can_transition(&self, target: &TransactionState) -> Result<()> {
        match (&self.state, target) {
            (&TransactionState::Nothing, &TransactionState::Calling)
            | (&TransactionState::Nothing, &TransactionState::Trying)
            | (&TransactionState::Nothing, &TransactionState::Proceeding)
            | (&TransactionState::Nothing, &TransactionState::Terminated)
            | (&TransactionState::Calling, &TransactionState::Trying)
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
                Err(Error::TransactionError(
                    format!(
                        "invalid state transition from {} to {}",
                        self.state, target
                    ),
                    self.key.clone(),
                ))
            }
        }
    }
    pub async fn send_cancel(&mut self, cancel: Request) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_cancel is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Calling | TransactionState::Trying | TransactionState::Proceeding => {
                if let Some(connection) = &self.connection {
                    let cancel = if let Some(ref inspector) = self.endpoint_inner.message_inspector
                    {
                        inspector.before_send(cancel.to_owned().into())
                    } else {
                        cancel.to_owned().into()
                    };

                    connection.send(cancel, self.destination.as_ref()).await?;
                }
                Ok(())
            }
            _ => Err(Error::TransactionError(
                format!("invalid state for sending CANCEL {:?}", self.state),
                self.key.clone(),
            )),
        }
    }

    pub async fn send_ack(&mut self, connection: Option<SipConnection>) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_ack is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Completed => {} // must be in completed state, to send ACK
            _ => {
                return Err(Error::TransactionError(
                    format!("invalid state for sending ACK {:?}", self.state),
                    self.key.clone(),
                ));
            }
        }
        let ack = match self.last_ack.clone() {
            Some(ack) => ack,
            None => match self.last_response {
                Some(ref resp) => {
                    let request_uri = resp
                        .remote_uri(self.destination.as_ref())
                        .unwrap_or_else(|_| self.original.uri.clone());
                    self.endpoint_inner.make_ack(resp, request_uri)?
                }
                None => {
                    return Err(Error::TransactionError(
                        "no last response found to send ACK".to_string(),
                        self.key.clone(),
                    ));
                }
            },
        };

        let ack = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(ack.to_owned().into())
        } else {
            ack.to_owned().into()
        };

        let mut connection = connection;
        if let SipMessage::Request(ref req) = ack {
            if let Some(resp) = self.last_response.as_ref() {
                if resp.status_code.kind() == StatusCodeKind::Successful {
                    // 2xx response, set destination from request
                    let target = match destination_from_request(&req) {
                        Some(target) => {
                            if let Some(locator) = self.endpoint_inner.locator.as_ref() {
                                Some(locator.locate(&target).await?)
                            } else {
                                target.try_into().ok()
                            }
                        }
                        None => None,
                    };
                    match target {
                        Some(addr) => {
                            let (via_connection, resolved_addr) = self
                                .endpoint_inner
                                .transport_layer
                                .lookup(&addr, Some(&self.key))
                                .await?;
                            // For UDP, we need to store the resolved destination address
                            if !via_connection.is_reliable() {
                                self.destination.replace(resolved_addr);
                            }
                            connection = Some(via_connection);
                        }
                        None => {}
                    }
                }
            }
        }

        match ack.clone() {
            SipMessage::Request(ack) => self.last_ack.replace(ack),
            _ => None,
        };
        if let Some(conn) = connection {
            conn.send(ack, self.destination.as_ref()).await?;
        }
        // client send ack and transition to Terminated
        self.transition(TransactionState::Terminated).map(|_| ())
    }

    pub async fn receive(&mut self) -> Option<SipMessage> {
        while let Some(event) = self.tu_receiver.recv().await {
            match event {
                TransactionEvent::Received(msg, connection) => {
                    if let Some(msg) = match msg {
                        SipMessage::Request(req) => self.on_received_request(req, connection).await,
                        SipMessage::Response(resp) => {
                            self.on_received_response(resp, connection).await
                        }
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
                TransactionEvent::Terminate(key) => {
                    info!(%key, "received terminate event");
                    return None;
                }
            }
        }
        None
    }

    pub async fn send_trying(&mut self) -> Result<()> {
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

                        let resp =
                            if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                                inspector.before_send(resp.into())
                            } else {
                                resp.into()
                            };

                        connection.send(resp, self.destination.as_ref()).await.ok();
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
                        let resp =
                            if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                                inspector.before_send(resp.into())
                            } else {
                                resp.into()
                            };
                        connection.send(resp, self.destination.as_ref()).await.ok();
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
            TransactionState::Completed | TransactionState::Confirmed => {
                if req.method == Method::Ack {
                    self.transition(TransactionState::Confirmed).ok();
                    return Some(req.into());
                }
            }
            _ => {}
        }
        None
    }

    async fn on_received_response(
        &mut self,
        resp: Response,
        connection: Option<SipConnection>,
    ) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ServerInvite | TransactionType::ServerNonInvite => return None,
            _ => {}
        }
        let new_state = match resp.status_code.kind() {
            StatusCodeKind::Provisional => {
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
        self.send_ack(connection).await.ok(); // send ACK for client invite
        Some(SipMessage::Response(resp))
    }

    async fn on_timer(&mut self, timer: TransactionTimer) -> Result<()> {
        match self.state {
            TransactionState::Calling | TransactionState::Trying => {
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if let TransactionTimer::TimerA(key, duration) = timer {
                        // Resend the INVITE request
                        if let Some(connection) = &self.connection {
                            let retry_message = if let Some(ref inspector) =
                                self.endpoint_inner.message_inspector
                            {
                                inspector.before_send(self.original.to_owned().into())
                            } else {
                                self.original.to_owned().into()
                            };
                            connection
                                .send(retry_message, self.destination.as_ref())
                                .await?;
                        }
                        // Restart Timer A with an upper limit
                        let duration = (duration * 2).min(self.endpoint_inner.option.t1x64);
                        let timer_a = self
                            .endpoint_inner
                            .timers
                            .timeout(duration, TransactionTimer::TimerA(key, duration));
                        self.timer_a.replace(timer_a);
                    } else if let TransactionTimer::TimerB(_) = timer {
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
                if let TransactionTimer::TimerC(_) = timer {
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
                            let last_response = if let Some(ref inspector) =
                                self.endpoint_inner.message_inspector
                            {
                                inspector.before_send(last_response.to_owned().into())
                            } else {
                                last_response.to_owned().into()
                            };
                            connection
                                .send(last_response, self.destination.as_ref())
                                .await?;
                        }
                    }
                    // restart Timer G with an upper limit
                    let duration = (duration * 2).min(self.endpoint_inner.option.t1x64);
                    let timer_g = self
                        .endpoint_inner
                        .timers
                        .timeout(duration, TransactionTimer::TimerG(key, duration));
                    self.timer_g.replace(timer_g);
                } else if let TransactionTimer::TimerD(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                } else if let TransactionTimer::TimerK(_) = timer {
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
            TransactionState::Nothing => {}
            TransactionState::Calling => {
                let connection = self.connection.as_ref().ok_or(Error::TransactionError(
                    "no connection found".to_string(),
                    self.key.clone(),
                ))?;

                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if !connection.is_reliable() {
                        let timer_a = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.t1,
                            TransactionTimer::TimerA(
                                self.key.clone(),
                                self.endpoint_inner.option.t1,
                            ),
                        );
                        self.timer_a.replace(timer_a);
                    }
                    self.timer_b.replace(self.endpoint_inner.timers.timeout(
                        self.endpoint_inner.option.t1x64,
                        TransactionTimer::TimerB(self.key.clone()),
                    ));
                }
            }
            TransactionState::Trying | TransactionState::Proceeding => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                if matches!(self.transaction_type, TransactionType::ClientInvite) {
                    self.timer_b
                        .take()
                        .map(|id| self.endpoint_inner.timers.cancel(id));
                    if self.timer_c.is_none() {
                        // start Timer C for client invite only
                        let timer_c = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.timerc,
                            TransactionTimer::TimerC(self.key.clone()),
                        );
                        self.timer_c.replace(timer_c);
                    }
                }
            }
            TransactionState::Completed => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_b
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_c
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
                            self.endpoint_inner.option.t1,
                            TransactionTimer::TimerG(
                                self.key.clone(),
                                self.endpoint_inner.option.t1,
                            ),
                        );
                        self.timer_g.replace(timer_g);
                    }
                    info!(key=%self.key, last = self.last_response.is_none(), "entered confirmed state, waiting for ACK");
                    match self.last_response {
                        Some(ref resp) => {
                            let dialog_id = DialogId::try_from(resp)?;
                            self.endpoint_inner
                                .waiting_ack
                                .write()
                                .as_mut()
                                .map(|wa| wa.insert(dialog_id, self.key.clone()))
                                .ok();
                        }
                        _ => {}
                    }
                    // start Timer K, wait for ACK
                    let timer_k = self.endpoint_inner.timers.timeout(
                        self.endpoint_inner.option.t4,
                        TransactionTimer::TimerK(self.key.clone()),
                    );
                    self.timer_k.replace(timer_k);
                }
                // start Timer D
                let timer_d = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.option.t1x64,
                    TransactionTimer::TimerD(self.key.clone()),
                );
                self.timer_d.replace(timer_d);
            }
            TransactionState::Confirmed => {
                self.cleanup_timer();
                let timer_k = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.option.t4,
                    TransactionTimer::TimerK(self.key.clone()),
                );
                self.timer_k.replace(timer_k);
            }
            TransactionState::Terminated => {
                self.cleanup();
                self.tu_sender
                    .send(TransactionEvent::Terminate(self.key.clone()))
                    .ok(); // tell TU to terminate
            }
        }
        debug!(
            key = %self.key,
            "transition: {:?} -> {:?}", self.state, state
        );
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
        self.timer_c
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

        match self.last_response {
            Some(ref resp) => match DialogId::try_from(resp) {
                Ok(dialog_id) => self
                    .endpoint_inner
                    .waiting_ack
                    .write()
                    .as_mut()
                    .map(|wa| wa.remove(&dialog_id))
                    .ok(),
                Err(_) => None,
            },
            _ => None,
        };

        let last_message = {
            match self.transaction_type {
                TransactionType::ClientInvite => {
                    //
                    // For client invite, make a placeholder ACK if in proceeding or trying state
                    if matches!(
                        self.state,
                        TransactionState::Proceeding | TransactionState::Trying
                    ) {
                        if self.last_ack.is_none() {
                            if let Some(ref resp) = self.last_response {
                                let request_uri = self.original.uri.clone();
                                if let Ok(ack) = self.endpoint_inner.make_ack(resp, request_uri) {
                                    self.last_ack.replace(ack);
                                }
                            }
                        }
                    }
                    self.last_ack.take().map(SipMessage::Request)
                }
                TransactionType::ServerNonInvite => {
                    self.last_response.take().map(SipMessage::Response)
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
        trace!(key=%self.key, state=%self.state, "transaction dropped");
    }
}
