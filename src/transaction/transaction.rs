use super::endpoint::EndpointInnerRef;
use super::key::TransactionKey;
use super::{SipConnection, TransactionState, TransactionTimer, TransactionType};
use crate::dialog::DialogId;
use crate::platform::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use crate::prelude::*;
use crate::sip::{
    ContentLength, HasHeaders, Header, HeadersExt, Method, Request, Response, SipMessage,
    StatusCode, StatusCodeKind,
};
use crate::transaction::key::TransactionRole;
use crate::transaction::make_tag;
use crate::transport::SipAddr;
use crate::{Error, Result};
use tracing::{debug, trace, warn};

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
/// use rsipstack::sip::SipMessage;
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

/// Create a no-op TU sender (drops all messages).
///
/// Useful for restoring dialogs after restart when a real transaction-user channel
/// is not available yet.
pub fn transaction_event_sender_noop() -> TransactionEventSender {
    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    let (tx, mut rx) = unbounded_channel::<TransactionEvent>();
    crate::platform::spawn(async move {
        while let Some(_ev) = rx.recv().await {
            // drop
        }
    });
    tx
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
/// use rsipstack::sip::SipMessage;
///
/// # async fn example() -> rsipstack::Result<()> {
/// # let endpoint_inner = todo!();
/// # let connection = None;
/// // Create a mock request
/// let request = rsipstack::sip::Request {
///     method: rsipstack::sip::Method::Register,
///     uri: rsipstack::sip::Uri::try_from("sip:example.com")?,
///     headers: vec![
///         rsipstack::sip::Header::Via("SIP/2.0/UDP example.com:5060;branch=z9hG4bKnashds".into()),
///         rsipstack::sip::Header::CSeq("1 REGISTER".into()),
///         rsipstack::sip::Header::From("Alice <sip:alice@example.com>;tag=1928301774".into()),
///         rsipstack::sip::Header::CallId("a84b4c76e66710@pc33.atlanta.com".into()),
///     ].into(),
///     version: rsipstack::sip::Version::V2,
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
    pub timer_g: Option<u64>, // server invite only (non-2xx final response retransmits per RFC 6026 §7.1)
    pub timer_l: Option<u64>, // server invite only (Accepted-state 64*T1 per RFC 6026 §7.1)
    pub timer_m: Option<u64>, // client invite only (Accepted-state 64*T1 per RFC 6026 §7.2)
    retransmission: bool,
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
            retransmission: true,
            timer_l: None,
            timer_m: None,
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

        let lookup_result = if self.connection.is_none() {
            let target_uri = self.resolve_target_uri().await?;

            Some(
                self.endpoint_inner
                    .transport_layer
                    .lookup(&target_uri, Some(&self.key))
                    .await,
            )
        } else {
            None
        };

        // Apply successful lookup result before before_send
        // so inspectors see the resolved destination address
        if let Some(Ok((connection, resolved_addr))) = &lookup_result {
            self.connection.replace(connection.clone());
            self.destination.replace(resolved_addr.clone());
        }

        // RFC 5626 flow affinity: when the request is bound to an existing
        // reliable connection (e.g. a WebSocket/WSS flow reused for in-dialog
        // requests), no transport lookup happens and `destination` would stay
        // None. Inspectors (sipflow src/dst recording) and senders need the
        // real peer address, so derive it from the flow itself instead of
        // falling back to the unresolvable Request-URI (RFC 7118 `.invalid`
        // contacts) or a wildcard listener default.
        if self.destination.is_none() {
            if let Some(connection) = self.connection.as_ref() {
                if connection.is_reliable() {
                    if let Some(remote_addr) = connection.get_remote_addr() {
                        debug!(key = %self.key, destination = %remote_addr, "destination from affinity connection");
                        self.destination.replace(remote_addr.clone());
                    }
                }
            }
        }

        let content_length_header =
            Header::ContentLength(ContentLength::from(self.original.body().len() as u32));
        self.original
            .headers_mut()
            .unique_push(content_length_header);

        let message = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(self.original.to_owned().into(), self.destination.as_ref())
        } else {
            self.original.to_owned().into()
        };

        // Try to send if we have a connection; log errors instead of returning
        // so the transaction always enters the state machine (Calling) and
        // timers (Timer A / Timer B) handle retries and timeouts.
        let mut stream_failed = false;
        if let Some(connection) = self.connection.as_ref() {
            if let Err(e) = connection.send(message, self.destination.as_ref()).await {
                warn!(key = %self.key, error = %e, "send failed");
                stream_failed = connection.is_stream();
            }
        } else {
            debug!(key = %self.key, "no connection, will retry on timer");
        }

        // Always transition to Calling — the transaction enters the state machine
        // even when transport is unavailable. Timer A will retry the send (and
        // redo the transport lookup if needed), and Timer B handles timeout.
        self.transition(TransactionState::Calling)?;
        if stream_failed {
            self.on_stream_send_failure()?;
        }
        Ok(())
    }

    /// A write on a stream connection (TCP/TLS/WS) failed. Nothing will ever
    /// retransmit the request on it (no Timer A on reliable transports), so
    /// instead of leaving the TU to wait for Timer B/F: retire the dead
    /// connection, so later requests to the peer do not pick it again, and
    /// report the failure to the TU as a local 503 (RFC 3261 §17.1.4,
    /// §8.1.3.1).
    fn on_stream_send_failure(&mut self) -> Result<()> {
        if let Some(connection) = self.connection.as_ref() {
            self.endpoint_inner
                .transport_layer
                .retire_connection(connection);
        }
        let response =
            self.endpoint_inner
                .make_response(&self.original, StatusCode::ServiceUnavailable, None);
        self.inform_tu_response(response)
    }

    /// Resolve the target URI for sending a request.
    ///
    /// Uses the same rule as `send()`: if `self.destination` is set, use it;
    /// otherwise consult the locator, then fall back to the request URI.
    /// Resolve the target URI for sending a request.
    ///
    /// Priority: self.destination (pre-set by dialog) >
    /// Request::destination() (first Route or request URI) + locator fallback.
    async fn resolve_target_uri(&self) -> Result<SipAddr> {
        match &self.destination {
            Some(addr) => Ok(addr.clone()),
            None => {
                let dest = self.original.destination();
                if let Some(locator) = self.endpoint_inner.locator.as_ref() {
                    locator.locate(&dest).await
                } else {
                    SipAddr::try_from(&dest)
                }
            }
        }
    }

    pub async fn reply_with(
        &mut self,
        status_code: StatusCode,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        match status_code.kind() {
            StatusCodeKind::Provisional => {}
            _ => {
                let to = self.original.to_header()?;
                if to.tag()?.is_none() {
                    self.original
                        .headers
                        .unique_push(to.clone().with_tag(make_tag()).into());
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
    /// Send a server response.
    ///
    /// Validates the state transition, sends the response through the
    /// transaction's connection, stores it as `last_response`, and
    /// transitions the state machine. The response routing follows
    /// RFC 3261 §17.2.1 + RFC 6026 §7.1 (server INVITE 2xx → Accepted;
    /// server INVITE 3xx-6xx → Completed; server non-INVITE → Terminated).
    ///
    /// # Errors
    /// Returns `Error::TransactionError` if:
    /// - the transaction is a client transaction (`respond` is server-only),
    /// - the requested transition is not allowed by `can_transition`,
    /// - the connection is missing,
    /// - the underlying transport send fails.
    ///
    /// # Cancel safety
    ///
    /// **NOT cancel-safe.** The mutation order is: store `last_response`
    /// (and, for a server INVITE 2xx, add its ACK route) → `await` the
    /// transport send → transition the state machine. If the
    /// future is dropped during the `await`, the ACK route is removed
    /// again but `last_response` will already
    /// be updated while the response may have been only partially
    /// transmitted (or not at all) and the state did not advance. If it
    /// is dropped between the send completing and the transition, the
    /// response is on the wire but the transaction remains in the previous
    /// state and subsequent timer-driven retransmits may fire incorrectly.
    /// Drive `respond` from an owning task; do not place it directly
    /// inside `tokio::select!` / `tokio::time::timeout` unless this hazard
    /// is acceptable. Prefer the `TransactionEvent::Respond` channel for
    /// cancellation-aware integration.
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
            StatusCodeKind::Provisional => match response.status_code {
                StatusCode::Trying => TransactionState::Trying,
                _ => TransactionState::Proceeding,
            },
            StatusCodeKind::Successful => match self.transaction_type {
                // RFC 6026 §7.1: server INVITE 2xx routes to Accepted, NOT
                // Completed. Pre-RFC-6026 behaviour incorrectly used the
                // Completed state — that triggered Timer G 2xx retransmits
                // (forbidden by §7.1) and used Timer K (T4 ≈ 5s) as the
                // effective ACK window instead of Timer L (64*T1 ≈ 32s),
                // causing spurious failures on proxy-chain ACK fan-in.
                TransactionType::ServerInvite => TransactionState::Accepted,
                // ServerNonInvite 2xx → Terminated (no ACK expected).
                _ => TransactionState::Terminated,
            },
            // Non-2xx final response (3xx, 4xx, 5xx, 6xx): RFC 3261 §17.2.1
            // semantics retained — server INVITE → Completed (waits for
            // ACK + Timer K + Timer D); server non-INVITE → Terminated.
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
            inspector.before_send(
                response.clone().to_owned().into(),
                self.destination.as_ref(),
            )
        } else {
            response.to_owned().into()
        };
        trace!(key = %self.key, response = %response, "responding");

        match response.clone() {
            SipMessage::Response(resp) => self.last_response.replace(resp),
            _ => None,
        };
        // The peer can ACK the 2xx before the transition below runs: add
        // the route the ACK takes (new branch, matched by dialog and CSeq)
        // before sending, so that ACK waits in this transaction's queue.
        // The guard removes it again if the send fails or is cancelled.
        let ack_route = self
            .last_response
            .as_ref()
            .filter(|_| {
                new_state == TransactionState::Accepted && self.state != TransactionState::Accepted
            })
            .and_then(|resp| DialogId::try_from((resp, TransactionRole::Server)).ok())
            .and_then(|dialog_id| self.add_ack_cseq_route(&dialog_id));
        let mut guard = AckRouteGuard(
            ack_route.map(|route| (self.endpoint_inner.clone(), route, self.key.clone())),
        );
        connection.send(response, self.destination.as_ref()).await?;
        guard.0 = None;
        self.transition(new_state).map(|_| ())
    }

    fn add_ack_cseq_route(&self, dialog_id: &DialogId) -> Option<(DialogId, u32)> {
        let seq = self.original.cseq_header().and_then(|c| c.seq()).ok()?;
        let route = (dialog_id.clone(), seq);
        self.endpoint_inner
            .waiting_ack_cseq
            .insert(route.clone(), self.key.clone());
        Some(route)
    }

    fn can_transition(&self, target: &TransactionState) -> Result<()> {
        match (&self.state, target) {
            (&TransactionState::Nothing, &TransactionState::Calling)
            | (&TransactionState::Nothing, &TransactionState::Trying)
            | (&TransactionState::Nothing, &TransactionState::Proceeding)
            | (&TransactionState::Nothing, &TransactionState::Terminated)
            | (&TransactionState::Calling, &TransactionState::Calling)
            | (&TransactionState::Calling, &TransactionState::Trying)
            | (&TransactionState::Calling, &TransactionState::Proceeding)
            | (&TransactionState::Calling, &TransactionState::Accepted) // RFC 6026 §7.2
            | (&TransactionState::Calling, &TransactionState::Completed)
            | (&TransactionState::Calling, &TransactionState::Terminated)
            | (&TransactionState::Trying, &TransactionState::Trying) // retransmission
            | (&TransactionState::Trying, &TransactionState::Proceeding)
            | (&TransactionState::Trying, &TransactionState::Accepted) // RFC 6026 §7.1/§7.2
            | (&TransactionState::Trying, &TransactionState::Completed)
            | (&TransactionState::Trying, &TransactionState::Confirmed)
            | (&TransactionState::Trying, &TransactionState::Terminated)
            | (&TransactionState::Proceeding, &TransactionState::Proceeding)
            | (&TransactionState::Proceeding, &TransactionState::Accepted) // RFC 6026 §7.1/§7.2
            | (&TransactionState::Proceeding, &TransactionState::Completed)
            | (&TransactionState::Proceeding, &TransactionState::Confirmed)
            | (&TransactionState::Proceeding, &TransactionState::Terminated)
            | (&TransactionState::Accepted, &TransactionState::Accepted) // RFC 6026 §7.1: absorb 2xx retransmits
            | (&TransactionState::Accepted, &TransactionState::Terminated) // RFC 6026 §7.1/§7.2: Timer L/M fires
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
                        inspector.before_send(cancel.to_owned().into(), self.destination.as_ref())
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

    /// Send an ACK for a final response on a client INVITE transaction.
    ///
    /// Constructs the ACK from `last_ack` (cached) or `last_response` +
    /// the original INVITE, resolves the destination (Contact for 2xx
    /// per RFC 3261 §13.2.2.4; Via/Record-Route for 3xx-6xx per §17.1.1.3),
    /// and sends through either the supplied `connection` argument or, for
    /// 2xx responses, a transport-layer connection looked up from the
    /// resolved Contact. For connection-oriented transports the ACK reuses
    /// the flow the response arrived on (RFC 7118 §5) instead of dialing
    /// the Record-Route/Contact target. The ACK is recorded as `last_ack`
    /// regardless of send outcome.
    ///
    /// State transitions per RFC 6026 §7.2 + RFC 3261 §17.1.1.3:
    /// - Completed (3xx-6xx): transitions to Terminated.
    /// - Accepted (2xx): no transition (Timer M drives Termination so
    ///   the §7.2 server-retransmitted-2xx absorption window is preserved).
    ///
    /// # Errors
    /// Returns `Error::TransactionError` if:
    /// - the transaction is not a client INVITE,
    /// - the state is neither Completed nor Accepted,
    /// - no `last_response` and no `last_ack` is available,
    /// - destination resolution or transport send fails.
    ///
    /// # Cancel safety
    ///
    /// **NOT cancel-safe.** This method has multiple `.await` points
    /// (locator lookup, transport lookup, transport send) interleaved
    /// with `last_ack` mutation and state transition. If the future is
    /// dropped between the ACK transmission and the state transition,
    /// the ACK will have been sent but the transaction state will remain
    /// in Completed/Accepted. The next inbound message may trigger
    /// inappropriate retransmits. Do not place inside `tokio::select!`
    /// unless this hazard is acceptable.
    pub async fn send_ack(&mut self, mut connection: Option<SipConnection>) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_ack is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Completed | TransactionState::Accepted => {} // RFC 3261 §17.1.1 (Completed, 3xx-6xx) or RFC 6026 §7.2 (Accepted, 2xx)
            _ => {
                return Err(Error::TransactionError(
                    format!("invalid state for sending ACK {:?}", self.state),
                    self.key.clone(),
                ));
            }
        }
        let ack = match self.last_ack.clone() {
            // A retransmission of the same 2xx re-uses the cached ACK. A
            // forked 2xx (different To tag) establishes a different dialog
            // (RFC 3261 §13.2.2.4): rebuild the ACK from that response so it
            // carries its To tag, remote target and route set (§12.2.1.1).
            // Non-2xx finals have a single branch — the cached ACK always
            // matches there.
            Some(ack) if Self::cached_ack_matches_response(&ack, self.last_response.as_ref()) => {
                ack
            }
            _ => {
                let resp = self.last_response.as_ref().ok_or(Error::TransactionError(
                    "no last response found to send ACK".to_string(),
                    self.key.clone(),
                ))?;
                self.endpoint_inner.make_ack(&self.original, resp)?
            }
        };

        // Capture locator + transport lookup result
        // so before_send is called regardless of lookup outcome
        if let Some(resp) = self.last_response.as_ref() {
            if resp.status_code.kind() == StatusCodeKind::Successful {
                // Per RFC 7118 §5 and general connection-oriented transport handling,
                // the 2xx ACK must reuse the existing flow the response arrived on
                // instead of dialing the Record-Route/Contact target (which may be
                // unreachable from the client) via lookup(). Only resolve a new
                // destination for UDP (connectionless) or when no connection is given.
                let reuse_existing = connection
                    .as_ref()
                    .map(|conn| conn.is_reliable())
                    .unwrap_or(false);

                if !reuse_existing {
                    // 2xx response, set destination from request
                    let target = ack.destination();
                    let addr = match self.endpoint_inner.locator.as_ref() {
                        Some(locator) => match locator.locate(&target).await {
                            Ok(addr) => Some(addr),
                            Err(e) => {
                                warn!(key = %self.key, error = %e, "ack locator failed");
                                None
                            }
                        },
                        None => (&target).try_into().ok(),
                    };
                    if let Some(addr) = addr {
                        match self
                            .endpoint_inner
                            .transport_layer
                            .lookup(&addr, Some(&self.key))
                            .await
                        {
                            Ok((via_connection, resolved_addr)) => {
                                // For UDP, we need to store the resolved destination address
                                if !via_connection.is_reliable() {
                                    self.destination.replace(resolved_addr);
                                }
                                connection = Some(via_connection);
                            }
                            Err(e) => {
                                warn!(key = %self.key, error = %e, "ack lookup failed");
                            }
                        }
                    }
                }
            }
        }

        let ack = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(ack.to_owned().into(), self.destination.as_ref())
        } else {
            ack.to_owned().into()
        };

        match ack.clone() {
            SipMessage::Request(ref ack_req) => self.last_ack.replace(ack_req.clone()),
            _ => None,
        };

        // Try to send if we have a connection; log errors instead of propagating
        // so the transaction always transitions to Terminated.
        if let Some(ref conn) = connection {
            if let Err(e) = conn.send(ack, self.destination.as_ref()).await {
                warn!(key = %self.key, error = %e, "ack send failed");
            }
        } else {
            debug!(key = %self.key, "no connection for ack");
        }
        // RFC 3261 §17.1.1.3 / RFC 6026 §7.2: ACK in Completed (3xx-6xx)
        // immediately terminates the client transaction. ACK in Accepted
        // (2xx) leaves the transaction in Accepted to absorb server-
        // retransmitted 2xx duplicates per §7.2; Timer M drives the
        // eventual transition to Terminated. Returning Ok(()) here lets
        // the caller observe a successful ACK send without forcing a
        // premature transition.
        if self.state == TransactionState::Completed {
            self.transition(TransactionState::Terminated).map(|_| ())
        } else {
            debug_assert_eq!(
                self.state,
                TransactionState::Accepted,
                "send_ack reached post-send dispatch in unexpected state; the entry guard restricts to Completed|Accepted",
            );
            Ok(())
        }
    }

    /// Receive the next SIP message routed to this transaction.
    ///
    /// Loops on the transaction's TU receiver, dispatching incoming
    /// requests/responses through `on_received_request` /
    /// `on_received_response`, processing timer events via `on_timer`,
    /// and forwarding `Respond` events through `respond`. Returns
    /// `Some(msg)` when a request/response should be propagated to the
    /// dialog/TU layer; returns `None` when the transaction is
    /// terminated by a `Terminate` event or the underlying channel
    /// closes.
    ///
    /// INVITE 2xx responses containing another Via hop are delivered without
    /// an automatic ACK, including retransmissions. Forwarding applications
    /// should retain the transaction and keep receiving until this returns None;
    /// the cleanup deadline is measured from the first such final response.
    ///
    /// # Cancel safety
    ///
    /// **NOT cancel-safe.** State mutations may occur around any inner
    /// `.await` — for example, an incoming response is passed to
    /// `on_received_response` which transitions state and stores
    /// `last_response` BEFORE the message is returned to the caller.
    /// If the future is dropped between those mutations and the
    /// `return Some(msg)`, the TU will not observe the response while
    /// the transaction has already advanced state. Drive
    /// `Transaction::receive` from an owning task; do not place it
    /// directly inside `tokio::select!` / `tokio::time::timeout` unless
    /// dropped state is acceptable. If timeout is required, prefer a
    /// dedicated cancellation channel that the transaction itself
    /// observes via `TransactionEvent::Terminate`.
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
                    debug!(%key, "received terminate event");
                    return None;
                }
            }
        }
        None
    }

    /// Stop request retransmissions while keeping the transaction alive to
    /// consume a provisional or final response already in flight.
    pub(crate) fn stop_retransmissions(&mut self) {
        self.retransmission = false;
        self.timer_a
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
    }

    pub async fn send_trying(&mut self) -> Result<()> {
        let response = self
            .endpoint_inner
            .make_response(&self.original, StatusCode::Trying, None);
        self.respond(response).await
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
    }
}

impl Transaction {
    fn inform_tu_response(&mut self, response: Response) -> Result<()> {
        let msg = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.after_received(SipMessage::Response(response), None)
        } else {
            SipMessage::Response(response)
        };
        self.tu_sender
            .send(TransactionEvent::Received(msg, None))
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
            let forward_to_tu = match self.state {
                TransactionState::Proceeding | TransactionState::Trying => true,
                // RFC 3261 Section 9.2: after a final response, CANCEL has no
                // effect on the original request, its responses, or session state.
                // A 2xx keeps the transaction in Accepted (RFC 6026 §7.1).
                TransactionState::Completed
                | TransactionState::Confirmed
                | TransactionState::Accepted => false,
                _ => {
                    if let Some(connection) = &self.connection {
                        let resp = self.endpoint_inner.make_response(
                            &req,
                            StatusCode::CallTransactionDoesNotExist,
                            None,
                        );
                        let resp =
                            if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                                inspector.before_send(resp.into(), self.destination.as_ref())
                            } else {
                                resp.into()
                            };

                        connection.send(resp, self.destination.as_ref()).await.ok();
                    }
                    return None;
                }
            };

            if let Some(connection) = &self.connection {
                let resp = self.endpoint_inner.make_cancel_response(
                    &req,
                    StatusCode::OK,
                    self.last_response.as_ref(),
                );
                let resp = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                    inspector.before_send(resp.into(), self.destination.as_ref())
                } else {
                    resp.into()
                };
                connection.send(resp, self.destination.as_ref()).await.ok();
            }
            return forward_to_tu.then(|| req.into());
        }

        match self.state {
            TransactionState::Trying | TransactionState::Proceeding => {
                // retransmission of last response
                if let Some(last_response) = &self.last_response {
                    self.respond(last_response.to_owned()).await.ok();
                }
            }
            TransactionState::Accepted => {
                // RFC 6026 §7.1: server INVITE Accepted state.
                //
                // ACK received: pass to TU; remain in Accepted (transition to
                // Terminated is driven by Timer L expiry, not by ACK arrival
                // — §7.1 'Timer L reflects the amount of time the server
                // transaction could receive 2xx responses for retransmission
                // from the TU while it is waiting to receive an ACK').
                //
                // INVITE retransmit: silently absorbed. Per §7.1 the server
                // transaction MUST NOT retransmit the 2xx on its own (only
                // the TU does, via respond()), so re-firing respond() here
                // would re-issue the 2xx through the transport AND trigger
                // a no-op Accepted-self-loop transition. Just drop.
                //
                // As in Completed/Confirmed, an ACK carries the CSeq number
                // of the INVITE it acknowledges (RFC 3261 §13.2.2.4): a
                // delayed ACK of an earlier re-INVITE routed here through
                // `waiting_ack` must not be delivered to the TU of this
                // transaction.
                if req.method == Method::Ack {
                    let ack_seq = req.cseq_header().and_then(|c| c.seq()).ok();
                    let invite_seq = self.original.cseq_header().and_then(|c| c.seq()).ok();
                    if ack_seq != invite_seq {
                        debug!(
                            key = %self.key,
                            ?ack_seq,
                            ?invite_seq,
                            "ignoring ACK with a CSeq that does not match the INVITE"
                        );
                        return None;
                    }
                    // The peer confirmed the dialog: stop the 2xx
                    // retransmissions (RFC 3261 §13.3.1.4) and end the
                    // transaction. Retransmitted ACKs and late INVITE
                    // retransmissions are absorbed below the TU by
                    // `finished_transactions`.
                    self.transition(TransactionState::Terminated).ok();
                    return Some(req.into());
                }
            }
            TransactionState::Completed | TransactionState::Confirmed
                if req.method == Method::Ack =>
            {
                // RFC 3261 §17.1.1.3 / §13.2.2.4: an ACK carries the CSeq
                // number of the INVITE it acknowledges. ACKs for 2xx are
                // routed by dialog and CSeq (`waiting_ack_cseq`); one with
                // another CSeq that lands here anyway must not confirm this
                // transaction or stop its 2xx retransmissions.
                let ack_seq = req.cseq_header().and_then(|c| c.seq()).ok();
                let invite_seq = self.original.cseq_header().and_then(|c| c.seq()).ok();
                if ack_seq != invite_seq {
                    debug!(
                        key = %self.key,
                        ?ack_seq,
                        ?invite_seq,
                        "ignoring ACK with a CSeq that does not match the INVITE"
                    );
                    return None;
                }
                self.transition(TransactionState::Confirmed).ok();
                return Some(req.into());
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
        if self.transaction_type == TransactionType::ClientInvite
            && resp.status_code.kind() == StatusCodeKind::Successful
            && resp.has_multiple_vias()
        {
            // A response with an upstream Via belongs to a forwarding transaction.
            // Its TU must receive every 2xx, including retransmissions and forks,
            // and the originating UA owns the ACK. Keep the first Timer M deadline
            // (RFC 6026 §7.2 Accepted window).
            if self.state != TransactionState::Accepted {
                self.can_transition(&TransactionState::Accepted).ok()?;
                self.transition(TransactionState::Accepted).ok()?;
            }
            self.last_response.replace(resp.clone());
            return Some(SipMessage::Response(resp));
        }
        let new_state = match resp.status_code.kind() {
            StatusCodeKind::Provisional => {
                if resp.status_code == StatusCode::Trying {
                    TransactionState::Trying
                } else {
                    TransactionState::Proceeding
                }
            }
            StatusCodeKind::Successful => {
                if self.transaction_type == TransactionType::ClientInvite {
                    if !self.endpoint_inner.option.auto_ack_2xx {
                        // auto_ack_2xx = false (proxy mode): a 2xx terminates
                        // the client INVITE transaction at once; the ACK is
                        // the TU's job (RFC 3261 section 17.1.1.2).
                        TransactionState::Terminated
                    } else {
                        // RFC 6026 §7.2: client INVITE 2xx routes to Accepted
                        // with Timer M = 64*T1 as the server-retransmitted-2xx
                        // absorption window. The convenience auto-ACK still
                        // fires below (rsipstack 0.5.x UA behavior; the strict
                        // §7.2 TU-owned ACK can be had with auto_ack_2xx =
                        // false).
                        TransactionState::Accepted
                    }
                } else {
                    TransactionState::Terminated
                }
            }
            _ => {
                // 3xx-6xx final response: RFC 3261 §17.1.1 unchanged.
                if self.transaction_type == TransactionType::ClientInvite {
                    TransactionState::Completed
                } else {
                    TransactionState::Terminated
                }
            }
        };

        self.can_transition(&new_state).ok()?;

        // RFC 6026 §7.2: every 2xx response received by a client INVITE in
        // the Accepted state MUST be passed to the TU — both genuine
        // server-retransmitted 2xx (which the TU/dialog re-acknowledges)
        // and forked 2xx (which can share status code + body but differ
        // in To-tag and so identify a different dialog). The pre-existing
        // duplicate-suppression filter below is correct for non-INVITE
        // transactions where the TU has no use for duplicates, but applying
        // it to the Accepted self-loop would silently swallow forked dialogs
        // and prevent the legacy auto-ACK from re-firing per retransmit.
        let is_client_invite_2xx_in_accepted = self.transaction_type
            == TransactionType::ClientInvite
            && new_state == TransactionState::Accepted;

        if !is_client_invite_2xx_in_accepted && self.state == new_state {
            if let Some(last) = self.last_response.as_ref() {
                // A reliable provisional (RFC 3262) with a new RSeq is a new
                // response even when status and body repeat; the TU must
                // see it to send the PRACK (RFC 3261 section 17.1.1.2).
                if last.status_code == resp.status_code
                    && last.body == resp.body
                    && last.rseq_value() == resp.rseq_value()
                {
                    // ignore duplicate response
                    return None;
                }
            }
        }

        self.last_response.replace(resp.clone());
        // Auto-ACK gate. Pre-RFC-6026 this fired only for new_state ==
        // Completed (which captured both 2xx and 3xx-6xx in the old routing).
        // Post-RFC-6026 split: 2xx → Accepted, 3xx-6xx → Completed. Both
        // states still benefit from the convenience auto-ACK; the transaction
        // layer constructs and sends the ACK via send_ack below. send_ack
        // transitions Completed → Terminated (RFC 3261 §17.1.1) but leaves
        // Accepted alone so Timer M can fire and the §7.2 2xx-retransmit
        // absorption window is preserved.
        let auto_ack_client_invite = self.transaction_type == TransactionType::ClientInvite
            && (new_state == TransactionState::Completed
                || new_state == TransactionState::Accepted);

        self.transition(new_state).ok();

        if auto_ack_client_invite {
            if let Err(e) = self.send_ack(connection).await {
                warn!(
                    key = %self.key,
                    state = %self.state,
                    error = %e,
                    "auto-ACK for client INVITE final response failed; downstream TU may need to handle ACK explicitly",
                );
            }
        }

        Some(SipMessage::Response(resp))
    }

    /// Retransmit `last_response` and re-arm Timer G with a doubled interval
    /// capped at T2 (RFC 3261 §13.3.1.4 / §17.2.1). Used by both the
    /// Completed (non-2xx) and Accepted (2xx) Timer G arms.
    async fn retransmit_last_response(
        &mut self,
        key: &TransactionKey,
        duration: &Duration,
    ) -> Result<()> {
        if let Some(last_response) = &self.last_response {
            if let Some(connection) = &self.connection {
                let last_response =
                    if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                        inspector
                            .before_send(last_response.to_owned().into(), self.destination.as_ref())
                    } else {
                        last_response.to_owned().into()
                    };
                connection
                    .send(last_response, self.destination.as_ref())
                    .await?;
            }
        }
        let duration = (*duration * 2).min(self.endpoint_inner.option.t2);
        let timer_g = self
            .endpoint_inner
            .timers
            .timeout(duration, TransactionTimer::TimerG(key.clone(), duration));
        self.timer_g.replace(timer_g);
        Ok(())
    }

    async fn on_timer(&mut self, timer: TransactionTimer) -> Result<()> {
        match self.state {
            TransactionState::Calling | TransactionState::Trying => {
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if let TransactionTimer::TimerA(key, duration) = timer {
                        if !self.retransmission {
                            return Ok(());
                        }
                        // If no connection (initial lookup failed), retry transport lookup
                        // using the same target resolution rule as send()
                        if self.connection.is_none() {
                            if let Ok(target) = self.resolve_target_uri().await {
                                if let Ok((connection, resolved_addr)) = self
                                    .endpoint_inner
                                    .transport_layer
                                    .lookup(&target, Some(&self.key))
                                    .await
                                {
                                    self.connection.replace(connection);
                                    self.destination.replace(resolved_addr);
                                }
                            }
                        }

                        // Resend the request if connection available
                        if let Some(connection) = &self.connection {
                            let retry_message = if let Some(ref inspector) =
                                self.endpoint_inner.message_inspector
                            {
                                inspector.before_send(
                                    self.original.to_owned().into(),
                                    self.destination.as_ref(),
                                )
                            } else {
                                self.original.to_owned().into()
                            };
                            if let Err(e) = connection
                                .send(retry_message, self.destination.as_ref())
                                .await
                            {
                                warn!(key = %self.key, error = %e, "timer A resend failed");
                                if connection.is_stream() {
                                    return self.on_stream_send_failure();
                                }
                            }
                        } else {
                            debug!(key = %self.key, "timer A: no connection yet");
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
                            StatusCode::RequestTimeout,
                            None,
                        );
                        self.inform_tu_response(timeout_response)?;
                    }
                }
            }
            TransactionState::Proceeding => {
                // Timer C (client INVITE), or Timer F, run as Timer B, for a
                // non-INVITE client (RFC 3261 §17.1.2.2).
                if matches!(timer, TransactionTimer::TimerC(_))
                    || (matches!(timer, TransactionTimer::TimerB(_))
                        && self.transaction_type == TransactionType::ClientNonInvite)
                {
                    // Inform TU about timeout
                    let timeout_response = self.endpoint_inner.make_response(
                        &self.original,
                        StatusCode::RequestTimeout,
                        None,
                    );
                    self.inform_tu_response(timeout_response)?;
                }
            }
            TransactionState::Completed => {
                if let TransactionTimer::TimerG(key, duration) = timer {
                    // resend the response (non-2xx final — RFC 3261 §17.2.1;
                    // 2xx finals route to Accepted, never here)
                    self.retransmit_last_response(&key, &duration).await?;
                } else if let TransactionTimer::TimerD(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                } else if let TransactionTimer::TimerK(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                }
            }
            TransactionState::Accepted => {
                // RFC 6026 §7.1 (server INVITE Timer L) / §7.2 (client INVITE
                // Timer M): on expiry the transaction transitions to
                // Terminated. Timer L is server-only per §7.1; Timer M is
                // client-only per §7.2 — mismatched pairings indicate a
                // programming bug and are logged for visibility.
                //
                // Timer G (server): retransmit the 2xx with the interval
                // doubling up to T2 (RFC 3261 §13.3.1.4) — see the
                // documented Timer G deviation on the Accepted entry.
                // Stray Timer A/B/C/D/K/Cleanup firings are race remnants
                // from prior states (the Accepted-state entry handler
                // cancels them, but fire-in-flight races are possible);
                // listed explicitly so future timer additions force
                // compile-time review here.
                match (&self.transaction_type, &timer) {
                    (TransactionType::ServerInvite, TransactionTimer::TimerL(_))
                    | (TransactionType::ClientInvite, TransactionTimer::TimerM(_)) => {
                        self.transition(TransactionState::Terminated)?;
                    }
                    (TransactionType::ServerInvite, TransactionTimer::TimerG(key, duration)) => {
                        // retransmit the 2xx (documented Timer G deviation,
                        // doubling up to T2 — RFC 3261 §13.3.1.4)
                        self.retransmit_last_response(key, &duration).await?;
                    }
                    (
                        TransactionType::ClientNonInvite
                        | TransactionType::ServerNonInvite
                        | TransactionType::ClientInvite,
                        TransactionTimer::TimerG(_, _),
                    ) => {
                        warn!(
                            key = %self.key,
                            tx_type = %self.transaction_type,
                            "Timer G fired outside the server Accepted state; ignoring",
                        );
                    }
                    (_, TransactionTimer::TimerL(_) | TransactionTimer::TimerM(_)) => {
                        warn!(
                            key = %self.key,
                            tx_type = %self.transaction_type,
                            "RFC 6026 Accepted-state timer fired with mismatched transaction type",
                        );
                    }
                    (_, TransactionTimer::TimerA(_, _))
                    | (_, TransactionTimer::TimerB(_))
                    | (_, TransactionTimer::TimerC(_))
                    | (_, TransactionTimer::TimerD(_))
                    | (_, TransactionTimer::TimerK(_))
                    | (_, TransactionTimer::TimerCleanup(_)) => {}
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
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    match self.connection.as_ref() {
                        Some(connection) if !connection.is_reliable() => {
                            // Unreliable transport: start Timer A for retransmission
                            let timer_a = self.endpoint_inner.timers.timeout(
                                self.endpoint_inner.option.t1,
                                TransactionTimer::TimerA(
                                    self.key.clone(),
                                    self.endpoint_inner.option.t1,
                                ),
                            );
                            self.timer_a.replace(timer_a);
                        }
                        None => {
                            // No connection yet (e.g., DNS lookup failed).
                            // Start Timer A to retry transport lookup + send.
                            let timer_a = self.endpoint_inner.timers.timeout(
                                self.endpoint_inner.option.t1,
                                TransactionTimer::TimerA(
                                    self.key.clone(),
                                    self.endpoint_inner.option.t1,
                                ),
                            );
                            self.timer_a.replace(timer_a);
                        }
                        _ => {} // Reliable transport: no Timer A needed
                    }
                    self.timer_b.replace(self.endpoint_inner.timers.timeout(
                        self.endpoint_inner.option.t1x64,
                        TransactionTimer::TimerB(self.key.clone()),
                    ));
                }
            }
            TransactionState::Trying | TransactionState::Proceeding => {
                self.timer_a.take().map(|id| -> Option<TransactionTimer> {
                    self.endpoint_inner.timers.cancel(id)
                });
                if matches!(self.transaction_type, TransactionType::ClientInvite) {
                    self.timer_b.take().map(|id| -> Option<TransactionTimer> {
                        self.endpoint_inner.timers.cancel(id)
                    });
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
            TransactionState::Accepted => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_b
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_c
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));

                match self.transaction_type {
                    TransactionType::ServerInvite => {
                        // RFC 6026 §7.1: server INVITE 2xx-Accepted entry.
                        //
                        // Start Timer L (64*T1). On expiry the transaction
                        // transitions to Terminated (handled in on_timer for
                        // the Accepted state).
                        //
                        // Register the dialog in `waiting_ack` so the dialog
                        // layer can route the ACK for this 2xx back to this
                        // transaction key.
                        //
                        // Timer G deviation (documented in lib.rs): strict
                        // §7.1 leaves 2xx retransmission to the TU; the
                        // rsipstack dialog layer does not retransmit, so the
                        // transaction keeps Timer G (T1, doubling to T2) on
                        // every transport — the wire behavior RFC 3261
                        // §13.3.1.4 requires — until the ACK or Timer L.
                        let timer_l = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.t1x64,
                            TransactionTimer::TimerL(self.key.clone()),
                        );
                        self.timer_l.replace(timer_l);

                        let timer_g = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.t1,
                            TransactionTimer::TimerG(
                                self.key.clone(),
                                self.endpoint_inner.option.t1,
                            ),
                        );
                        self.timer_g.replace(timer_g);

                        if let Some(ref resp) = self.last_response {
                            let dialog_id = DialogId::try_from((resp, TransactionRole::Server))?;
                            // Route the ACK by dialog AND INVITE CSeq: the ACK
                            // of an earlier re-INVITE can arrive after a newer
                            // one was answered, and must reach its own
                            // transaction (RFC 3261 §13.2.2.4). A non-2xx ACK
                            // matches by branch (§17.2.3) — unreachable here,
                            // Accepted only carries 2xx. `respond` adds the
                            // CSeq route before sending the 2xx (an ACK can
                            // arrive before this transition).
                            self.add_ack_cseq_route(&dialog_id);
                            self.endpoint_inner
                                .waiting_ack
                                .insert(dialog_id, self.key.clone());
                        }
                        debug!(
                            key = %self.key,
                            "entered Accepted state (server); Timer L and Timer G armed, waiting for ACK"
                        );
                    }
                    TransactionType::ClientInvite => {
                        // RFC 6026 §7.2: client INVITE 2xx-Accepted entry.
                        //
                        // Start Timer M (64*T1). On expiry the transaction
                        // transitions to Terminated. While in Accepted, the
                        // client absorbs server-retransmitted 2xx responses
                        // (these are forwarded to the TU as duplicates and
                        // ignored by the transaction state machine itself —
                        // see Accepted-self-loop edge in can_transition).
                        //
                        // Strict RFC 3261 §17.1.1.3 + RFC 6026 §7.2 make
                        // the ACK for 2xx the TU's responsibility. For
                        // rsipstack 0.5.x backward compatibility, the
                        // auto_ack_client_invite gate at the tail of
                        // on_received_response still emits that ACK after
                        // entering Accepted; see lib.rs Standards Compliance
                        // for the disclaimer. 3xx-6xx ACKs continue to be
                        // sent by the transaction layer through the
                        // Completed → Terminated path.
                        let timer_m = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.t1x64,
                            TransactionTimer::TimerM(self.key.clone()),
                        );
                        self.timer_m.replace(timer_m);
                        debug!(
                            key = %self.key,
                            "entered Accepted state (client); Timer M armed, awaiting expiry or 2xx retransmits"
                        );
                    }
                    _ => {
                        // Non-INVITE transactions never reach Accepted per
                        // RFC 6026 §4. can_transition() should have already
                        // rejected this; treat as a programming error.
                        return Err(Error::TransactionError(
                            format!(
                                "Accepted state is INVITE-only (transaction type was {})",
                                self.transaction_type
                            ),
                            self.key.clone(),
                        ));
                    }
                }
            }
            TransactionState::Completed => {
                self.timer_a.take().map(|id| -> Option<TransactionTimer> {
                    self.endpoint_inner.timers.cancel(id)
                });
                self.timer_b.take().map(|id| -> Option<TransactionTimer> {
                    self.endpoint_inner.timers.cancel(id)
                });
                self.timer_c.take().map(|id| -> Option<TransactionTimer> {
                    self.endpoint_inner.timers.cancel(id)
                });

                if self.transaction_type == TransactionType::ServerInvite {
                    // start Timer G for server invite only. Completed only
                    // carries non-2xx finals (2xx route to Accepted), so
                    // Timer G retransmits on unreliable transports only
                    // (RFC 3261 §17.2.1); reliable transports need no
                    // response retransmission.
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
                    debug!(key=%self.key, last = self.last_response.is_none(), "entered confirmed state, waiting for ACK");
                    if let Some(ref resp) = self.last_response {
                        let dialog_id = DialogId::try_from((resp, TransactionRole::Server))?;
                        self.endpoint_inner
                            .waiting_ack
                            .insert(dialog_id, self.key.clone());
                    }
                    // Wait for the ACK until Timer D (64*T1) — Timer H for a
                    // non-2xx (RFC 3261 §17.2.1). Timer G keeps retransmitting.
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
                // ACK was received; remove waiting_ack entry since it's no longer needed.
                if self.transaction_type == TransactionType::ServerInvite {
                    if let Some(ref resp) = self.last_response {
                        if let Ok(dialog_id) = DialogId::try_from((resp, self.role())) {
                            self.endpoint_inner.forget_waiting_ack(
                                dialog_id,
                                &self.original,
                                &self.key,
                            );
                        }
                    }
                }
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
            from = %self.state,
            to = %state,
            "transition"
        );
        self.state = state;
        Ok(self.state.clone())
    }

    fn cleanup_timer(&mut self) {
        self.timer_a
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_b
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_c
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_d
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_k
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_g
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_l
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
        self.timer_m
            .take()
            .map(|id| -> Option<TransactionTimer> { self.endpoint_inner.timers.cancel(id) });
    }

    /// Whether the cached ACK acknowledges the response currently stored in
    /// `last_response`: true when the tags match (a retransmission) — a
    /// different tag means a forked 2xx that needs its own ACK.
    fn cached_ack_matches_response(ack: &Request, resp: Option<&Response>) -> bool {
        let Some(resp) = resp else {
            return true;
        };
        let ack_tag = ack
            .to_header()
            .ok()
            .and_then(|h| h.tag().ok())
            .flatten()
            .map(|t| t.value().to_string());
        let resp_tag = resp
            .to_header()
            .ok()
            .and_then(|h| h.tag().ok())
            .flatten()
            .map(|t| t.value().to_string());
        match (ack_tag, resp_tag) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }

    pub fn role(&self) -> TransactionRole {
        match self.transaction_type {
            crate::transaction::TransactionType::ClientInvite
            | crate::transaction::TransactionType::ClientNonInvite => TransactionRole::Client,
            crate::transaction::TransactionType::ServerInvite
            | crate::transaction::TransactionType::ServerNonInvite => TransactionRole::Server,
        }
    }

    fn cleanup(&mut self) {
        if self.is_cleaned_up {
            return;
        }
        self.is_cleaned_up = true;
        self.cleanup_timer();

        // For ServerInvite in Completed state, keep the waiting_ack entry
        // so that incoming ACK can still be routed and absorbed by finished_transactions.
        // Confirmed state means the ACK was already received, so the entry is no longer needed.
        let is_server_invite_waiting_ack =
            matches!(self.transaction_type, TransactionType::ServerInvite)
                && self.state == TransactionState::Completed;
        if !is_server_invite_waiting_ack {
            if let Some(Ok(dialog_id)) = self
                .last_response
                .as_ref()
                .map(|resp| DialogId::try_from((resp, self.role())))
            {
                self.endpoint_inner
                    .forget_waiting_ack(dialog_id, &self.original, &self.key);
            }
        }

        let last_message = {
            match self.transaction_type {
                TransactionType::ClientInvite => {
                    //
                    // For client invite, make a placeholder ACK if in proceeding or trying state
                    if matches!(
                        self.state,
                        TransactionState::Proceeding | TransactionState::Trying
                    ) && self.last_ack.is_none()
                    {
                        if let Some(ref resp) = self.last_response {
                            // auto_ack_2xx = false (proxy mode): store no ACK
                            // for a 2xx, so retransmitted 2xx fall through
                            // to the TU instead of being absorbed or re-ACKed
                            // here (RFC 3261 section 17.1.1.2).
                            let auto_ack = self.endpoint_inner.option.auto_ack_2xx
                                || resp.status_code.kind() != StatusCodeKind::Successful;
                            if auto_ack {
                                if let Ok(ack) = self.endpoint_inner.make_ack(&self.original, resp)
                                {
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
                // Kept: the matching ACK terminates an Accepted server
                // INVITE before the dialog reads the 2xx for
                // `DialogState::Confirmed`.
                TransactionType::ServerInvite => {
                    self.last_response.clone().map(SipMessage::Response)
                }
                _ => None,
            }
        };
        self.endpoint_inner
            .detach_transaction(&self.key, last_message);
    }
}

/// A 2xx ACK route added by `respond` before the send; removed on drop
/// unless disarmed once the send completed.
struct AckRouteGuard(Option<(EndpointInnerRef, (DialogId, u32), TransactionKey)>);

impl Drop for AckRouteGuard {
    fn drop(&mut self) {
        if let Some((endpoint_inner, route, key)) = self.0.take() {
            endpoint_inner.waiting_ack_cseq.with_mut(|m| {
                if m.get(&route) == Some(&key) {
                    m.remove(&route);
                }
            });
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.cleanup();
        trace!(key=%self.key, state=%self.state, "transaction dropped");
    }
}
