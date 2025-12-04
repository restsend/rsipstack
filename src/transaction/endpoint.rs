use super::{
    key::TransactionKey,
    make_via_branch,
    timer::Timer,
    transaction::{Transaction, TransactionEvent, TransactionEventSender},
    SipConnection, TransactionReceiver, TransactionSender, TransactionTimer,
};
use crate::{
    dialog::DialogId,
    transport::{SipAddr, TransportEvent, TransportLayer},
    Error, Result, VERSION,
};
use async_trait::async_trait;
use rsip::{prelude::HeadersExt, SipMessage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    select,
    sync::mpsc::{error, unbounded_channel},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

pub trait MessageInspector: Send + Sync {
    fn before_send(&self, msg: SipMessage) -> SipMessage;
    fn after_received(&self, msg: SipMessage) -> SipMessage;
}

#[async_trait]
pub trait TargetLocator: Send + Sync {
    async fn locate(&self, uri: &rsip::Uri) -> Result<SipAddr>;
}

#[async_trait]
pub trait TransportEventInspector: Send + Sync {
    async fn handle(&self, event: &TransportEvent);
}

pub struct EndpointOption {
    pub t1: Duration,
    pub t4: Duration,
    pub t1x64: Duration,
    pub timerc: Duration,
    pub callid_suffix: Option<String>,
}

impl Default for EndpointOption {
    fn default() -> Self {
        EndpointOption {
            t1: Duration::from_millis(500),
            t4: Duration::from_secs(4),
            t1x64: Duration::from_millis(64 * 500),
            timerc: Duration::from_secs(180),
            callid_suffix: None,
        }
    }
}

pub struct EndpointStats {
    pub running_transactions: usize,
    pub finished_transactions: usize,
    pub waiting_ack: usize,
}

/// SIP Endpoint Core Implementation
///
/// `EndpointInner` is the core implementation of a SIP endpoint that manages
/// transactions, timers, and transport layer communication. It serves as the
/// central coordination point for all SIP protocol operations.
///
/// # Key Responsibilities
///
/// * Managing active SIP transactions
/// * Handling SIP timers (Timer A, B, D, E, F, G, K)
/// * Coordinating with the transport layer
/// * Processing incoming and outgoing SIP messages
/// * Maintaining transaction state and cleanup
///
/// # Fields
///
/// * `allows` - List of supported SIP methods
/// * `user_agent` - User-Agent header value for outgoing messages
/// * `timers` - Timer management system for SIP timers
/// * `transport_layer` - Transport layer for network communication
/// * `finished_transactions` - Cache of completed transactions
/// * `transactions` - Active transaction senders
/// * `incoming_sender` - Channel for incoming transaction notifications
/// * `cancel_token` - Cancellation token for graceful shutdown
/// * `timer_interval` - Interval for timer processing
/// * `t1`, `t4`, `t1x64` - SIP timer values as per RFC 3261
///
/// # Timer Values
///
/// * `t1` - RTT estimate (default 500ms)
/// * `t4` - Maximum duration a message will remain in the network (default 4s)
/// * `t1x64` - Maximum retransmission timeout (default 32s)
pub struct EndpointInner {
    pub allows: Mutex<Option<Vec<rsip::Method>>>,
    pub user_agent: String,
    pub timers: Timer<TransactionTimer>,
    pub transport_layer: TransportLayer,
    pub finished_transactions: RwLock<HashMap<TransactionKey, Option<SipMessage>>>,
    pub transactions: RwLock<HashMap<TransactionKey, TransactionEventSender>>,
    pub waiting_ack: RwLock<HashMap<DialogId, TransactionKey>>,
    incoming_sender: TransactionSender,
    incoming_receiver: Mutex<Option<TransactionReceiver>>,
    cancel_token: CancellationToken,
    #[allow(dead_code)]
    timer_interval: Duration,
    pub(super) message_inspector: Option<Box<dyn MessageInspector>>,
    pub(super) locator: Option<Box<dyn TargetLocator>>,
    pub(super) transport_inspector: Option<Box<dyn TransportEventInspector>>,
    pub option: EndpointOption,
}
pub type EndpointInnerRef = Arc<EndpointInner>;

/// SIP Endpoint Builder
///
/// `EndpointBuilder` provides a fluent interface for constructing SIP endpoints
/// with custom configuration. It follows the builder pattern to allow flexible
/// endpoint configuration.
///
/// # Examples
///
/// ```rust
/// use rsipstack::EndpointBuilder;
/// use std::time::Duration;
///
/// let endpoint = EndpointBuilder::new()
///     .with_user_agent("MyApp/1.0")
///     .with_timer_interval(Duration::from_millis(10))
///     .with_allows(vec![rsip::Method::Invite, rsip::Method::Bye])
///     .build();
/// ```
pub struct EndpointBuilder {
    allows: Vec<rsip::Method>,
    user_agent: String,
    transport_layer: Option<TransportLayer>,
    cancel_token: Option<CancellationToken>,
    timer_interval: Option<Duration>,
    option: Option<EndpointOption>,
    message_inspector: Option<Box<dyn MessageInspector>>,
    target_locator: Option<Box<dyn TargetLocator>>,
    transport_inspector: Option<Box<dyn TransportEventInspector>>,
}

/// SIP Endpoint
///
/// `Endpoint` is the main entry point for SIP protocol operations. It provides
/// a high-level interface for creating and managing SIP transactions, handling
/// incoming requests, and coordinating with the transport layer.
///
/// # Key Features
///
/// * Transaction management and lifecycle
/// * Automatic timer handling per RFC 3261
/// * Transport layer abstraction
/// * Graceful shutdown support
/// * Incoming request processing
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::EndpointBuilder;
/// use tokio_util::sync::CancellationToken;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let endpoint = EndpointBuilder::new()
///         .with_user_agent("MyApp/1.0")
///         .build();
///     
///     // Get incoming transactions
///     let mut incoming = endpoint.incoming_transactions().expect("incoming_transactions");
///     
///     // Start the endpoint
///     let endpoint_inner = endpoint.inner.clone();
///     tokio::spawn(async move {
///          endpoint_inner.serve().await.ok();
///     });
///     
///     // Process incoming transactions
///     while let Some(transaction) = incoming.recv().await {
///         // Handle transaction
///         break; // Exit for example
///     }
///     
///     Ok(())
/// }
/// ```
///
/// # Lifecycle
///
/// 1. Create endpoint using `EndpointBuilder`
/// 2. Start serving with `serve()` method
/// 3. Process incoming transactions via `incoming_transactions()`
/// 4. Shutdown gracefully with `shutdown()`
pub struct Endpoint {
    pub inner: EndpointInnerRef,
}

impl EndpointInner {
    pub fn new(
        user_agent: String,
        transport_layer: TransportLayer,
        cancel_token: CancellationToken,
        timer_interval: Option<Duration>,
        allows: Vec<rsip::Method>,
        option: Option<EndpointOption>,
        message_inspector: Option<Box<dyn MessageInspector>>,
        locator: Option<Box<dyn TargetLocator>>,
        transport_inspector: Option<Box<dyn TransportEventInspector>>,
    ) -> Arc<Self> {
        let (incoming_sender, incoming_receiver) = unbounded_channel();
        Arc::new(EndpointInner {
            allows: Mutex::new(Some(allows)),
            user_agent,
            timers: Timer::new(),
            transport_layer,
            transactions: RwLock::new(HashMap::new()),
            finished_transactions: RwLock::new(HashMap::new()),
            waiting_ack: RwLock::new(HashMap::new()),
            timer_interval: timer_interval.unwrap_or(Duration::from_millis(20)),
            cancel_token,
            incoming_sender,
            incoming_receiver: Mutex::new(Some(incoming_receiver)),
            option: option.unwrap_or_default(),
            message_inspector,
            locator,
            transport_inspector,
        })
    }

    pub async fn serve(self: &Arc<Self>) -> Result<()> {
        select! {
            _ = self.cancel_token.cancelled() => {},
            _ = self.process_timer() => {},
            r = self.clone().process_transport_layer() => {
                _ = r?;
            },
        }
        Ok(())
    }

    // process transport layer, receive message from transport layer
    async fn process_transport_layer(self: Arc<Self>) -> Result<()> {
        self.transport_layer.serve_listens().await.ok();

        let mut transport_rx = match self
            .transport_layer
            .inner
            .transport_rx
            .lock()
            .unwrap()
            .take()
        {
            Some(rx) => rx,
            None => {
                return Err(Error::EndpointError("transport_rx not set".to_string()));
            }
        };

        while let Some(event) = transport_rx.recv().await {
            if let Some(transport_inspector) = &self.transport_inspector {
                transport_inspector.handle(&event).await;
            }

            match event {
                TransportEvent::Incoming(msg, connection, from) => {
                    match self.on_received_message(msg, connection, &from).await {
                        Ok(()) => {}
                        Err(e) => {
                            warn!(addr=%from,"on_received_message error: {}", e);
                        }
                    }
                }
                TransportEvent::New(t) => {
                    info!(addr=%t.get_addr(), "new connection");
                }
                TransportEvent::Closed(t) => {
                    info!(addr=%t.get_addr(), "closed connection");
                }
            }
        }
        Ok(())
    }

    pub async fn process_timer(&self) {
        loop {
            for t in self.timers.wait_for_ready().await.into_iter() {
                match t {
                    TransactionTimer::TimerCleanup(key) => {
                        trace!(%key, "TimerCleanup");
                        self.transactions
                            .write()
                            .as_mut()
                            .map(|ts| ts.remove(&key))
                            .ok();
                        self.finished_transactions
                            .write()
                            .as_mut()
                            .map(|t| t.remove(&key))
                            .ok();
                        continue;
                    }
                    _ => {}
                }

                if let Ok(Some(tu)) =
                    { self.transactions.read().as_ref().map(|ts| ts.get(&t.key())) }
                {
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
        }
    }

    // receive message from transport layer
    pub async fn on_received_message(
        self: &Arc<Self>,
        msg: SipMessage,
        connection: SipConnection,
        from: &SipAddr,
    ) -> Result<()> {
        let mut key = match &msg {
            SipMessage::Request(req) => {
                TransactionKey::from_request(req, super::key::TransactionRole::Server)?
            }
            SipMessage::Response(resp) => {
                TransactionKey::from_response(resp, super::key::TransactionRole::Client)?
            }
        };
        match &msg {
            SipMessage::Request(req) => {
                match req.method() {
                    rsip::Method::Ack => match DialogId::try_from(req) {
                        Ok(dialog_id) => {
                            let tx_key = self
                                .waiting_ack
                                .read()
                                .map(|wa| wa.get(&dialog_id).cloned());
                            if let Ok(Some(tx_key)) = tx_key {
                                key = tx_key;
                            }
                        }
                        Err(_) => {}
                    },
                    _ => {}
                }
                // check is the termination of an existing transaction
                let last_message = self
                    .finished_transactions
                    .read()
                    .unwrap()
                    .get(&key)
                    .cloned()
                    .flatten();

                if let Some(last_message) = last_message {
                    connection.send(last_message, None).await?;
                    return Ok(());
                }
            }
            SipMessage::Response(resp) => {
                let last_message = self
                    .finished_transactions
                    .read()
                    .unwrap()
                    .get(&key)
                    .cloned()
                    .flatten();

                if let Some(mut last_message) = last_message {
                    match last_message {
                        SipMessage::Request(ref mut last_req) => {
                            if last_req.method() == &rsip::Method::Ack {
                                match resp.status_code.kind() {
                                    rsip::StatusCodeKind::Provisional => {
                                        return Ok(());
                                    }
                                    rsip::StatusCodeKind::Successful => {
                                        if last_req.to_header()?.tag().ok().is_none() {
                                            // don't ack 2xx response when ack is placeholder
                                            return Ok(());
                                        }
                                    }
                                    rsip::StatusCodeKind::RequestFailure => {
                                        // for ACK to 487, send it where it came from
                                        connection.send(last_message, Some(from)).await?;
                                        return Ok(());
                                    }
                                    _ => {}
                                }
                                if let Ok(Some(tag)) = resp.to_header()?.tag() {
                                    last_req.to_header_mut().and_then(|h| h.mut_tag(tag)).ok();
                                }
                            }
                        }
                        _ => {}
                    }
                    connection.send(last_message, None).await?;
                    return Ok(());
                }
            }
        };

        let msg = if let Some(inspector) = &self.message_inspector {
            inspector.after_received(msg)
        } else {
            msg
        };

        if let Some(tu) = self.transactions.read().unwrap().get(&key) {
            tu.send(TransactionEvent::Received(msg, Some(connection)))
                .map_err(|e| Error::TransactionError(e.to_string(), key))?;
            return Ok(());
        }
        // if the transaction is not exist, create a new transaction
        let request = match msg {
            SipMessage::Request(req) => req,
            SipMessage::Response(resp) => {
                if resp.cseq_header()?.method()? != rsip::Method::Cancel {
                    debug!(%key, "the transaction is not exist {}", resp);
                }
                return Ok(());
            }
        };

        match request.method {
            rsip::Method::Cancel => {
                let resp = self.make_response(
                    &request,
                    rsip::StatusCode::CallTransactionDoesNotExist,
                    None,
                );
                let resp = if let Some(ref inspector) = self.message_inspector {
                    inspector.before_send(resp.into())
                } else {
                    resp.into()
                };
                connection.send(resp, None).await?;
                return Ok(());
            }
            rsip::Method::Ack => return Ok(()),
            _ => {}
        }

        let tx =
            Transaction::new_server(key.clone(), request.clone(), self.clone(), Some(connection));

        self.incoming_sender.send(tx).ok();
        Ok(())
    }

    pub fn attach_transaction(&self, key: &TransactionKey, tu_sender: TransactionEventSender) {
        trace!(%key, "attach transaction");
        self.transactions
            .write()
            .as_mut()
            .map(|ts| ts.insert(key.clone(), tu_sender))
            .ok();
    }

    pub fn detach_transaction(&self, key: &TransactionKey, last_message: Option<SipMessage>) {
        trace!(%key, "detach transaction");
        self.transactions
            .write()
            .as_mut()
            .map(|ts| ts.remove(key))
            .ok();

        if let Some(msg) = last_message {
            self.timers.timeout(
                self.option.t1x64,
                TransactionTimer::TimerCleanup(key.clone()), // maybe use TimerK ???
            );

            self.finished_transactions
                .write()
                .as_mut()
                .map(|ft| ft.insert(key.clone(), Some(msg)))
                .ok();
        }
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.transport_layer.get_addrs()
    }

    pub fn get_record_route(&self) -> Result<rsip::typed::RecordRoute> {
        let first_addr = self
            .transport_layer
            .get_addrs()
            .first()
            .ok_or(Error::EndpointError("not sipaddrs".to_string()))
            .cloned()?;
        let rr = rsip::UriWithParamsList(vec![rsip::UriWithParams {
            uri: first_addr.into(),
            params: vec![rsip::Param::Other("lr".into(), None)],
        }]);
        Ok(rr.into())
    }

    pub fn get_via(
        &self,
        addr: Option<crate::transport::SipAddr>,
        branch: Option<rsip::Param>,
    ) -> Result<rsip::typed::Via> {
        let first_addr = match addr {
            Some(addr) => addr,
            None => self
                .transport_layer
                .get_addrs()
                .first()
                .ok_or(Error::EndpointError("not sipaddrs".to_string()))
                .cloned()?,
        };

        let via = rsip::typed::Via {
            version: rsip::Version::V2,
            transport: first_addr.r#type.unwrap_or_default(),
            uri: first_addr.addr.into(),
            params: vec![
                branch.unwrap_or_else(make_via_branch),
                rsip::Param::Other("rport".into(), None),
            ],
        };
        Ok(via)
    }

    pub fn get_stats(&self) -> EndpointStats {
        let waiting_ack = self
            .waiting_ack
            .read()
            .map(|wa| wa.len())
            .unwrap_or_default();
        let running_transactions = self
            .transactions
            .read()
            .map(|ts| ts.len())
            .unwrap_or_default();
        let finished_transactions = self
            .finished_transactions
            .read()
            .map(|ft| ft.len())
            .unwrap_or_default();

        EndpointStats {
            running_transactions,
            finished_transactions,
            waiting_ack,
        }
    }
}

impl EndpointBuilder {
    pub fn new() -> Self {
        EndpointBuilder {
            allows: Vec::new(),
            user_agent: VERSION.to_string(),
            transport_layer: None,
            cancel_token: None,
            timer_interval: None,
            option: None,
            message_inspector: None,
            target_locator: None,
            transport_inspector: None,
        }
    }
    pub fn with_option(&mut self, option: EndpointOption) -> &mut Self {
        self.option = Some(option);
        self
    }
    pub fn with_user_agent(&mut self, user_agent: &str) -> &mut Self {
        self.user_agent = user_agent.to_string();
        self
    }

    pub fn with_transport_layer(&mut self, transport_layer: TransportLayer) -> &mut Self {
        self.transport_layer.replace(transport_layer);
        self
    }

    pub fn with_cancel_token(&mut self, cancel_token: CancellationToken) -> &mut Self {
        self.cancel_token.replace(cancel_token);
        self
    }

    pub fn with_timer_interval(&mut self, timer_interval: Duration) -> &mut Self {
        self.timer_interval.replace(timer_interval);
        self
    }
    pub fn with_allows(&mut self, allows: Vec<rsip::Method>) -> &mut Self {
        self.allows = allows;
        self
    }
    pub fn with_inspector(&mut self, inspector: Box<dyn MessageInspector>) -> &mut Self {
        self.message_inspector = Some(inspector);
        self
    }
    pub fn with_target_locator(&mut self, locator: Box<dyn TargetLocator>) -> &mut Self {
        self.target_locator = Some(locator);
        self
    }

    pub fn with_transport_inspector(
        &mut self,
        inspector: Box<dyn TransportEventInspector>,
    ) -> &mut Self {
        self.transport_inspector = Some(inspector);
        self
    }

    pub fn build(&mut self) -> Endpoint {
        let cancel_token = self.cancel_token.take().unwrap_or_default();

        let transport_layer = self
            .transport_layer
            .take()
            .unwrap_or(TransportLayer::new(cancel_token.child_token()));

        let allows = self.allows.to_owned();
        let user_agent = self.user_agent.to_owned();
        let timer_interval = self.timer_interval.to_owned();
        let option = self.option.take();
        let message_inspector = self.message_inspector.take();
        let locator = self.target_locator.take();
        let transport_inspector = self.transport_inspector.take();

        let core = EndpointInner::new(
            user_agent,
            transport_layer,
            cancel_token,
            timer_interval,
            allows,
            option,
            message_inspector,
            locator,
            transport_inspector,
        );

        Endpoint { inner: core }
    }
}

impl Endpoint {
    pub async fn serve(&self) {
        let inner = self.inner.clone();
        match inner.serve().await {
            Ok(()) => {
                info!("endpoint shutdown");
            }
            Err(e) => {
                warn!("endpoint serve error: {:?}", e);
            }
        }
    }

    pub fn shutdown(&self) {
        info!("endpoint shutdown requested");
        self.inner.cancel_token.cancel();
    }

    //
    // get incoming requests from the endpoint
    // don't call repeat!
    pub fn incoming_transactions(&self) -> Result<TransactionReceiver> {
        self.inner
            .incoming_receiver
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::EndpointError("incoming recevier taken".to_string()))
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.inner.transport_layer.get_addrs()
    }
}
