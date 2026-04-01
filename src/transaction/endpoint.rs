use super::{
    key::TransactionKey,
    make_via_branch,
    timer::Timer,
    transaction::{Transaction, TransactionEvent, TransactionEventSender},
    SipConnection, TransactionReceiver, TransactionSender, TransactionTimer,
};
use crate::sip::{prelude::HeadersExt, SipMessage};
use crate::{
    dialog::DialogId,
    transport::{transport_layer::DomainResolver, SipAddr, TransportEvent, TransportLayer},
    Error, Result, VERSION,
};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use tokio::{
    select,
    sync::mpsc::{error, unbounded_channel},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

pub trait MessageInspector: Send + Sync {
    fn before_send(&self, msg: SipMessage, dest: Option<&SipAddr>) -> SipMessage;
    fn after_received(&self, msg: SipMessage, from: &SipAddr) -> SipMessage;
}

#[async_trait]
pub trait TargetLocator: Send + Sync {
    async fn locate(&self, uri: &crate::sip::Uri) -> Result<SipAddr>;
}

#[async_trait]
pub trait TransportEventInspector: Send + Sync {
    async fn handle(&self, event: TransportEvent) -> Option<TransportEvent>;
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
            t4: Duration::from_secs(5),
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
    pub allows: Mutex<Option<Vec<crate::sip::Method>>>,
    pub user_agent: String,
    pub timers: Timer<TransactionTimer>,
    pub transport_layer: TransportLayer,
    pub finished_transactions: DashMap<TransactionKey, Option<SipMessage>>,
    pub transactions: DashMap<TransactionKey, TransactionEventSender>,
    pub waiting_ack: DashMap<DialogId, TransactionKey>,
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
///     .with_allows(vec![rsipstack::sip::Method::Invite, rsipstack::sip::Method::Bye])
///     .build();
/// ```
pub struct EndpointBuilder {
    allows: Vec<crate::sip::Method>,
    user_agent: String,
    transport_layer: Option<TransportLayer>,
    cancel_token: Option<CancellationToken>,
    timer_interval: Option<Duration>,
    option: Option<EndpointOption>,
    message_inspector: Option<Box<dyn MessageInspector>>,
    target_locator: Option<Box<dyn TargetLocator>>,
    transport_inspector: Option<Box<dyn TransportEventInspector>>,
    domain_resolver: Option<Box<dyn DomainResolver>>,
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
        allows: Vec<crate::sip::Method>,
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
            transactions: DashMap::new(),
            finished_transactions: DashMap::new(),
            waiting_ack: DashMap::new(),
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

        let mut transport_rx = match self.transport_layer.inner.transport_rx.lock().take() {
            Some(rx) => rx,
            None => {
                return Err(Error::EndpointError("transport_rx not set".to_string()));
            }
        };

        while let Some(mut event) = transport_rx.recv().await {
            if let Some(transport_inspector) = &self.transport_inspector {
                match transport_inspector.handle(event).await {
                    Some(e) => {
                        event = e;
                    }
                    None => {
                        continue;
                    }
                }
            }

            match event {
                TransportEvent::Incoming(msg, connection, from) => {
                    match self.on_received_message(msg, connection, &from).await {
                        Ok(()) => {}
                        Err(e) => {
                            warn!(addr = %from, error = %e, "on_received_message error");
                        }
                    }
                }
                TransportEvent::New(t) => {
                    debug!(addr=%t.get_addr(), "new connection");
                }
                TransportEvent::Closed(t) => {
                    debug!(addr=%t.get_addr(), "closed connection");
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
                        self.transactions.remove(&key);
                        self.finished_transactions.remove(&key);
                        continue;
                    }
                    _ => {}
                }

                if let Some(tu) = self.transactions.get(&t.key()) {
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

    // Note: This function used for determine destination of response message, from via of the request
    pub async fn get_destination_from_request(&self, req: &crate::sip::Request) -> Option<SipAddr> {
        let (transport, host_with_port) =
            SipConnection::parse_target_from_via(req.via_header().ok()?).ok()?;

        let sip_addr = SipAddr {
            r#type: Some(transport),
            addr: host_with_port,
        };

        if matches!(sip_addr.addr.host, crate::sip::Host::Domain(_)) {
            return self
                .transport_layer
                .inner
                .domain_resolver
                .resolve(&sip_addr)
                .await
                .ok();
        }
        Some(sip_addr)
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
                    crate::sip::Method::Ack => {
                        match DialogId::try_from((req, super::key::TransactionRole::Server)) {
                            Ok(dialog_id) => {
                                if let Some(tx_key) =
                                    self.waiting_ack.get(&dialog_id).map(|v| v.clone())
                                {
                                    key = tx_key;
                                }
                            }
                            Err(_) => {}
                        }
                    }
                    _ => {}
                }
                // check is the termination of an existing transaction
                let last_message = self
                    .finished_transactions
                    .get(&key)
                    .and_then(|v| v.value().clone());

                if let Some(last_message) = last_message {
                    let dest = if !connection.is_reliable() {
                        self.get_destination_from_request(req).await
                    } else {
                        None
                    };
                    connection.send(last_message, dest.as_ref()).await?;
                    return Ok(());
                }
            }
            SipMessage::Response(resp) => {
                let last_message = self
                    .finished_transactions
                    .get(&key)
                    .and_then(|v| v.value().clone());

                if let Some(mut last_message) = last_message {
                    match last_message {
                        SipMessage::Request(ref mut last_req) => {
                            if last_req.method() == &crate::sip::Method::Ack {
                                match resp.status_code.kind() {
                                    crate::sip::StatusCodeKind::Provisional => {
                                        return Ok(());
                                    }
                                    crate::sip::StatusCodeKind::Successful => {
                                        if last_req.to_header()?.tag().ok().is_none() {
                                            // don't ack 2xx response when ack is placeholder
                                            return Ok(());
                                        }
                                    }
                                    _ => {}
                                }

                                if let Ok(Some(tag)) = resp.to_header().and_then(|h| h.tag()) {
                                    last_req.to_header_mut().and_then(|h| h.mut_tag(tag)).ok();
                                }

                                if let crate::sip::StatusCodeKind::RequestFailure =
                                    resp.status_code.kind()
                                {
                                    // for ACK to 487, send it where it came from
                                    connection.send(last_message, Some(from)).await?;
                                    return Ok(());
                                }

                                let dest_uri = last_req.destination();
                                let dest = match SipAddr::try_from(&dest_uri).ok() {
                                    Some(addr)
                                        if matches!(
                                            addr.addr.host,
                                            crate::sip::Host::Domain(_)
                                        ) =>
                                    {
                                        self.transport_layer
                                            .inner
                                            .domain_resolver
                                            .resolve(&addr)
                                            .await
                                            .ok()
                                    }
                                    addr => addr,
                                };

                                connection.send(last_message, dest.as_ref()).await?;
                            }
                        }
                        _ => {}
                    }
                    return Ok(());
                }
            }
        };

        let msg = if let Some(inspector) = &self.message_inspector {
            inspector.after_received(msg, from)
        } else {
            msg
        };

        if let Some(tu) = self.transactions.get(&key) {
            tu.send(TransactionEvent::Received(msg, Some(connection)))
                .map_err(|e| Error::TransactionError(e.to_string(), key))?;
            return Ok(());
        }
        // if the transaction is not exist, create a new transaction
        let request = match msg {
            SipMessage::Request(req) => req,
            SipMessage::Response(resp) => {
                if resp.cseq_header()?.method()? != crate::sip::Method::Cancel {
                    debug!(%key, response = %resp, "the transaction does not exist");
                }
                return Ok(());
            }
        };

        match request.method {
            crate::sip::Method::Cancel => {
                let resp = self.make_response(
                    &request,
                    crate::sip::StatusCode::CallTransactionDoesNotExist,
                    None,
                );

                let dest = if !connection.is_reliable() {
                    self.get_destination_from_request(&request).await
                } else {
                    None
                };

                let resp = if let Some(ref inspector) = self.message_inspector {
                    inspector.before_send(resp.into(), dest.as_ref())
                } else {
                    resp.into()
                };

                connection.send(resp, dest.as_ref()).await?;
                return Ok(());
            }
            crate::sip::Method::Ack => return Ok(()),
            _ => {}
        }

        let tx =
            Transaction::new_server(key.clone(), request.clone(), self.clone(), Some(connection));

        self.incoming_sender.send(tx).ok();
        Ok(())
    }

    pub fn attach_transaction(&self, key: &TransactionKey, tu_sender: TransactionEventSender) {
        trace!(%key, "attach transaction");
        self.transactions.insert(key.clone(), tu_sender);
    }

    pub fn detach_transaction(&self, key: &TransactionKey, last_message: Option<SipMessage>) {
        trace!(%key, "detach transaction");
        self.transactions.remove(key);

        if let Some(msg) = last_message {
            self.timers.timeout(
                self.option.t1x64,
                TransactionTimer::TimerCleanup(key.clone()), // maybe use TimerK ???
            );

            self.finished_transactions.insert(key.clone(), Some(msg));
        }
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.transport_layer.get_addrs()
    }

    pub fn get_record_route(&self) -> Result<crate::sip::typed::RecordRoute> {
        let first_addr = self
            .transport_layer
            .get_addrs()
            .first()
            .ok_or(Error::EndpointError("not sipaddrs".to_string()))
            .cloned()?;
        let mut uri: crate::sip::Uri = first_addr.into();
        uri.params.push(crate::sip::Param::Lr);
        Ok(crate::sip::typed::RecordRoute {
            display_name: None,
            uri,
            params: vec![],
        })
    }

    pub fn get_via(
        &self,
        addr: Option<crate::transport::SipAddr>,
        branch: Option<crate::sip::Param>,
    ) -> Result<crate::sip::typed::Via> {
        let first_addr = match addr {
            Some(addr) => addr,
            None => self
                .transport_layer
                .get_addrs()
                .first()
                .ok_or(Error::EndpointError("not sipaddrs".to_string()))
                .cloned()?,
        };

        let via = crate::sip::typed::Via {
            version: crate::sip::Version::V2,
            transport: first_addr.r#type.unwrap_or_default(),
            uri: first_addr.addr.into(),
            params: vec![
                branch.unwrap_or_else(make_via_branch),
                crate::sip::Param::Rport(None),
            ],
        };
        Ok(via)
    }

    pub fn get_running_transactions(&self) -> Option<Vec<TransactionKey>> {
        Some(self.transactions.iter().map(|e| e.key().clone()).collect())
    }

    pub fn get_stats(&self) -> EndpointStats {
        let waiting_ack = self.waiting_ack.len();
        let running_transactions = self.transactions.len();
        let finished_transactions = self.finished_transactions.len();

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
            domain_resolver: None,
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
    pub fn with_allows(&mut self, allows: Vec<crate::sip::Method>) -> &mut Self {
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

    pub fn with_domain_resolver(&mut self, resolver: Box<dyn DomainResolver>) -> &mut Self {
        self.domain_resolver = Some(resolver);
        self
    }

    pub fn build(&mut self) -> Endpoint {
        let cancel_token = self.cancel_token.take().unwrap_or_default();
        let transport_layer = self.transport_layer.take().unwrap_or_else(|| {
            if let Some(resolver) = self.domain_resolver.take() {
                TransportLayer::new_with_domain_resolver(cancel_token.clone(), resolver)
            } else {
                TransportLayer::new(cancel_token.clone())
            }
        });

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
                warn!(error = ?e, "endpoint serve error");
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
            .take()
            .ok_or_else(|| Error::EndpointError("incoming recevier taken".to_string()))
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.inner.transport_layer.get_addrs()
    }
}
