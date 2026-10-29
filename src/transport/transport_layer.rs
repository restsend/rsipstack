#[cfg(feature = "platform-tokio")]
use super::tcp::TcpConnection;
#[cfg(all(feature = "platform-tokio", feature = "rustls"))]
use super::tls::{TlsConfig, TlsConnection};
#[cfg(all(feature = "platform-tokio", feature = "websocket"))]
use super::websocket::WebSocketConnection;
use super::{connection::TransportSender, sip_addr::SipAddr, SipConnection};
use crate::platform::mpsc;
use crate::platform::sync::RwMap;
use crate::platform::sync::{Mutex, RwLock};
use crate::platform::CancellationToken;
use crate::prelude::*;
#[cfg(feature = "platform-tokio")]
use crate::resolver::SipResolver;
#[cfg(feature = "platform-tokio")]
use crate::sip::HostWithPort;
use crate::sip::{Host, Transport};
use crate::transaction::key::TransactionKey;
use crate::transport::connection::TransportReceiver;
use crate::{transport::TransportEvent, Result};
use async_trait::async_trait;
use core::net::IpAddr;
use core::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info, warn};

/// Default idle timeout applied to stream (TCP/TLS/WS) connections when the
/// application does not configure one. A stream connection that receives no
/// bytes (SIP message, keepalive, WS ping) for this long is closed and
/// retired: half-open sockets (client vanished without FIN — network drop,
/// NAT rebinding, sleep) otherwise pin their `serve_loop` forever and leak
/// the connection table entry.
pub const DEFAULT_STREAM_IDLE_TIMEOUT_MS: u32 = 300_000;

#[async_trait]
pub trait DomainResolver: Send + Sync {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr>;
}

#[async_trait]
pub trait TransportWhitelist: Send + Sync {
    /// Return true to accept the packet/connection for the given peer IP.
    async fn allow(&self, ip: IpAddr) -> bool;
}

#[async_trait]
impl<F, Fut> TransportWhitelist for F
where
    F: Send + Sync + Fn(IpAddr) -> Fut,
    Fut: core::future::Future<Output = bool> + Send,
{
    async fn allow(&self, ip: IpAddr) -> bool {
        (self)(ip).await
    }
}

pub(crate) type TransportWhitelistRef = Arc<dyn TransportWhitelist>;

/// No-backend placeholder: domain resolution requires a real backend
/// (tokio today, embassy + embassy-net DNS in WP3).
#[cfg(not(feature = "platform-tokio"))]
struct UnimplementedDomainResolver;

#[cfg(not(feature = "platform-tokio"))]
#[async_trait]
impl DomainResolver for UnimplementedDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr> {
        Err(crate::Error::DnsResolutionError(format!(
            "no platform backend: cannot resolve {target}"
        )))
    }
}
pub struct DefaultDomainResolver {
    #[cfg(feature = "platform-tokio")]
    resolver: SipResolver,
}

impl DefaultDomainResolver {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "platform-tokio")]
            resolver: SipResolver::default(),
        }
    }

    #[cfg(feature = "platform-tokio")]
    pub async fn resolve_with_lookup(&self, target: &SipAddr) -> Result<SipAddr> {
        let domain = match &target.addr.host {
            Host::Domain(domain) => domain,
            _ => {
                return Err(crate::Error::DnsResolutionError(target.addr.to_string()));
            }
        };

        // RFC 5626: .invalid domains are placeholders for temporary contacts
        // and must not be resolved via DNS
        if domain.0 == "invalid" || domain.0.ends_with(".invalid") {
            return Err(crate::Error::DnsResolutionError(format!(
                "cannot resolve .invalid domain: {}",
                domain
            )));
        }

        // Use new SipResolver
        let secure = matches!(
            target.r#type,
            Some(Transport::Tls) | Some(Transport::Wss) | Some(Transport::TlsSctp)
        );

        let addrs = self
            .resolver
            .lookup(domain, target.addr.port, target.r#type, secure)
            .await
            .map_err(|e| crate::Error::DnsResolutionError(format!("{}: {}", target.addr, e)))?;

        if let Some(first) = addrs.first() {
            return Ok(SipAddr {
                r#type: Some(first.transport),
                addr: HostWithPort {
                    host: Host::IpAddr(first.addr.ip()),
                    port: Some(first.addr.port().into()),
                },
            });
        }

        Err(crate::Error::DnsResolutionError(target.addr.to_string()))
    }
}

impl Default for DefaultDomainResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "platform-tokio")]
#[cfg(feature = "platform-tokio")]
#[async_trait]
impl DomainResolver for DefaultDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr> {
        return self.resolve_with_lookup(target).await;
    }
}

pub struct TransportLayerInner {
    pub(crate) cancel_token: CancellationToken,
    listens: Arc<RwLock<Vec<SipConnection>>>, // listening transports
    // outbound/inbound connections, keyed by remote address. A single remote
    // ip:port may own SEVERAL live stream connections (NAT port reuse / shared
    // office egress), so the value is a list — never fold: overwriting here is
    // what silently redirected calls to the wrong user's socket.
    connections: Arc<RwMap<SipAddr, Vec<SipConnection>>>,
    pub(crate) transport_tx: TransportSender,
    pub(crate) transport_rx: Mutex<Option<TransportReceiver>>,
    pub domain_resolver: Box<dyn DomainResolver>,
    whitelist: RwLock<Option<TransportWhitelistRef>>,
    #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
    tls_config: RwLock<Option<TlsConfig>>,
    #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
    ws_path: RwLock<Option<String>>,
    /// Idle timeout for stream (TCP/TLS/WS) connections, in **milliseconds**.
    /// `0` disables the timeout (legacy behavior). See
    /// [`DEFAULT_STREAM_IDLE_TIMEOUT_MS`].
    stream_idle_timeout_ms: AtomicU32,
}
pub(crate) type TransportLayerInnerRef = Arc<TransportLayerInner>;

// Deliberately NOT `Clone`: `Drop` below cancels the shared token, and Rust
// drops are per-value, not per-resource — if this handle were clonable, the
// first clone dropped anywhere (a guard, a moved task argument) would tear
// down every listener and serve loop while the owner is still using the
// layer. rustpbx hit exactly that premature-shutdown bug with a cleanup guard
// that owned a clone. Single-owner RAII: dropping the layer *is* shutdown.
// When shared access is needed, reach it through `EndpointInner` (plain Arc,
// no drop side effects) or wrap it in an explicit `Arc<TransportLayer>` and
// revisit the shutdown story.
pub struct TransportLayer {
    pub outbound: Option<SipAddr>,
    pub inner: TransportLayerInnerRef,
}

impl TransportLayer {
    pub fn new_with_domain_resolver(
        cancel_token: CancellationToken,
        domain_resolver: Box<dyn DomainResolver>,
    ) -> Self {
        let (transport_tx, transport_rx) = mpsc::unbounded_channel();
        let inner = TransportLayerInner {
            cancel_token,
            listens: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwMap::new()),
            transport_tx,
            transport_rx: Mutex::new(Some(transport_rx)),
            domain_resolver,
            whitelist: RwLock::new(None),
            #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
            tls_config: RwLock::new(None),
            #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
            ws_path: RwLock::new(None),
            stream_idle_timeout_ms: AtomicU32::new(DEFAULT_STREAM_IDLE_TIMEOUT_MS),
        };
        Self {
            outbound: None,
            inner: Arc::new(inner),
        }
    }

    #[cfg(feature = "platform-tokio")]
    pub fn new(cancel_token: CancellationToken) -> Self {
        let domain_resolver = Box::new(DefaultDomainResolver::default());
        Self::new_with_domain_resolver(cancel_token, domain_resolver)
    }

    #[cfg(not(feature = "platform-tokio"))]
    pub fn new(cancel_token: CancellationToken) -> Self {
        let domain_resolver = Box::new(UnimplementedDomainResolver);
        Self::new_with_domain_resolver(cancel_token, domain_resolver)
    }

    pub fn add_transport(&self, transport: SipConnection) {
        self.inner.add_listener(transport)
    }

    pub fn del_transport(&self, addr: &SipAddr) {
        self.inner.del_listener(addr)
    }

    pub fn add_connection(&self, connection: SipConnection) {
        self.inner.add_connection(connection);
    }

    /// Remove a specific stream connection **by identity** (pointer equality of
    /// the underlying stream), cancelling its flow-affinity token.
    ///
    /// Unlike [`TransportLayer::del_connection`], this never touches sibling
    /// connections cached for the same remote address: several endpoints can
    /// legitimately share one public `ip:port` behind NAT, and tearing the
    /// address down wholesale evicts the wrong user's channel.
    pub fn remove_connection(&self, connection: &SipConnection) {
        self.retire_connection(connection);
    }

    /// Remove every cached connection for `addr`.
    #[deprecated(
        since = "0.7.5",
        note = "address-scoped removal evicts sibling connections sharing the same remote ip:port; use remove_connection"
    )]
    pub fn del_connection(&self, addr: &SipAddr) {
        self.inner.del_connection(addr)
    }

    /// Retire a stream connection that can no longer carry messages: the next
    /// lookup for its peer opens a new one (a newer connection cached for the
    /// same peer is left alone), and its cancel token is cancelled so flow
    /// affinity stops choosing it.
    pub(crate) fn retire_connection(&self, connection: &SipConnection) {
        retire_connection(&self.inner.connections, connection)
    }

    pub async fn lookup(
        &self,
        target: &SipAddr,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        self.inner.lookup(target, self.outbound.as_ref(), key).await
    }

    /// Start registered listeners. Endpoint owns startup after claiming the event receiver.
    pub(crate) async fn serve_listens(&self) -> Result<()> {
        let listens = self.inner.listens.read().clone();
        for transport in listens {
            let addr = transport.get_addr().clone();
            match TransportLayerInner::serve_listener(self.inner.clone(), transport).await {
                Ok(()) => {}
                Err(e) => {
                    warn!(error = ?e, %addr, "Failed to serve listener");
                }
            }
        }
        Ok(())
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        let mut addrs: Vec<SipAddr> = self
            .inner
            .listens
            .read()
            .iter()
            .map(|t| t.get_addr().to_owned())
            .collect();
        self.inner.connections.with(|m| {
            for conn in m.values().flatten() {
                addrs.push(conn.get_addr().clone());
            }
        });
        addrs
    }

    /// Number of live tracked stream/outbound connections (listeners
    /// excluded): the sum of every remote-address slot in the connection
    /// table. Cheap snapshot for health/metrics endpoints — unlike
    /// [`TransportLayer::get_addrs`] it clones nothing.
    pub fn connections_count(&self) -> usize {
        self.inner
            .connections
            .with(|m| m.values().map(Vec::len).sum())
    }

    /// Set an async whitelist callback invoked on incoming packets/connections.
    pub fn set_whitelist<T>(&self, whitelist: T)
    where
        T: TransportWhitelist + 'static,
    {
        self.inner.set_whitelist(Some(Arc::new(whitelist)));
    }

    /// Remove the whitelist callback.
    pub fn clear_whitelist(&self) {
        self.inner.set_whitelist(None);
    }

    #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
    /// Set the TLS configuration used for future outbound TLS connections.
    pub fn set_tls_config(&self, tls_config: TlsConfig) {
        self.inner.set_tls_config(Some(tls_config));
    }

    /// Remove the TLS configuration used for future outbound TLS connections.
    #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
    pub fn clear_tls_config(&self) {
        self.inner.set_tls_config(None);
    }

    #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
    /// Set the WebSocket path used for future outbound WebSocket connections.
    /// Defaults to `/` if not set.
    pub fn set_ws_path(&self, path: impl Into<String>) {
        self.inner.set_ws_path(Some(path.into()));
    }

    /// Remove the WebSocket path override, reverting to default `/`.
    #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
    pub fn clear_ws_path(&self) {
        self.inner.set_ws_path(None);
    }

    /// Set the idle timeout applied to stream (TCP/TLS/WS) connections.
    ///
    /// A stream connection that receives no bytes for this long is closed and
    /// retired from the connection table, reclaiming half-open sockets whose
    /// peer vanished without a FIN. `Duration::ZERO` disables the timeout
    /// (legacy behavior). Defaults to [`DEFAULT_STREAM_IDLE_TIMEOUT_MS`]
    /// (300 s). Sub-second values are honored (useful for tests).
    pub fn set_stream_idle_timeout(&self, timeout: Duration) {
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        self.inner.set_stream_idle_timeout_ms(ms);
    }

    /// Current stream idle timeout (`Duration::ZERO` = disabled).
    pub fn stream_idle_timeout(&self) -> Duration {
        self.inner.stream_idle_timeout()
    }
}

impl TransportLayerInner {
    pub(super) fn set_whitelist(&self, whitelist: Option<TransportWhitelistRef>) {
        *self.whitelist.write() = whitelist;
    }

    pub(crate) async fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let whitelist = self.whitelist.read().clone();
        match whitelist {
            Some(whitelist) => whitelist.allow(ip).await,
            None => true,
        }
    }

    #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
    fn set_tls_config(&self, tls_config: Option<TlsConfig>) {
        *self.tls_config.write() = tls_config;
    }

    #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
    fn tls_config(&self) -> Option<TlsConfig> {
        self.tls_config.read().clone()
    }

    #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
    fn set_ws_path(&self, path: Option<String>) {
        *self.ws_path.write() = path;
    }

    /// Set the stream idle timeout in milliseconds (0 disables it).
    /// Millisecond granularity: sub-second timeouts are meaningful for tests
    /// and aggressive deployments; `as_secs()` truncation would silently turn
    /// them into "disabled".
    fn set_stream_idle_timeout_ms(&self, ms: u32) {
        self.stream_idle_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// Current stream idle timeout.
    fn stream_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.stream_idle_timeout_ms.load(Ordering::Relaxed) as u64)
    }

    #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
    fn ws_path(&self) -> Option<String> {
        self.ws_path.read().clone()
    }

    pub fn add_listener(&self, connection: SipConnection) {
        self.listens.write().push(connection);
    }

    pub(super) fn del_listener(&self, addr: &SipAddr) {
        self.listens.write().retain(|t| t.get_addr() != addr);
    }

    pub(super) fn add_connection(&self, connection: SipConnection) {
        if let Some(remote_addr) = connection.get_remote_addr().cloned() {
            debug!(%remote_addr, "add_connection");
            if !connection.is_stream() {
                // Connectionless transports keep a single cached handle per peer.
                self.connections
                    .insert(remote_addr, vec![connection.clone()]);
            } else {
                let existing_locals = self.connections.with(|cached| {
                    cached
                        .get(&remote_addr)
                        .map(|slots| {
                            slots
                                .iter()
                                .filter(|c| c.is_stream() && !c.is_same_stream(&connection))
                                .map(|c| c.get_addr().to_string())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                });
                let existing = existing_locals.len();
                let duplicate = self.connections.with(|cached| {
                    cached
                        .get(&remote_addr)
                        .is_some_and(|slots| slots.iter().any(|c| c.is_same_stream(&connection)))
                });
                if duplicate {
                    // Same object re-registered: keep the list deduplicated so
                    // identity-based removal can never double-count entries.
                    debug!(%remote_addr, "add_connection: stream already cached; skipping duplicate entry");
                } else {
                    self.connections.with_mut(|cached| {
                        cached
                            .entry(remote_addr.clone())
                            .or_default()
                            .push(connection.clone())
                    });
                    if existing > 0 {
                        // Multiple live stream connections behind one remote
                        // ip:port: NAT port reuse or a shared office egress.
                        // Keep both — the newest registration wins for outbound
                        // delivery, and the conflict is made visible here.
                        warn!(
                            %remote_addr,
                            existing,
                            existing_locals = ?existing_locals,
                            new_local = %connection.get_addr(),
                            "connection conflict: multiple stream connections share one remote address"
                        );
                    }
                }
            }
            self.serve_connection(connection);
        } else {
            warn!(addr = %connection.get_addr(), "connection has no remote address");
        }
    }

    pub(super) fn del_connection(&self, addr: &SipAddr) {
        debug!(%addr, "del_connection");
        self.connections.remove(addr);
    }

    async fn lookup(
        &self,
        destination: &SipAddr,
        outbound: Option<&SipAddr>,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        let target = outbound.unwrap_or(destination);
        // Capture the original domain name before DNS resolution: it is the
        // TLS SNI / certificate identity (all backends, not just rustls).
        let original_domain = match &target.addr.host {
            Host::Domain(domain) => Some(domain.to_string()),
            _ => None,
        };

        let target = if matches!(target.addr.host, Host::Domain(_)) {
            &self.domain_resolver.resolve(target).await?
        } else {
            target
        };

        debug!(?key, src = %destination, %target, "lookup target");
        if let Some(connections) = self.connections.get(target) {
            // Newest wins: entries are appended on add, so the last slot is the
            // most recent connection for this peer. Several peers may share one
            // remote ip:port behind NAT; without an application-level channel
            // hint the most recent registration is the best delivery target.
            if let Some(transport) = connections.last() {
                return Ok((transport.clone(), target.clone()));
            }
        }
        // TLS client dial for embedded backends: no tokio, no rustls — the
        // `platform::tls` connector seam owns the TCP dial and the handshake.
        #[cfg(not(all(feature = "platform-tokio", feature = "rustls")))]
        if let Some(Transport::Tls) = target.r#type {
            let sip_connection = SipConnection::TlsPlatform(
                crate::transport::tls_platform::PlatformTlsConnection::connect(
                    target,
                    original_domain.as_deref(),
                    Some(self.cancel_token.child_token()),
                )
                .await?,
            );
            self.add_connection(sip_connection.clone());
            return Ok((sip_connection, target.clone()));
        }
        #[cfg(feature = "platform-tokio")]
        if let Some(Transport::Tcp | Transport::Tls | Transport::Ws | Transport::Wss) =
            target.r#type
        {
            let sip_connection = match target.r#type {
                #[cfg(feature = "platform-tokio")]
                Some(Transport::Tcp) => {
                    let connection =
                        TcpConnection::connect(target, Some(self.cancel_token.child_token()))
                            .await?;
                    SipConnection::Tcp(connection)
                }
                #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
                Some(Transport::Tls) => {
                    // Build effective TLS config with SNI from the original domain
                    let mut effective_config = self.tls_config().clone().unwrap_or_default();
                    if effective_config.sni_hostname.is_none() {
                        effective_config.sni_hostname = original_domain;
                    }
                    let connection = TlsConnection::connect(
                        target,
                        Some(&effective_config),
                        None,
                        Some(self.cancel_token.child_token()),
                    )
                    .await?;
                    SipConnection::Tls(connection)
                }
                #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
                Some(Transport::Ws | Transport::Wss) => {
                    let ws_path = self.ws_path();
                    let connection = WebSocketConnection::connect_with_path(
                        target,
                        ws_path.as_deref(),
                        Some(self.cancel_token.child_token()),
                    )
                    .await?;
                    SipConnection::WebSocket(connection)
                }
                _ => {
                    return Err(crate::Error::TransportLayerError(
                        format!("unsupported transport type: {:?}", target.r#type),
                        target.to_owned(),
                    ));
                }
            };
            self.add_connection(sip_connection.clone());
            return Ok((sip_connection, target.clone()));
        }

        let listens = self.listens.read();
        let mut first_udp = None;
        for transport in listens.iter() {
            let addr = transport.get_addr();
            if addr.r#type == Some(Transport::Udp) && first_udp.is_none() {
                first_udp = Some(transport.clone());
            }
            if addr == target {
                return Ok((transport.clone(), target.clone()));
            }
        }
        // A UDP listener can only carry UDP (or transport-less) targets:
        // never downgrade a reliable-transport target to the UDP listener —
        // that silently sent `sips:` INVITEs as plaintext datagrams to a TLS
        // port (5061).
        if matches!(target.r#type, None | Some(Transport::Udp)) {
            if let Some(transport) = first_udp {
                return Ok((transport, target.clone()));
            }
        }
        Err(crate::Error::TransportLayerError(
            format!("unsupported transport type: {:?}", target.r#type),
            target.to_owned(),
        ))
    }

    pub(super) async fn serve_listener(self: Arc<Self>, transport: SipConnection) -> Result<()> {
        // consumed by the transport arms below
        #[cfg_attr(not(feature = "platform-tokio"), allow(unused_variables))]
        let sender = self.transport_tx.clone();
        match transport {
            // Backend-agnostic: `platform::spawn` and `serve_loop_with_whitelist`
            // work on every backend — without this arm, embassy (no_std) endpoints
            // silently never read their UDP listeners and inbound responses die
            // in the socket shim.
            SipConnection::Udp(transport) => {
                let transport_layer_inner = self.clone();
                crate::platform::spawn(async move {
                    // embassy spawn demands `Output = ()`; the loop logs its
                    // own exit, so the Result carries no information here.
                    let _ = transport
                        .serve_loop_with_whitelist(sender, Some(transport_layer_inner))
                        .await;
                });
                Ok(())
            }
            #[cfg(feature = "platform-tokio")]
            SipConnection::TcpListener(connection) => connection.serve_listener(self.clone()).await,
            #[cfg(all(feature = "platform-tokio", feature = "rustls"))]
            SipConnection::TlsListener(connection) => connection.serve_listener(self.clone()).await,
            #[cfg(all(feature = "platform-tokio", feature = "websocket"))]
            SipConnection::WebSocketListener(connection) => {
                connection.serve_listener(self.clone()).await
            }

            _ => {
                warn!(
                    "serve_listener: unsupported transport type: {:?}",
                    transport.get_addr()
                );
                Ok(())
            }
        }
    }

    pub fn serve_connection(&self, transport: SipConnection) {
        let sub_token = self.cancel_token.child_token();
        let sender_clone = self.transport_tx.clone();
        let idle_timeout = self.stream_idle_timeout();
        let remote_addr = transport
            .get_remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string());
        info!(addr=%transport.get_addr(), remote=%remote_addr, "serve_connection: starting serve_loop");
        let connections = self.connections.clone();
        crate::platform::spawn(async move {
            match sender_clone.send(TransportEvent::New(transport.clone())) {
                Ok(()) => {
                    info!(addr=%transport.get_addr(), remote=%remote_addr, "serve_connection: New event sent");
                }
                Err(e) => {
                    warn!(addr=%transport.get_addr(), remote=%remote_addr, error = ?e, "Error sending new connection event");
                    return;
                }
            }
            let transport2 = transport.clone();
            let mut cancel_f = core::pin::pin!(sub_token.cancelled());
            let mut serve_f = core::pin::pin!(async {
                transport2
                    .serve_loop(sender_clone.clone(), idle_timeout)
                    .await
            });
            match crate::platform::select::select2(&mut cancel_f, &mut serve_f).await {
                crate::platform::select::Either::A(()) => {}
                crate::platform::select::Either::B(result) => {
                    if let Err(e) = result {
                        warn!(addr=%transport.get_addr(), remote=%remote_addr, error = %e, "serve_loop error");
                    }
                }
            }
            info!(addr=%transport.get_addr(), remote=%remote_addr, "transport serve_loop exited");
            // The connection is gone: lookup must not hand it out again.
            retire_connection(&connections, &transport);
            transport.close().await.ok();
            sender_clone.send(TransportEvent::Closed(transport)).ok();
        });
    }
}
fn retire_connection(connections: &RwMap<SipAddr, Vec<SipConnection>>, connection: &SipConnection) {
    // Identity-based removal applies to stream transports (TCP/TLS/WS) and
    // in-memory Channel bridges (e.g. WebSocket sessions bridged by a proxy
    // host) alike; connectionless UDP cache entries are managed
    // per-remote-address by lookup and are never retired here.
    if !connection.is_stream() && !matches!(connection, SipConnection::Channel(_)) {
        return;
    }
    // The token is the connection's own: cancelling it marks the flow as
    // terminated for flow affinity (see `resolve_affinity_connection`).
    if let Some(token) = connection.cancel_token() {
        token.cancel();
    }
    if let Some(remote_addr) = connection.get_remote_addr() {
        let removed = connections.with_mut(|cached| {
            let mut removed = false;
            if let Some(slots) = cached.get_mut(remote_addr) {
                let before = slots.len();
                // Identity-based removal: only the dying connection is taken
                // out. Sibling connections sharing the same remote ip:port
                // (other users behind one NAT address) must survive.
                slots.retain(|c| !c.is_same_stream(connection));
                removed = before != slots.len();
                if slots.is_empty() {
                    cached.remove(remote_addr);
                }
            }
            removed
        });
        if removed {
            debug!(%remote_addr, "retire connection");
        }
    }
}

/// Owner-side shutdown: cancelling the shared token cascades to every
/// listener/serve-loop child token. This lives on the (non-clonable) owner
/// handle, NOT on `TransportLayerInner` — the listener tasks hold
/// `Arc<TransportLayerInner>` for their whole lifetime and only exit when
/// this token fires, so a drop impl on the inner Arc would deadlock shutdown.
impl Drop for TransportLayer {
    fn drop(&mut self) {
        self.inner.cancel_token.cancel();
    }
}
#[cfg(all(test, feature = "platform-tokio"))]
mod tests {
    use crate::resolver::SipResolver;
    use crate::sip::uri::ParamsExt;
    use crate::sip::{Host, HostWithPort, Transport};
    use crate::{
        transport::{udp::UdpConnection, SipAddr},
        Result,
    };

    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        let first_uri = SipAddr {
            r#type: Some(Transport::Udp),
            addr: HostWithPort {
                host: Host::IpAddr("127.0.0.1".parse()?),
                port: Some(5060.into()),
            },
        };
        assert!(tl.lookup(&first_uri, None).await.is_err());
        let udp_peer = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let udp_peer_addr = udp_peer.get_addr().to_owned();
        tl.add_transport(udp_peer.into());

        let (target, _) = tl.lookup(&first_uri, None).await?;
        assert_eq!(target.get_addr(), &udp_peer_addr);

        // test outbound
        let outbound_peer = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let outbound = outbound_peer.get_addr().to_owned();
        tl.add_transport(outbound_peer.into());
        tl.outbound = Some(outbound.clone());

        // must return the outbound transport
        let (target, _) = tl.lookup(&first_uri, None).await?;
        assert_eq!(target.get_addr(), &outbound);
        Ok(())
    }

    #[tokio::test]
    async fn test_sip_dns_lookup() -> Result<()> {
        let check_list = vec![
            (
                "sip:bob@127.0.0.1:5061;transport=udp",
                ("bob", "127.0.0.1", 5061, Transport::Udp),
            ),
            (
                "sip:bob@127.0.0.1:5062;transport=tcp",
                ("bob", "127.0.0.1", 5062, Transport::Tcp),
            ),
            (
                "sip:bob@localhost:5063;transport=tls",
                ("bob", "127.0.0.1", 5063, Transport::Tls),
            ),
        ];

        let resolver = SipResolver::default();

        for item in check_list {
            let uri = crate::sip::uri::Uri::try_from(item.0)?;
            let domain = match &uri.host_with_port.host {
                crate::sip::Host::Domain(d) => d.clone(),
                crate::sip::Host::IpAddr(ip) => crate::sip::Domain::from(ip.to_string()),
            };

            let secure = match uri.scheme {
                Some(crate::sip::Scheme::Sips) => true,
                _ => false,
            };

            // Extract transport from params
            let transport_param = uri.transport().map(|t| *t); // This returns Option<&Transport>

            let targets = resolver
                .lookup(&domain, uri.host_with_port.port, transport_param, secure)
                .await;

            assert!(targets.is_ok(), "Failed to resolve {}", item.0);
            let targets = targets.unwrap();
            assert!(!targets.is_empty());

            let target = &targets[0];

            assert_eq!(uri.user().unwrap(), item.1 .0);
            assert_eq!(target.transport, item.1 .3);
            assert_eq!(target.addr.ip().to_string(), item.1 .1);
            assert_eq!(target.addr.port(), item.1 .2);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_serve_listens() -> Result<()> {
        let tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        // Add a UDP connection first
        let udp_conn = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let addr = udp_conn.get_addr().clone();
        tl.add_transport(udp_conn.into());

        // Start serving listeners
        tl.serve_listens().await?;

        // Verify that the transport list is not empty
        let addrs = tl.get_addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr);

        // Cancel to stop the spawned tasks
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        drop(tl);

        Ok(())
    }

    #[tokio::test]
    async fn test_resolve_invalid_domain_rejected() {
        use super::DefaultDomainResolver;

        let resolver = DefaultDomainResolver::new();

        // Test various .invalid domains
        let cases = vec![
            ("invalid", "invalid"),
            ("invalid.invalid", "invalid.invalid"),
            ("abc123.invalid", "abc123.invalid"),
        ];

        for (input, expected_in_message) in cases {
            let target = SipAddr {
                r#type: Some(Transport::Udp),
                addr: HostWithPort {
                    host: Host::Domain(input.into()),
                    port: Some(5060.into()),
                },
            };
            let result = resolver.resolve_with_lookup(&target).await;
            assert!(
                result.is_err(),
                "expected error for .invalid domain: {}",
                input
            );
            let err = result.unwrap_err();
            let err_msg = err.to_string();
            assert!(
                err_msg.contains(expected_in_message),
                "error must mention '{}', got: {}",
                expected_in_message,
                err_msg
            );
        }
    }
}
