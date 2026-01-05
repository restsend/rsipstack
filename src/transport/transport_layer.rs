use super::tls::TlsConnection;
use super::websocket::WebSocketConnection;
use super::{connection::TransportSender, sip_addr::SipAddr, tcp::TcpConnection, SipConnection};
use crate::transaction::key::TransactionKey;
use crate::transport::connection::TransportReceiver;
use crate::{transport::TransportEvent, Result};
use async_trait::async_trait;

#[cfg(feature = "rsip-dns")]
use rsip_dns::trust_dns_resolver::TokioAsyncResolver;
#[cfg(feature = "rsip-dns")]
use rsip_dns::ResolvableExt;

use std::sync::{Mutex, RwLock};
use std::{collections::HashMap, sync::Arc};
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[async_trait]
pub trait DomainResolver: Send + Sync {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr>;
}

pub struct DefaultDomainResolver {}

impl DefaultDomainResolver {
    #[cfg(not(feature = "rsip-dns"))]
    pub async fn resolve_with_lookup(&self, target: &SipAddr) -> Result<SipAddr> {
        let host = match &target.addr.host {
            rsip::Host::Domain(domain) => domain,
            _ => {
                return Err(crate::Error::DnsResolutionError(target.addr.to_string()));
            }
        };
        let port = target.addr.port.unwrap_or(5060.into());
        let lookup_str = format!("{}:{}", host, port);
        let addrs = tokio::net::lookup_host(lookup_str).await?;
        for addr in addrs {
            return Ok(SipAddr {
                r#type: target.r#type,
                addr: rsip::HostWithPort {
                    host: rsip::Host::IpAddr(addr.ip()),
                    port: Some(addr.port().into()),
                },
            });
        }
        Err(crate::Error::DnsResolutionError(target.addr.to_string()))
    }

    #[cfg(feature = "rsip-dns")]
    pub async fn resolve_with_rsip_dns(&self, target: &SipAddr) -> Result<SipAddr> {
        let params = target
            .r#type
            .filter(|&t| !matches!(t, rsip::Transport::Udp))
            .map(rsip::Param::Transport)
            .into_iter()
            .collect();
        let scheme = target.r#type.map(|t| match t {
            rsip::Transport::Tls | rsip::Transport::Wss => rsip::Scheme::Sips,
            _ => rsip::Scheme::Sip,
        });
        let target_for_lookup = rsip::uri::Uri {
            scheme,
            host_with_port: target.addr.clone(),
            params,
            ..Default::default()
        };
        let context = rsip_dns::Context::initialize_from(
            target_for_lookup,
            rsip_dns::AsyncTrustDnsClient::new(
                TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap(),
            ),
            rsip_dns::SupportedTransports::any(),
        )?;

        let mut lookup = rsip_dns::Lookup::from(context);
        match lookup.resolve_next().await {
            Some(result) => Ok(SipAddr {
                r#type: Some(result.transport),
                addr: rsip::HostWithPort::from(core::net::SocketAddr::new(
                    result.ip_addr,
                    u16::from(result.port),
                )),
            }),
            None => Err(crate::Error::DnsResolutionError(target.addr.to_string())),
        }
    }
}

#[async_trait]
impl DomainResolver for DefaultDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr> {
        #[cfg(feature = "rsip-dns")]
        return self.resolve_with_rsip_dns(target).await;

        #[cfg(not(feature = "rsip-dns"))]
        return self.resolve_with_lookup(target).await;
    }
}

pub struct TransportLayerInner {
    pub(crate) cancel_token: CancellationToken,
    listens: Arc<RwLock<Vec<SipConnection>>>, // listening transports
    connections: Arc<RwLock<HashMap<SipAddr, SipConnection>>>, // outbound/inbound connections
    pub(crate) transport_tx: TransportSender,
    pub(crate) transport_rx: Mutex<Option<TransportReceiver>>,
    pub domain_resolver: Box<dyn DomainResolver>,
}
pub(crate) type TransportLayerInnerRef = Arc<TransportLayerInner>;

#[derive(Clone)]
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
            connections: Arc::new(RwLock::new(HashMap::new())),
            transport_tx,
            transport_rx: Mutex::new(Some(transport_rx)),
            domain_resolver,
        };
        Self {
            outbound: None,
            inner: Arc::new(inner),
        }
    }

    pub fn new(cancel_token: CancellationToken) -> Self {
        let domain_resolver = Box::new(DefaultDomainResolver {});
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

    pub fn del_connection(&self, addr: &SipAddr) {
        self.inner.del_connection(addr)
    }

    pub async fn lookup(
        &self,
        target: &SipAddr,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        self.inner.lookup(target, self.outbound.as_ref(), key).await
    }

    pub async fn serve_listens(&self) -> Result<()> {
        let listens = match self.inner.listens.read() {
            Ok(listens) => listens.clone(),
            Err(e) => {
                return Err(crate::Error::Error(format!(
                    "Failed to read listens: {:?}",
                    e
                )));
            }
        };
        for transport in listens {
            let addr = transport.get_addr().clone();
            match TransportLayerInner::serve_listener(self.inner.clone(), transport).await {
                Ok(()) => {}
                Err(e) => {
                    warn!(?addr, "Failed to serve listener: {:?}", e);
                }
            }
        }
        Ok(())
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        match self.inner.listens.read() {
            Ok(listens) => listens.iter().map(|t| t.get_addr().to_owned()).collect(),
            Err(e) => {
                warn!("Failed to read listens: {:?}", e);
                Vec::new()
            }
        }
    }
}

impl TransportLayerInner {
    pub(super) fn add_listener(&self, connection: SipConnection) {
        match self.listens.write() {
            Ok(mut listens) => {
                listens.push(connection);
            }
            Err(e) => {
                warn!("Failed to write listens: {:?}", e);
            }
        }
    }

    pub(super) fn del_listener(&self, addr: &SipAddr) {
        match self.listens.write() {
            Ok(mut listens) => {
                listens.retain(|t| t.get_addr() != addr);
            }
            Err(e) => {
                warn!("Failed to write listens: {} {:?}", addr, e);
            }
        }
    }

    pub(super) fn add_connection(&self, connection: SipConnection) {
        match self.connections.write() {
            Ok(mut connections) => {
                connections.insert(connection.get_addr().to_owned(), connection.clone());
                self.serve_connection(connection);
            }
            Err(e) => {
                warn!("Failed to write connections: {:?}", e);
            }
        }
    }

    pub(super) fn del_connection(&self, addr: &SipAddr) {
        match self.connections.write() {
            Ok(mut connections) => {
                connections.remove(addr);
            }
            Err(e) => {
                warn!("Failed to write connections: {} {:?}", addr, e);
            }
        }
    }

    async fn lookup(
        &self,
        destination: &SipAddr,
        outbound: Option<&SipAddr>,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        let target = outbound.unwrap_or(destination);
        let target = if matches!(target.addr.host, rsip::Host::Domain(_)) {
            &self.domain_resolver.resolve(target).await?
        } else {
            target
        };

        debug!(?key, "lookup target: {} -> {}", destination, target);
        match self.connections.read() {
            Ok(connections) => {
                if let Some(transport) = connections.get(&target) {
                    return Ok((transport.clone(), target.clone()));
                }
            }
            Err(e) => {
                warn!("Failed to read connections: {:?}", e);
                return Err(crate::Error::Error(format!(
                    "Failed to read connections: {:?}",
                    e
                )));
            }
        }
        match target.r#type {
            Some(
                rsip::transport::Transport::Tcp
                | rsip::transport::Transport::Tls
                | rsip::transport::Transport::Ws
                | rsip::transport::Transport::Wss,
            ) => {
                let sip_connection = match target.r#type {
                    Some(rsip::transport::Transport::Tcp) => {
                        let connection =
                            TcpConnection::connect(target, Some(self.cancel_token.child_token()))
                                .await?;
                        SipConnection::Tcp(connection)
                    }
                    Some(rsip::transport::Transport::Tls) => {
                        let connection = TlsConnection::connect(
                            target,
                            None,
                            Some(self.cancel_token.child_token()),
                        )
                        .await?;
                        SipConnection::Tls(connection)
                    }
                    Some(rsip::transport::Transport::Ws | rsip::transport::Transport::Wss) => {
                        let connection = WebSocketConnection::connect(
                            target,
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
            _ => {}
        }

        let listens = match self.listens.read() {
            Ok(listens) => listens,
            Err(e) => {
                return Err(crate::Error::Error(format!(
                    "Failed to read listens: {:?}",
                    e
                )));
            }
        };
        let mut first_udp = None;
        for transport in listens.iter() {
            let addr = transport.get_addr();
            if addr.r#type == Some(rsip::transport::Transport::Udp) && first_udp.is_none() {
                first_udp = Some(transport.clone());
            }
            if addr == target {
                return Ok((transport.clone(), target.clone()));
            }
        }
        if let Some(transport) = first_udp {
            return Ok((transport, target.clone()));
        }
        Err(crate::Error::TransportLayerError(
            format!("unsupported transport type: {:?}", target.r#type),
            target.to_owned(),
        ))
    }

    pub(super) async fn serve_listener(self: Arc<Self>, transport: SipConnection) -> Result<()> {
        let sender = self.transport_tx.clone();
        match transport {
            SipConnection::Udp(transport) => {
                tokio::spawn(async move { transport.serve_loop(sender).await });
                Ok(())
            }
            SipConnection::TcpListener(connection) => connection.serve_listener(self.clone()).await,
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(connection) => connection.serve_listener(self.clone()).await,
            #[cfg(feature = "websocket")]
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
        tokio::spawn(async move {
            match sender_clone.send(TransportEvent::New(transport.clone())) {
                Ok(()) => {}
                Err(e) => {
                    warn!(addr=%transport.get_addr(), "Error sending new connection event: {:?}", e);
                    return;
                }
            }
            select! {
                _ = sub_token.cancelled() => { }
                _ = transport.serve_loop(sender_clone.clone()) => {
                }
            }
            info!(addr=%transport.get_addr(), "transport serve_loop exited");
            transport.close().await.ok();
            sender_clone.send(TransportEvent::Closed(transport)).ok();
        });
    }
}
impl Drop for TransportLayer {
    fn drop(&mut self) {
        self.inner.cancel_token.cancel();
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        transport::{udp::UdpConnection, SipAddr},
        Result,
    };
    use rsip::{Host, Transport};
    use rsip_dns::{trust_dns_resolver::TokioAsyncResolver, ResolvableExt};

    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        let first_uri = SipAddr {
            r#type: Some(rsip::transport::Transport::Udp),
            addr: rsip::HostWithPort {
                host: rsip::Host::IpAddr("127.0.0.1".parse()?),
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
    async fn test_rsip_dns_lookup() -> Result<()> {
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
            (
                "sip:bob@localhost:5064;transport=TLS-SCTP",
                ("bob", "127.0.0.1", 5064, Transport::TlsSctp),
            ),
            (
                "sip:bob@localhost:5065;transport=sctp",
                ("bob", "127.0.0.1", 5065, Transport::Sctp),
            ),
            (
                "sip:bob@localhost:5066;transport=ws",
                ("bob", "127.0.0.1", 5066, Transport::Ws),
            ),
            (
                "sip:bob@localhost:5067;transport=wss",
                ("bob", "127.0.0.1", 5067, Transport::Wss),
            ),
        ];
        for item in check_list {
            let uri = rsip::uri::Uri::try_from(item.0)?;
            let context = rsip_dns::Context::initialize_from(
                uri.clone(),
                rsip_dns::AsyncTrustDnsClient::new(
                    TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap(),
                ),
                rsip_dns::SupportedTransports::any(),
            )?;

            let mut lookup = rsip_dns::Lookup::from(context);
            let mut target = lookup.resolve_next().await.unwrap();
            match uri.host_with_port.host {
                Host::IpAddr(_) => {
                    if let Some(port) = uri.host_with_port.port {
                        target.port = port;
                    }
                }
                _ => {}
            }
            assert_eq!(uri.user().unwrap(), item.1 .0);
            assert_eq!(target.transport, item.1 .3);
            assert_eq!(target.ip_addr.to_string(), item.1 .1);
            assert_eq!(target.port, item.1 .2.into());
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
}
