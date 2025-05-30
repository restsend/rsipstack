use super::tls::{TlsConfig, TlsConnection};
use super::websocket::WebSocketConnection;
use super::{connection::TransportSender, sip_addr::SipAddr, tcp::TcpConnection, SipConnection};
use crate::{transport::TransportEvent, Result};
use rsip::HostWithPort;
use rsip_dns::{trust_dns_resolver::TokioAsyncResolver, ResolvableExt};
use std::net::SocketAddr;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Transport layer configuration
#[derive(Default, Clone)]
pub struct TransportConfig {
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    pub enable_ws: bool,
    pub enable_wss: bool,
}

#[derive(Default)]
pub struct TransportLayerInner {
    cancel_token: CancellationToken,
    listens: Arc<Mutex<HashMap<SipAddr, SipConnection>>>, // listening transports
    config: Arc<Mutex<TransportConfig>>,
}

#[derive(Default)]
pub struct TransportLayer {
    pub outbound: Option<SipAddr>,
    inner: Arc<TransportLayerInner>,
}

impl TransportLayer {
    pub fn new(cancel_token: CancellationToken) -> Self {
        let inner = TransportLayerInner {
            cancel_token,
            listens: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(TransportConfig::default())),
        };
        Self {
            outbound: None,
            inner: Arc::new(inner),
        }
    }

    pub fn with_config(cancel_token: CancellationToken, config: TransportConfig) -> Self {
        let inner = TransportLayerInner {
            cancel_token,
            listens: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(config)),
        };
        Self {
            outbound: None,
            inner: Arc::new(inner),
        }
    }

    pub fn add_transport(&self, transport: SipConnection) {
        self.inner.add_connection(transport)
    }

    pub fn del_transport(&self, addr: &SipAddr) {
        self.inner.del_connection(addr)
    }

    pub async fn lookup(
        &self,
        uri: &rsip::uri::Uri,
        sender: TransportSender,
    ) -> Result<(SipConnection, SipAddr)> {
        self.inner.lookup(uri, self.outbound.as_ref(), sender).await
    }

    pub async fn serve_listens(&self, sender: TransportSender) -> Result<()> {
        let listens = self.inner.listens.lock().unwrap().clone();
        for (_, transport) in listens {
            self.inner.start_serve(transport.clone(), sender.clone());
        }
        Ok(())
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.inner.listens.lock().unwrap().keys().cloned().collect()
    }

    /// Create and add UDP listener
    pub async fn add_udp_listener(&self, local: SocketAddr) -> Result<SipAddr> {
        use super::udp::UdpConnection;

        let connection = UdpConnection::create_connection(local, None).await?;
        let addr = connection.get_addr().clone();
        self.add_transport(connection.into());
        Ok(addr)
    }

    /// Create and add TCP listener
    pub async fn add_tcp_listener(
        &self,
        local: SocketAddr,
        sender: TransportSender,
    ) -> Result<SipAddr> {
        let (listener, addr) = TcpConnection::create_listener(local).await?;

        let cancel_token = self.inner.cancel_token.child_token();
        let addr_clone = addr.clone();
        let sender_clone = sender.clone();

        tokio::spawn(async move {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("TCP listener cancelled: {}", addr_clone);
                }
                result = TcpConnection::serve_listener(listener, addr_clone.clone(), sender_clone) => {
                    if let Err(e) = result {
                        warn!("TCP listener error: {}: {:?}", addr_clone, e);
                    }
                }
            }
        });

        Ok(addr)
    }

    pub async fn add_tls_listener(
        &self,
        local: SocketAddr,
        _sender: TransportSender,
    ) -> Result<SipAddr> {
        let config_guard = self.inner.config.lock().unwrap();
        let config = match &config_guard.tls {
            Some(cfg) => cfg,
            None => {
                return Err(crate::Error::Error(
                    "TLS configuration not provided".to_string(),
                ));
            }
        };

        let acceptor = TlsConnection::create_acceptor(config).await?;
        drop(config_guard);

        // Create TCP listener
        let (_listener, addr) = tokio::net::TcpListener::bind(local).await.map(|l| {
            let local_addr = l.local_addr().unwrap();
            let sip_addr = SipAddr {
                r#type: Some(rsip::transport::Transport::Tls),
                addr: local_addr.into(),
            };
            (l, sip_addr)
        })?;

        // Add listener to the list
        let mut listeners = self.inner.listens.lock().unwrap();

        listeners.insert(
            addr.clone(),
            SipConnection::Tls(TlsConnection::new_with_acceptor(acceptor, addr.clone())),
        );
        info!("Added TLS listener on {}", addr);
        Ok(addr)
    }

    pub async fn add_ws_listener(
        &self,
        local: SocketAddr,
        sender: TransportSender,
        secure: bool,
    ) -> Result<SipAddr> {
        let config = self.inner.config.lock().unwrap();
        if secure && !config.enable_wss {
            return Err(crate::Error::Error(
                "WSS not enabled in configuration".to_string(),
            ));
        } else if !secure && !config.enable_ws {
            return Err(crate::Error::Error(
                "WS not enabled in configuration".to_string(),
            ));
        }
        drop(config);

        let listener = tokio::net::TcpListener::bind(local).await?;
        let local_addr = listener.local_addr()?;

        let transport_type = if secure {
            rsip::transport::Transport::Wss
        } else {
            rsip::transport::Transport::Ws
        };

        let addr = SipAddr {
            r#type: Some(transport_type),
            addr: local_addr.into(),
        };

        let cancel_token = self.inner.cancel_token.child_token();
        let addr_clone = addr.clone();
        let sender_clone = sender.clone();

        tokio::spawn(async move {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("WebSocket listener cancelled: {}", addr_clone);
                }
                result = WebSocketConnection::serve_listener(listener, addr_clone.clone(), sender_clone, secure) => {
                    if let Err(e) = result {
                        warn!("WebSocket listener error: {}: {:?}", addr_clone, e);
                    }
                }
            }
        });

        Ok(addr)
    }
}

impl TransportLayerInner {
    pub fn add_connection(&self, connection: SipConnection) {
        self.listens
            .lock()
            .unwrap()
            .insert(connection.get_addr().to_owned(), connection);
    }

    pub fn del_connection(&self, addr: &SipAddr) {
        self.listens.lock().unwrap().remove(addr);
    }

    async fn lookup<'a>(
        &'a self,
        uri: &rsip::uri::Uri,
        outbound: Option<&'a SipAddr>,
        sender: TransportSender,
    ) -> Result<(SipConnection, SipAddr)> {
        let target = if let Some(addr) = outbound {
            addr
        } else {
            let context = rsip_dns::Context::initialize_from(
                uri.clone(),
                rsip_dns::AsyncTrustDnsClient::new(
                    TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap(),
                ),
                rsip_dns::SupportedTransports::any(),
            )?;

            let mut lookup = rsip_dns::Lookup::from(context);
            match lookup.resolve_next().await {
                Some(mut target) => {
                    match uri.host_with_port.host {
                        rsip::Host::IpAddr(_) => {
                            if let Some(port) = uri.host_with_port.port {
                                target.port = port;
                            }
                        }
                        _ => {}
                    }
                    &SipAddr {
                        r#type: Some(target.transport),
                        addr: HostWithPort::from(SocketAddr::new(
                            target.ip_addr,
                            u16::from(target.port),
                        )),
                    }
                }
                None => {
                    return Err(crate::Error::DnsResolutionError(format!(
                        "DNS resolution error: {}",
                        uri
                    )))
                }
            }
        };

        info!("lookup target: {} -> {}", uri, target);

        if let Some(transport) = self.listens.lock().unwrap().get(&target) {
            return Ok((transport.clone(), target.clone()));
        }

        match target.r#type {
            Some(rsip::transport::Transport::Udp) => {
                let listens = self.listens.lock().unwrap();
                for (_, transport) in listens.iter() {
                    if transport.get_addr().r#type == Some(rsip::transport::Transport::Udp) {
                        return Ok((transport.clone(), target.clone()));
                    }
                }
            }
            Some(rsip::transport::Transport::Tcp) => {
                let connection = TcpConnection::connect(target).await?;
                let sip_connection = SipConnection::Tcp(connection);
                self.start_serve(sip_connection.clone(), sender);
                return Ok((sip_connection, target.clone()));
            }
            Some(rsip::transport::Transport::Tls) => {
                let connection = TlsConnection::connect(target, None).await?;
                let sip_connection = SipConnection::Tls(connection);
                self.start_serve(sip_connection.clone(), sender);
                return Ok((sip_connection, target.clone()));
            }
            Some(rsip::transport::Transport::Ws) | Some(rsip::transport::Transport::Wss) => {
                let connection = WebSocketConnection::connect(target).await?;
                let sip_connection = SipConnection::WebSocket(connection);
                self.start_serve(sip_connection.clone(), sender);
                return Ok((sip_connection, target.clone()));
            }
            _ => {}
        }

        return Err(crate::Error::TransportLayerError(
            format!("unsupported transport type: {:?}", target.r#type),
            target.to_owned(),
        ));
    }

    pub fn start_serve(&self, transport: SipConnection, sender: TransportSender) {
        let sub_token = self.cancel_token.child_token();
        let sender_clone = sender.clone();
        let listens_ref = self.listens.clone();

        tokio::spawn(async move {
            select! {
                _ = sub_token.cancelled() => { }
                _ = transport.serve_loop(sender_clone.clone()) => {
                }
            }
            listens_ref.lock().unwrap().remove(transport.get_addr());
            warn!("transport serve_loop exited: {}", transport.get_addr());
            sender_clone.send(TransportEvent::Closed(transport)).ok();
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{transport::udp::UdpConnection, Result};
    use rsip::{Host, Transport};
    use rsip_dns::{trust_dns_resolver::TokioAsyncResolver, ResolvableExt};
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());
        let (sender, _receiver) = unbounded_channel();

        let first_uri = "sip:bob@127.0.0.1:5060".try_into().expect("parse uri");
        assert!(tl.lookup(&first_uri, sender.clone()).await.is_err());
        let udp_peer = UdpConnection::create_connection("127.0.0.1:0".parse()?, None).await?;
        let udp_peer_addr = udp_peer.get_addr().to_owned();
        tl.add_transport(udp_peer.into());

        let (target, _) = tl.lookup(&first_uri, sender.clone()).await?;
        assert_eq!(target.get_addr(), &udp_peer_addr);

        // test outbound
        let outbound_peer = UdpConnection::create_connection("127.0.0.1:0".parse()?, None).await?;
        let outbound = outbound_peer.get_addr().to_owned();
        tl.add_transport(outbound_peer.into());
        tl.outbound = Some(outbound.clone());

        // must return the outbound transport
        let (target, _) = tl.lookup(&first_uri, sender.clone()).await?;
        assert_eq!(target.get_addr(), &outbound);
        Ok(())
    }

    #[tokio::test]
    async fn test_tcp_listener() -> Result<()> {
        let tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());
        let (sender, _receiver) = mpsc::unbounded_channel();

        let addr = tl.add_tcp_listener("127.0.0.1:0".parse()?, sender).await?;
        assert_eq!(addr.r#type, Some(rsip::transport::Transport::Tcp));

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
        let (sender, _receiver) = unbounded_channel();

        // Add a UDP connection first
        let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse()?, None).await?;
        let addr = udp_conn.get_addr().clone();
        tl.add_transport(udp_conn.into());

        // Start serving listeners
        tl.serve_listens(sender).await?;

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
