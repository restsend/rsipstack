use std::net::SocketAddr;
use super::{
    connection::{SipAddr, TransportSender},
    SipConnection,
};
use crate::{transport::TransportEvent, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use rsip::HostWithPort;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use rsip_dns::{trust_dns_resolver::TokioAsyncResolver, ResolvableExt};

#[derive(Default)]
pub struct TransportLayerInner {
    cancel_token: CancellationToken,
    listens: Arc<Mutex<HashMap<SipAddr, SipConnection>>>, // Listen transports
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

    pub async fn lookup(&self, uri: &rsip::uri::Uri) -> Result<SipConnection> {
        self.inner.lookup(uri, self.outbound.as_ref()).await
    }

    pub async fn serve_listens(&self, sender: TransportSender) -> Result<()> {
        self.inner.serve_listens(sender).await
    }
    pub fn get_addrs(&self) -> Vec<SipAddr> {
        self.inner.listens.lock().unwrap().keys().cloned().collect()
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
    ) -> Result<SipConnection> {
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
                Some(target) => {
                    &SipAddr {
                        r#type: Some(target.transport),
                        addr: HostWithPort::from(SocketAddr::new(target.ip_addr, u16::from(target.port)))
                    }
                },
                None => {
                    return Err(crate::Error::DnsResolutionError(
                        format!("DNS resolution error: {}", uri)
                    ))
                }
            }
        };

        info!("lookup target: {} -> {}", uri, target);

        if let Some(transport) = self.listens.lock().unwrap().get(&target) {
            return Ok(transport.clone());
        }

        match target.r#type {
            Some(rsip::transport::Transport::Udp) => {
                let listens = self.listens.lock().unwrap();
                // lookup first udp transport
                for (_, transport) in listens.iter() {
                    if transport.get_addr().r#type == Some(rsip::transport::Transport::Udp) {
                        return Ok(transport.clone());
                    }
                }
            }
            Some(rsip::transport::Transport::Tcp)
            | Some(rsip::transport::Transport::Tls)
            | Some(rsip::transport::Transport::Ws) => {
                // create new transport and serve it
                todo!()
            }
            _ => {}
        }
        return Err(crate::Error::TransportLayerError(
            format!("unsupported transport type: {:?}", target.r#type),
            target.to_owned(),
        ));
    }

    async fn serve_listens(&self, sender: TransportSender) -> Result<()> {
        let listens = self.listens.lock().unwrap().clone();
        for (_, transport) in listens {
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
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use crate::{transport::udp::UdpConnection, Result};
    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        let first_uri = "sip:bob@127.0.0.1:5060".try_into().expect("parse uri");
        assert!(tl.lookup(&first_uri).await.is_err());
        let udp_peer = UdpConnection::create_connection("127.0.0.1:0".parse()?, None).await?;
        let udp_peer_addr = udp_peer.get_addr().to_owned();
        tl.add_transport(udp_peer.into());

        let target = tl.lookup(&first_uri).await?;
        assert_eq!(target.get_addr(), &udp_peer_addr);

        // test outbound
        let outbound_peer = UdpConnection::create_connection("127.0.0.1:0".parse()?, None).await?;
        let outbound = outbound_peer.get_addr().to_owned();
        tl.add_transport(outbound_peer.into());
        tl.outbound = Some(outbound.clone());

        // must return the outbound transport
        let target = tl.lookup(&first_uri).await?;
        assert_eq!(target.get_addr(), &outbound);
        Ok(())
    }
}
