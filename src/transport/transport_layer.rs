use super::{
    transport::{SipAddr, TransportSender},
    Transport,
};
use crate::{transport::TransportEvent, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Default)]
pub struct TransportLayerInner {
    cancel_token: CancellationToken,
    listens: Arc<Mutex<HashMap<SipAddr, Transport>>>, // Listen transports
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

    pub fn add_transport(&self, transport: Transport) {
        self.inner.add_transport(transport)
    }

    pub fn del_transport(&self, addr: &SipAddr) {
        self.inner.del_transport(addr)
    }

    pub async fn lookup(&self, uri: &rsip::uri::Uri) -> Result<Transport> {
        self.inner.lookup(uri, self.outbound.clone()).await
    }

    pub async fn serve(&self, sender: TransportSender) -> Result<()> {
        self.inner.serve(sender).await
    }
}

impl TransportLayerInner {
    pub fn add_transport(&self, transport: Transport) {
        self.listens
            .lock()
            .unwrap()
            .insert(transport.get_addr().to_owned(), transport);
    }

    pub fn del_transport(&self, addr: &SipAddr) {
        self.listens.lock().unwrap().remove(addr);
    }

    async fn lookup(&self, uri: &rsip::uri::Uri, outbound: Option<SipAddr>) -> Result<Transport> {
        let target = if outbound.is_none() {
            let target_host_port = uri.host_with_port.to_owned();
            let mut r#type = uri.scheme.as_ref().map(|scheme| match scheme {
                rsip::Scheme::Sip => rsip::transport::Transport::Udp,
                rsip::Scheme::Sips => rsip::transport::Transport::Tls,
                rsip::Scheme::Other(schema) => {
                    if schema.eq_ignore_ascii_case("ws") {
                        rsip::transport::Transport::Ws
                    } else if schema.eq_ignore_ascii_case("wss") {
                        rsip::transport::Transport::Wss
                    } else {
                        rsip::transport::Transport::Udp
                    }
                }
            });
            uri.params.iter().for_each(|param| {
                if let rsip::common::uri::Param::Transport(transport) = param {
                    r#type = Some(transport.clone());
                }
            });
            let addr = target_host_port.try_into()?;
            SipAddr { r#type, addr }
        } else {
            outbound.unwrap()
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
            target,
        ));
    }

    async fn serve(&self, sender: TransportSender) -> Result<()> {
        let listens = self.listens.lock().unwrap().clone();

        for (_, transport) in listens {
            let sender = sender.clone();
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
                sender_clone
                    .send(TransportEvent::TransportClosed(transport))
                    .ok();
            });
        }
        self.cancel_token.cancelled().await;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use crate::{transport::udp::UdpTransport, Result};
    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        let first_uri = "sip:bob@127.0.0.1:5060".try_into().expect("parse uri");
        assert!(tl.lookup(&first_uri).await.is_err());
        let udp_peer = UdpTransport::create_connection("127.0.0.1:0".parse()?, None).await?;
        let udp_peer_addr = udp_peer.get_addr().to_owned();
        tl.add_transport(udp_peer.into());

        let target = tl.lookup(&first_uri).await?;
        assert_eq!(target.get_addr(), &udp_peer_addr);

        let outbound_peer = UdpTransport::create_connection("127.0.0.1:0".parse()?, None).await?;
        let outbound = outbound_peer.get_addr().to_owned();
        tl.add_transport(outbound_peer.into());
        tl.outbound = Some(outbound.clone());

        let target = tl.lookup(&first_uri).await?;
        assert_eq!(target.get_addr(), &outbound);
        Ok(())
    }
}
