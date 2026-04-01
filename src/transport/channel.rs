use tokio_util::sync::CancellationToken;

use super::{
    connection::{TransportReceiver, TransportSender},
    SipAddr, SipConnection,
};
use crate::Result;
use std::sync::Arc;
use parking_lot::Mutex;

struct ChannelInner {
    incoming: Mutex<Option<TransportReceiver>>,
    outgoing: TransportSender,
    addr: SipAddr,
}

#[derive(Clone)]
pub struct ChannelConnection {
    inner: Arc<ChannelInner>,
    cancel_token: Option<CancellationToken>,
}

impl ChannelConnection {
    pub async fn create_connection(
        incoming: TransportReceiver,
        outgoing: TransportSender,
        addr: SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let t = ChannelConnection {
            inner: Arc::new(ChannelInner {
                incoming: Mutex::new(Some(incoming)),
                outgoing,
                addr,
            }),
            cancel_token,
        };
        Ok(t)
    }

    pub async fn send(&self, msg: crate::sip::SipMessage) -> crate::Result<()> {
        let transport = SipConnection::Channel(self.clone());
        let source = self.get_addr().clone();
        self.inner
            .outgoing
            .send(super::TransportEvent::Incoming(msg, transport, source))
            .map_err(|e| e.into())
    }

    pub fn get_addr(&self) -> &SipAddr {
        &self.inner.addr
    }

    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let mut incoming = match self.inner.clone().incoming.lock().take() {
            Some(incoming) => incoming,
            None => {
                return Err(crate::Error::Error(
                    "ChannelTransport::serve_loop called twice".to_string(),
                ));
            }
        };
        while let Some(event) = incoming.recv().await {
            sender.send(event)?;
        }
        Ok(())
    }
    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

impl std::fmt::Display for ChannelConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "*:*")
    }
}

impl std::fmt::Debug for ChannelConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "*:*")
    }
}
