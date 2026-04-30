use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{
    connection::{TransportReceiver, TransportSender},
    SipAddr, SipConnection,
};
use crate::Result;
use parking_lot::Mutex;
use std::sync::Arc;

enum Outgoing {
    Unbounded(TransportSender),
    Bounded(mpsc::Sender<super::TransportEvent>),
}

struct ChannelInner {
    incoming: Mutex<Option<TransportReceiver>>,
    outgoing: Outgoing,
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
        Self::create_connection_inner(
            incoming,
            Outgoing::Unbounded(outgoing),
            addr,
            cancel_token,
        )
        .await
    }

    pub async fn create_connection_bounded(
        incoming: TransportReceiver,
        outgoing: mpsc::Sender<super::TransportEvent>,
        addr: SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        Self::create_connection_inner(
            incoming,
            Outgoing::Bounded(outgoing),
            addr,
            cancel_token,
        )
        .await
    }

    async fn create_connection_inner(
        incoming: TransportReceiver,
        outgoing: Outgoing,
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
        let event = super::TransportEvent::Incoming(msg, transport, source);

        match &self.inner.outgoing {
            Outgoing::Unbounded(tx) => tx.send(event).map_err(|e| e.into()),
            Outgoing::Bounded(tx) => tx.send(event).await.map_err(|e| e.into()),
        }
    }

    pub fn try_send(&self, msg: crate::sip::SipMessage) -> crate::Result<()> {
        let transport = SipConnection::Channel(self.clone());
        let source = self.get_addr().clone();
        let event = super::TransportEvent::Incoming(msg, transport, source);

        match &self.inner.outgoing {
            Outgoing::Unbounded(tx) => tx.send(event).map_err(|e| e.into()),
            Outgoing::Bounded(tx) => tx.try_send(event).map_err(|e| e.into()),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::{HostWithPort, Request, SipMessage, Version};

    fn test_sip_addr() -> SipAddr {
        SipAddr {
            r#type: None,
            addr: HostWithPort {
                host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
                port: Some(5060.into()),
            },
        }
    }

    fn test_message() -> SipMessage {
        SipMessage::Request(Request {
            method: crate::sip::Method::Invite,
            uri: crate::sip::Uri::try_from("sip:test@example.com").unwrap(),
            headers: vec![].into(),
            version: Version::V2,
            body: vec![],
        })
    }

    #[tokio::test]
    async fn test_create_connection_bounded_send_receive() {
        let (_incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let conn = ChannelConnection::create_connection_bounded(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection_bounded");

        let msg = test_message();
        conn.send(msg).await.expect("send via bounded channel");

        let received = outgoing_rx.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_try_send_on_bounded() {
        let (_incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(2);
        let conn = ChannelConnection::create_connection_bounded(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection_bounded");

        let msg = test_message();
        conn.try_send(msg).expect("try_send on bounded");

        let received = outgoing_rx.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_try_send_on_unbounded() {
        let (_incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
        let conn = ChannelConnection::create_connection(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection");

        let msg = test_message();
        conn.try_send(msg).expect("try_send on unbounded");

        let received = outgoing_rx.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_try_send_bounded_full() {
        let (_incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(1);
        let conn = ChannelConnection::create_connection_bounded(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection_bounded");

        conn.try_send(test_message()).expect("first send");
        let result = conn.try_send(test_message());
        assert!(result.is_err(), "try_send on full bounded channel should return error");
    }

    #[tokio::test]
    async fn test_bounded_connection_serve_loop() {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<super::super::TransportEvent>();
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(16);
        let conn = ChannelConnection::create_connection_bounded(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection_bounded");

        // Serve loop in background, forwarding events
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let serve_conn = conn.clone();
        tokio::spawn(async move {
            let _ = serve_conn.serve_loop(event_tx).await;
        });

        // Send a message through the incoming channel
        let msg = test_message();
        let transport = SipConnection::Channel(conn.clone());
        let source = conn.get_addr().clone();
        let event = super::super::TransportEvent::Incoming(msg, transport, source);
        let _ = incoming_tx.send(event);

        // Give the serve loop time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn test_bounded_serve_loop_twice_returns_error() {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<super::super::TransportEvent>();
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(16);
        let conn = ChannelConnection::create_connection_bounded(incoming_rx, outgoing_tx, test_sip_addr(), None)
            .await
            .expect("create_connection_bounded");

        // Drop the sender so the incoming channel is closed
        drop(incoming_tx);

        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let result = conn.serve_loop(event_tx).await;
        // First serve_loop should succeed (incoming channel is closed, so recv returns None)
        assert!(result.is_ok());

        // Second serve_loop should fail since incoming was already taken
        let (event_tx2, _event_rx2) = mpsc::unbounded_channel();
        let result2 = conn.serve_loop(event_tx2).await;
        assert!(result2.is_err());
    }
}
