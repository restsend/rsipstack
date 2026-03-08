use super::{connection::TransportSender, SipAddr, SipConnection};
use crate::{
    transport::transport_layer::TransportLayerInnerRef,
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE, MAX_UDP_BUF_SIZE},
        TransportEvent,
    },
    Result,
};
use arc_swap::ArcSwapOption;
use bytes::BytesMut;
use rsip::prelude::HeadersExt;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub struct UdpInner {
    pub conn: UdpSocket,
    pub addr: SipAddr,
    pub learned_public_addr: ArcSwapOption<SocketAddr>,
    pub auto_learn_public_addr: bool,
}

#[derive(Clone)]
pub struct UdpConnection {
    pub external: Option<SipAddr>,
    cancel_token: Option<CancellationToken>,
    inner: Arc<UdpInner>,
}

impl UdpConnection {
    pub async fn attach(
        inner: UdpInner,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Self {
        Self::attach_with_auto_learn_public_addr(inner, external, cancel_token, false).await
    }

    pub async fn attach_with_auto_learn_public_addr(
        mut inner: UdpInner,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
        auto_learn_public_addr: bool,
    ) -> Self {
        inner.auto_learn_public_addr = auto_learn_public_addr;
        UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(rsip::transport::Transport::Udp),
                addr: SipConnection::resolve_bind_address(addr).into(),
            }),
            inner: Arc::new(inner),
            cancel_token,
        }
    }

    pub async fn create_connection(
        local: SocketAddr,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        Self::create_connection_with_auto_learn_public_addr(local, external, cancel_token, false)
            .await
    }

    pub async fn create_connection_with_auto_learn_public_addr(
        local: SocketAddr,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
        auto_learn_public_addr: bool,
    ) -> Result<Self> {
        let conn = UdpSocket::bind(local).await?;

        let addr = SipAddr {
            r#type: Some(rsip::transport::Transport::Udp),
            addr: SipConnection::resolve_bind_address(conn.local_addr()?).into(),
        };

        let t = UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(rsip::transport::Transport::Udp),
                addr: addr.into(),
            }),
            inner: Arc::new(UdpInner {
                addr,
                conn,
                learned_public_addr: ArcSwapOption::empty(),
                auto_learn_public_addr,
            }),
            cancel_token,
        };
        debug!(local = %t, ?external, "created UDP connection");
        Ok(t)
    }

    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        self.serve_loop_with_whitelist(sender, None).await
    }

    pub async fn serve_loop_with_whitelist(
        &self,
        sender: TransportSender,
        transport_layer_inner: Option<TransportLayerInnerRef>,
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(MAX_UDP_BUF_SIZE);
        buf.resize(MAX_UDP_BUF_SIZE, 0);
        loop {
            let (len, addr) = tokio::select! {
                // Check for cancellation on each iteration
                _ = async {
                    if let Some(ref cancel_token) = self.cancel_token {
                        cancel_token.cancelled().await;
                    } else {
                        // If no cancel token, wait forever
                        std::future::pending::<()>().await;
                    }
                } => {
                    debug!(local = %self.get_addr(), "UDP serve_loop cancelled");
                    return Ok(());
                }
                // Receive UDP packets
                result = self.inner.conn.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => (len, addr),
                        Err(e) => {
                            warn!(error = %e, "error receiving UDP packet");
                            continue;
                        }
                    }
                }
            };

            if let Some(transport_layer_inner) = &transport_layer_inner {
                if !transport_layer_inner.is_whitelisted(addr.ip()).await {
                    debug!(src = %addr, "udp packet rejected by whitelist");
                    continue;
                }
            }

            match &buf[..len] {
                KEEPALIVE_REQUEST => {
                    self.inner.conn.send_to(KEEPALIVE_RESPONSE, addr).await.ok();
                    continue;
                }
                KEEPALIVE_RESPONSE => continue,
                _ => {
                    if buf.iter().all(|&b| b.is_ascii_whitespace()) {
                        continue;
                    }
                }
            }

            let undecoded = match std::str::from_utf8(&buf[..len]) {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = %e,
                        buf = ?&buf[..len],
                        "decoding text error"
                    );
                    continue;
                }
            };

            let msg = match rsip::SipMessage::try_from(undecoded) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = %e,
                        raw_message = %undecoded,
                        "error parsing SIP message"
                    );
                    continue;
                }
            };

            let msg = match SipConnection::update_msg_received(
                msg,
                addr,
                rsip::transport::Transport::Udp,
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = ?e,
                        raw_message = %undecoded,
                        "error updating SIP via"
                    );
                    continue;
                }
            };

            if self.external.is_none() && self.inner.auto_learn_public_addr {
                self.learn_public_addr_from_message(&msg);
            }

            debug!(len, src=%addr, dest=%self.get_addr(), raw_message=undecoded, "udp received");

            sender.send(TransportEvent::Incoming(
                msg,
                SipConnection::Udp(self.clone()),
                SipAddr {
                    r#type: Some(rsip::transport::Transport::Udp),
                    addr: addr.into(),
                },
            ))?;
        }
    }

    pub async fn send(
        &self,
        msg: rsip::SipMessage,
        destination: Option<&SipAddr>,
    ) -> crate::Result<()> {
        let destination = match destination {
            Some(addr) => addr.get_socketaddr(),
            None => SipConnection::get_destination(&msg),
        }?;
        let buf = msg.to_string();

        debug!(len=buf.len(), dest=%destination, src=%self.get_addr(), raw_message=buf, "udp send");

        self.inner
            .conn
            .send_to(buf.as_bytes(), destination)
            .await
            .map_err(|e| {
                crate::Error::TransportLayerError(e.to_string(), self.get_addr().to_owned())
            })
            .map(|_| ())
    }

    pub async fn send_raw(&self, buf: &[u8], destination: &SipAddr) -> Result<()> {
        self.inner
            .conn
            .send_to(buf, destination.get_socketaddr()?)
            .await
            .map_err(|e| {
                crate::Error::TransportLayerError(e.to_string(), self.get_addr().to_owned())
            })
            .map(|_| ())
    }

    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<(usize, SipAddr)> {
        let (len, addr) = self.inner.conn.recv_from(buf).await?;
        Ok((
            len,
            SipAddr {
                r#type: Some(rsip::transport::Transport::Udp),
                addr: addr.into(),
            },
        ))
    }

    pub fn get_addr(&self) -> &SipAddr {
        if let Some(external) = &self.external {
            external
        } else {
            &self.inner.addr
        }
    }

    pub fn get_contact_addr(&self) -> SipAddr {
        if let Some(external) = &self.external {
            external.clone()
        } else {
            self.inner
                .learned_public_addr
                .load_full()
                .map(|addr| SipAddr {
                    r#type: Some(rsip::transport::Transport::Udp),
                    addr: (*addr).into(),
                })
                .unwrap_or_else(|| self.inner.addr.clone())
        }
    }
    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }

    fn learn_public_addr_from_message(&self, msg: &rsip::SipMessage) {
        let response = match msg {
            rsip::SipMessage::Response(resp) => resp,
            rsip::SipMessage::Request(_) => return,
        };

        let via = match response.via_header() {
            Ok(via) => via,
            Err(_) => return,
        };

        let target = match SipConnection::parse_target_from_via(via) {
            Ok((transport, host_with_port)) if transport == rsip::transport::Transport::Udp => {
                match host_with_port.try_into() {
                    Ok(addr) => addr,
                    Err(_) => return,
                }
            }
            _ => return,
        };

        let current = self.inner.learned_public_addr.load();
        let changed = current.as_deref() != Some(&target);
        if changed {
            debug!(addr = %target, "udp learned public address");
            self.inner.learned_public_addr.store(Some(Arc::new(target)));
        }
    }
}

impl std::fmt::Display for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.conn.local_addr() {
            Ok(addr) => write!(f, "{}", addr),
            Err(_) => write!(f, "*:*"),
        }
    }
}

impl std::fmt::Debug for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.addr)
    }
}

impl Drop for UdpInner {
    fn drop(&mut self) {
        debug!(addr = %self.addr, "dropping UDP transport");
    }
}
