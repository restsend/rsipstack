use super::{connection::TransportSender, SipAddr, SipConnection};
use crate::{
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE, MAX_UDP_BUF_SIZE},
        TransportEvent,
    },
    Result,
};
use bytes::BytesMut;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
pub struct UdpInner {
    pub conn: UdpSocket,
    pub addr: SipAddr,
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
            inner: Arc::new(UdpInner { addr, conn }),
            cancel_token,
        };
        info!("created UDP connection: {} external: {:?}", t, external);
        Ok(t)
    }

    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
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
                    debug!("UDP serve_loop cancelled");
                    return Ok(());
                }
                // Receive UDP packets
                result = self.inner.conn.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => (len, addr),
                        Err(e) => {
                            warn!("error receiving UDP packet: {}", e);
                            continue;
                        }
                    }
                }
            };

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
                        "decoding text from: {} error: {} buf: {:?}",
                        addr,
                        e,
                        &buf[..len]
                    );
                    continue;
                }
            };

            let msg = match rsip::SipMessage::try_from(undecoded) {
                Ok(msg) => msg,
                Err(e) => {
                    info!(
                        "error parsing SIP message from: {} error: {} buf: {}",
                        addr, e, undecoded
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
                    info!(
                        "error updating SIP via from: {} error: {:?} buf: {}",
                        addr, e, undecoded
                    );
                    continue;
                }
            };

            debug!(
                len, src=%addr,dest=%self.get_addr(), message=undecoded,
                "udp received"
            );

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

        debug!(len=buf.len(), src=%self.get_addr(),
        dest=%destination, message=%buf,
        "udp send");

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
        //trace!("send_raw {} -> {}", buf.len(), target);
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
        // trace!("received {} -> {}", len, addr);
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
    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
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
        info!("dropping UDP transport: {}", self.addr);
    }
}
