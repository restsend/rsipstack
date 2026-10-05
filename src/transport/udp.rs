use super::{connection::TransportSender, SipAddr, SipConnection};
use crate::sip::prelude::HeadersExt;
use crate::{
    transport::transport_layer::TransportLayerInnerRef,
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE, MAX_UDP_BUF_SIZE},
        TransportEvent,
    },
    Result,
};
use bytes::BytesMut;
use crate::platform::net::UdpSocket as PlatformUdpSocket;
use crate::platform::CancellationToken;
#[cfg(feature = "platform-tokio")]
use socket2::{Domain, Protocol, Socket, Type};
use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use core::net::SocketAddr;
use alloc::sync::Arc;
use tracing::{debug, info, warn};
pub struct UdpInner {
    pub conn: Arc<dyn PlatformUdpSocket>,
    pub addr: SipAddr,
}

#[derive(Clone)]
pub struct UdpConnection {
    pub external: Option<SipAddr>,
    remote: Option<SipAddr>,
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
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: SipConnection::resolve_bind_address(addr).into(),
            }),
            remote: None,
            inner: Arc::new(inner),
            cancel_token,
        }
    }

    /// Backend-agnostic constructor: wraps an already-created platform
    /// socket. Embedded backends (embassy-net adapters) build their socket
    /// and hand it over here; `addr` must be the socket's local address.
    pub async fn from_socket(
        conn: Arc<dyn PlatformUdpSocket>,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Udp),
            addr: SipConnection::resolve_bind_address(conn.local_addr()?).into(),
        };
        let t = UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            }),
            remote: None,
            inner: Arc::new(UdpInner { addr, conn }),
            cancel_token,
        };
        debug!(local = %t, ?external, "created UDP connection (platform socket)");
        Ok(t)
    }

    #[cfg(feature = "platform-tokio")]
    pub async fn create_connection(
        local: SocketAddr,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let domain = if local.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        match socket.set_reuse_address(true) {
            Ok(_) => (),
            Err(e) => {
                warn!(error = %e, "Failed to set SO_REUSEADDR on UDP socket");
            }
        }
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        let conn: Arc<dyn PlatformUdpSocket> =
            Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        let addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Udp),
            addr: SipConnection::resolve_bind_address(conn.local_addr()?).into(),
        };

        let t = UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            }),
            remote: None,
            inner: Arc::new(UdpInner { addr, conn }),
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
            // Race cancellation against the next datagram (backend-agnostic
            // combinator; both arms cancelled cleanly when one wins). The
            // block scopes the pinned recv future so `buf` is released
            // before the packet is parsed below.
            let (len, addr) = {
                let mut cancel_f = core::pin::pin!(async {
                    if let Some(ref cancel_token) = self.cancel_token {
                        cancel_token.cancelled().await;
                    } else {
                        core::future::pending::<()>().await;
                    }
                });
                let mut recv_f = core::pin::pin!(self.inner.conn.recv_from(&mut buf));
                match crate::platform::select::select2(&mut cancel_f, &mut recv_f).await {
                    crate::platform::select::Either::A(()) => {
                        debug!(local = %self.get_addr(), "UDP serve_loop cancelled");
                        return Ok(());
                    }
                    crate::platform::select::Either::B(result) => match result {
                        Ok((len, addr)) => (len, addr),
                        Err(e) => {
                            warn!(error = %e, "error receiving UDP packet");
                            continue;
                        }
                    },
                }
            };

            if let Some(transport_layer_inner) = &transport_layer_inner {
                if !transport_layer_inner.is_whitelisted(addr.ip()).await {
                    debug!(src = %addr, "udp packet rejected by whitelist");
                    continue;
                }
            }

            let packet = &buf[..len];

            match packet {
                KEEPALIVE_REQUEST => {
                    self.inner.conn.send_to(KEEPALIVE_RESPONSE, addr).await.ok();
                    continue;
                }
                KEEPALIVE_RESPONSE => continue,
                _ => {
                    if packet.iter().all(|&b| b.is_ascii_whitespace()) {
                        continue;
                    }
                }
            }

            let raw_message = String::from_utf8_lossy(packet);

            let msg = match crate::sip::SipMessage::try_from(packet) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = %e,
                        raw_message = ?raw_message,
                        "error parsing SIP message"
                    );
                    continue;
                }
            };

            let msg = match SipConnection::update_msg_received(
                msg,
                addr,
                crate::sip::transport::Transport::Udp,
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    info!(
                        src = %addr,
                        error = ?e,
                        raw_message = ?raw_message,
                        "error updating SIP via"
                    );
                    continue;
                }
            };

            let cseq = msg
                .cseq_header()
                .map(|c| c.value().to_string())
                .unwrap_or_default();
            info!(len, src=%addr, dest=%self.get_addr(), cseq = %cseq, raw_message = ?raw_message, "udp received");

            let from = SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            };

            sender.send(TransportEvent::Incoming(
                msg,
                SipConnection::Udp(Self {
                    external: self.external.clone(),
                    remote: Some(from.clone()),
                    cancel_token: self.cancel_token.clone(),
                    inner: self.inner.clone(),
                }),
                from,
            ))?;
        }
    }

    pub async fn send(
        &self,
        msg: crate::sip::SipMessage,
        destination: Option<&SipAddr>,
    ) -> crate::Result<()> {
        let destination = match destination {
            Some(addr) => addr.get_socketaddr(),
            None => SipConnection::get_destination(&msg),
        }?;
        // Use to_bytes() (not to_string()) so binary bodies are preserved
        // byte-for-byte; a SIP body is opaque octets (RFC 3261 §7.4).
        let buf = msg.to_bytes();

        let cseq = msg
            .cseq_header()
            .map(|c| c.value().to_string())
            .unwrap_or_default();
        info!(len=buf.len(), dest=%destination, src=%self.get_addr(), cseq = %cseq, raw_message = ?String::from_utf8_lossy(&buf), "udp send");

        self.inner
            .conn
            .send_to(&buf, destination)
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
                r#type: Some(crate::sip::transport::Transport::Udp),
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

    pub fn get_remote_addr(&self) -> Option<&SipAddr> {
        self.remote.as_ref()
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

impl core::fmt::Display for UdpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.inner.conn.local_addr() {
            Ok(addr) => write!(f, "{}", addr),
            Err(_) => write!(f, "*:*"),
        }
    }
}

impl core::fmt::Debug for UdpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.inner.addr)
    }
}

impl Drop for UdpInner {
    fn drop(&mut self) {
        debug!(addr = %self.addr, "dropping UDP transport");
    }
}
