use crate::platform::CancellationToken;
use crate::transport::tcp::TcpConnection;
use crate::transport::transport_layer::TransportLayerInnerRef;
use crate::transport::SipAddr;
use crate::transport::SipConnection;
use crate::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::fmt;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};
pub struct TcpListenerConnectionInner {
    pub local_addr: SipAddr,
    pub external: Option<SipAddr>,
}

#[derive(Clone)]
pub struct TcpListenerConnection {
    pub inner: Arc<TcpListenerConnectionInner>,
}

impl TcpListenerConnection {
    pub async fn new(local_addr: SocketAddr, external: Option<SocketAddr>) -> Result<Self> {
        let inner = TcpListenerConnectionInner {
            local_addr: SipAddr {
                r#type: Some(crate::sip::transport::Transport::Tcp),
                addr: local_addr.into(),
            },
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Tcp),
                addr: addr.into(),
            }),
        };
        Ok(TcpListenerConnection {
            inner: Arc::new(inner),
        })
    }

    pub async fn serve_listener(
        &self,
        transport_layer_inner: TransportLayerInnerRef,
    ) -> Result<()> {
        let local = self.inner.local_addr.get_socketaddr()?;
        let domain = if local.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if let Err(e) = socket.set_reuse_address(true) {
            warn!(error = %e, "failed to set SO_REUSEADDR on TCP listener");
        }
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from_std(socket.into())?;
        let listener_local_addr = self.get_addr().clone();
        crate::platform::spawn(async move {
            loop {
                let (stream, remote_addr) =
                    match accept_or_cancelled(&listener, &transport_layer_inner.cancel_token).await
                    {
                        Some(Ok((stream, remote_addr))) => (stream, remote_addr),
                        Some(Err(e)) => {
                            warn!(error = ?e, "Failed to accept connection");
                            continue;
                        }
                        None => {
                            debug!(local = %listener_local_addr, "TCP listener cancelled");
                            break;
                        }
                    };
                if !transport_layer_inner.is_whitelisted(remote_addr.ip()).await {
                    debug!(remote = %remote_addr, "tcp connection rejected by whitelist");
                    continue;
                }
                let local_addr = listener_local_addr.clone();
                let tcp_connection = match TcpConnection::from_stream(
                    stream,
                    local_addr.clone(),
                    Some(transport_layer_inner.cancel_token.child_token()),
                ) {
                    Ok(tcp_connection) => tcp_connection,
                    Err(e) => {
                        warn!(error = ?e, %local_addr, "Failed to create TCP connection");
                        continue;
                    }
                };
                let sip_connection = SipConnection::Tcp(tcp_connection.clone());
                transport_layer_inner.add_connection(sip_connection.clone());
                debug!(?local_addr, "new tcp connection");
            }
        });
        Ok(())
    }
}

/// Accepts the next connection, or returns `None` once `cancel_token` fires.
///
/// Listener accept loops run in detached tasks; racing the token lets them exit
/// and release the listening socket (and the transport layer they hold) when the
/// transport layer is cancelled.
pub(crate) async fn accept_or_cancelled(
    listener: &TcpListener,
    cancel_token: &CancellationToken,
) -> Option<std::io::Result<(TcpStream, SocketAddr)>> {
    let mut cancel_f = core::pin::pin!(cancel_token.cancelled());
    let mut accept_f = core::pin::pin!(listener.accept());
    match crate::platform::select::select2(&mut cancel_f, &mut accept_f).await {
        crate::platform::select::Either::A(()) => None,
        crate::platform::select::Either::B(accepted) => Some(accepted),
    }
}

impl TcpListenerConnection {
    pub fn get_addr(&self) -> &SipAddr {
        if let Some(external) = &self.inner.external {
            external
        } else {
            &self.inner.local_addr
        }
    }

    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl fmt::Display for TcpListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP Listener {}", self.get_addr())
    }
}

impl fmt::Debug for TcpListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
