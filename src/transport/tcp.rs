use crate::{
    transport::{
        connection::TransportSender,
        sip_addr::SipAddr,
        stream::{StreamConnection, StreamConnectionInner},
        SipConnection,
    },
    Result,
};
use rsip::SipMessage;
use std::{fmt, sync::Arc};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

type TcpInner =
    StreamConnectionInner<tokio::io::ReadHalf<TcpStream>, tokio::io::WriteHalf<TcpStream>>;

#[derive(Clone)]
pub struct TcpConnection {
    pub inner: Arc<TcpInner>,
    pub cancel_token: Option<CancellationToken>,
}

impl TcpConnection {
    pub async fn connect(
        remote: &SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let socket_addr = remote.get_socketaddr()?;
        let stream = TcpStream::connect(socket_addr).await?;

        let local_addr = SipAddr {
            r#type: Some(rsip::transport::Transport::Tcp),
            addr: SipConnection::resolve_bind_address(stream.local_addr()?).into(),
        };

        let (read_half, write_half) = tokio::io::split(stream);

        let connection = TcpConnection {
            inner: Arc::new(StreamConnectionInner::new(
                local_addr.clone(),
                remote.clone(),
                read_half,
                write_half,
            )),
            cancel_token,
        };

        debug!(
            local = %local_addr,
            remote = %remote,
            "Created TCP client connection"
        );

        Ok(connection)
    }

    pub fn from_stream(
        stream: TcpStream,
        local_addr: SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let remote_addr = stream.peer_addr()?;
        let remote_sip_addr = SipAddr {
            r#type: Some(rsip::transport::Transport::Tcp),
            addr: remote_addr.into(),
        };

        let (read_half, write_half) = tokio::io::split(stream);

        let connection = TcpConnection {
            inner: Arc::new(StreamConnectionInner::new(
                local_addr,
                remote_sip_addr,
                read_half,
                write_half,
            )),
            cancel_token,
        };

        debug!(
            local = %connection.inner.local_addr,
            remote = %remote_addr,
            "Created TCP server connection"
        );

        Ok(connection)
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

#[async_trait::async_trait]
impl StreamConnection for TcpConnection {
    fn get_addr(&self) -> &SipAddr {
        &self.inner.remote_addr
    }

    async fn send_message(&self, msg: SipMessage) -> Result<()> {
        self.inner.send_message(msg).await
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        self.inner.send_raw(data).await
    }

    async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let sip_connection = SipConnection::Tcp(self.clone());
        self.inner.serve_loop(sender, sip_connection).await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

impl fmt::Display for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {} -> {}",
            self.inner.local_addr, self.inner.remote_addr
        )
    }
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
