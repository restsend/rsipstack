use crate::{
    transport::{
        connection::{TransportSender, KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        sip_addr::SipAddr,
        stream::StreamConnection,
        transport_layer::TransportLayerInnerRef,
        SipConnection, TransportEvent,
    },
    Result,
};
use futures_util::{SinkExt, StreamExt};
use rsip::SipMessage;
use std::{fmt, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request, Response},
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

// Define a type alias for the WebSocket sink to make the code more readable
type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;
type WsRead =
    futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

// WebSocket Listener Connection Structure
pub struct WebSocketListenerConnectionInner {
    pub local_addr: SipAddr,
    pub external: Option<SipAddr>,
    pub is_secure: bool,
}

#[derive(Clone)]
pub struct WebSocketListenerConnection {
    pub inner: Arc<WebSocketListenerConnectionInner>,
}

impl WebSocketListenerConnection {
    pub async fn new(
        local_addr: SipAddr,
        external: Option<SocketAddr>,
        is_secure: bool,
    ) -> Result<Self> {
        let transport_type = if is_secure {
            rsip::transport::Transport::Wss
        } else {
            rsip::transport::Transport::Ws
        };

        let inner = WebSocketListenerConnectionInner {
            local_addr,
            external: external.map(|addr| SipAddr {
                r#type: Some(transport_type),
                addr: addr.into(),
            }),
            is_secure,
        };
        Ok(WebSocketListenerConnection {
            inner: Arc::new(inner),
        })
    }

    pub async fn serve_listener(
        &self,
        transport_layer_inner: TransportLayerInnerRef,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.inner.local_addr.get_socketaddr()?).await?;
        let transport_type = if self.inner.is_secure {
            rsip::transport::Transport::Wss
        } else {
            rsip::transport::Transport::Ws
        };

        debug!(local = %self.inner.local_addr, "Starting WebSocket listener");
        tokio::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok((stream, remote_addr)) => (stream, remote_addr),
                    Err(e) => {
                        warn!(error = ?e, "Failed to accept WebSocket connection");
                        continue;
                    }
                };

                debug!(remote = %remote_addr, "New WebSocket connection");

                let remote_addr = SipAddr {
                    r#type: Some(transport_type),
                    addr: remote_addr.into(),
                };
                let transport_layer_inner_ref = transport_layer_inner.clone();
                tokio::spawn(async move {
                    // Wrap the TCP stream in MaybeTlsStream
                    let maybe_tls_stream = MaybeTlsStream::Plain(stream);

                    // Accept the WebSocket connection with custom header handling
                    let callback = |req: &Request, mut response: Response| {
                        // Check if client requested 'sip' subprotocol
                        if let Some(protocols) = req.headers().get("sec-websocket-protocol") {
                            if let Ok(protocols_str) = protocols.to_str() {
                                if protocols_str.contains("sip") {
                                    // Add the 'sip' subprotocol to response
                                    response
                                        .headers_mut()
                                        .insert("sec-websocket-protocol", "sip".parse().unwrap());
                                }
                            }
                        }
                        Ok(response)
                    };

                    let ws_stream = match tokio_tungstenite::accept_hdr_async(
                        maybe_tls_stream,
                        callback,
                    )
                    .await
                    {
                        Ok(ws) => ws,
                        Err(e) => {
                            warn!(error = %e, remote = %remote_addr, "Error upgrading to WebSocket");
                            return;
                        }
                    };

                    let (ws_sink, ws_read) = ws_stream.split();
                    let connection = WebSocketConnection {
                        inner: Arc::new(WebSocketInner {
                            remote_addr,
                            ws_sink: Mutex::new(ws_sink),
                            ws_read: Mutex::new(Some(ws_read)),
                        }),
                        cancel_token: Some(transport_layer_inner_ref.cancel_token.child_token()),
                    };
                    let sip_connection = SipConnection::WebSocket(connection.clone());
                    let connection_addr = connection.get_addr().clone();
                    transport_layer_inner_ref.add_connection(sip_connection.clone());
                    debug!(?connection_addr, "new websocket connection");
                });
            }
        });
        Ok(())
    }

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

impl fmt::Display for WebSocketListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = if self.inner.is_secure { "WSS" } else { "WS" };
        write!(f, "{} Listener {}", transport, self.get_addr())
    }
}

impl fmt::Debug for WebSocketListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct WebSocketInner {
    pub remote_addr: SipAddr,
    pub ws_sink: Mutex<WsSink>,
    pub ws_read: Mutex<Option<WsRead>>,
}

#[derive(Clone)]
pub struct WebSocketConnection {
    pub inner: Arc<WebSocketInner>,
    pub cancel_token: Option<CancellationToken>,
}

impl WebSocketConnection {
    pub async fn connect(
        remote: &SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let scheme = match remote.r#type {
            Some(rsip::transport::Transport::Wss) => "wss",
            _ => "ws",
        };

        let host = match &remote.addr.host {
            rsip::host_with_port::Host::Domain(domain) => domain.to_string(),
            rsip::host_with_port::Host::IpAddr(ip) => ip.to_string(),
        };

        let port = remote.addr.port.as_ref().map_or(5060, |p| *p.value());

        let url = format!("{}://{}:{}/", scheme, host, port);
        let mut request = url.into_client_request()?;
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "sip".parse().unwrap());

        let (ws_stream, _) = connect_async(request).await?;
        let (ws_sink, ws_stream) = ws_stream.split();

        let connection = WebSocketConnection {
            inner: Arc::new(WebSocketInner {
                remote_addr: remote.clone(),
                ws_sink: Mutex::new(ws_sink),
                ws_read: Mutex::new(Some(ws_stream)),
            }),
            cancel_token,
        };

        debug!(
            local = %connection.get_addr(),
            remote = %remote,
            "Created WebSocket client connection"
        );

        Ok(connection)
    }
    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

#[async_trait::async_trait]
impl StreamConnection for WebSocketConnection {
    fn get_addr(&self) -> &SipAddr {
        &self.inner.remote_addr
    }

    async fn send_message(&self, msg: SipMessage) -> Result<()> {
        let data = msg.to_string();
        let mut sink = self.inner.ws_sink.lock().await;
        debug!(dest = %self.inner.remote_addr, raw_message = %data, "websocket send");
        sink.send(Message::Text(data.into())).await?;
        Ok(())
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        let mut sink = self.inner.ws_sink.lock().await;
        sink.send(Message::Binary(data.to_vec().into())).await?;
        Ok(())
    }

    async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let sip_connection = SipConnection::WebSocket(self.clone());

        let remote_addr = self.inner.remote_addr.clone();
        let mut ws_read = match self.inner.ws_read.lock().await.take() {
            Some(ws_read) => ws_read,
            None => {
                warn!(src = %remote_addr, "WebSocket connection already closed");
                return Ok(());
            }
        };
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    debug!(src = %remote_addr, raw_message = %text, "websocket message received");
                    match SipMessage::try_from(text.as_str()) {
                        Ok(sip_msg) => {
                            let remote_socket_addr = remote_addr.get_socketaddr()?;
                            let sip_msg = SipConnection::update_msg_received(
                                sip_msg,
                                remote_socket_addr,
                                remote_addr.r#type.unwrap_or_default(),
                            )?;

                            if let Err(e) = sender.send(TransportEvent::Incoming(
                                sip_msg,
                                sip_connection.clone(),
                                remote_addr.clone(),
                            )) {
                                warn!(error = ?e, src = %remote_addr, "Error sending incoming message");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, src = %remote_addr, raw_message = %text, "Error parsing SIP message");
                        }
                    }
                }
                Ok(Message::Binary(bin)) => {
                    if bin == *KEEPALIVE_REQUEST {
                        if let Err(e) = self.send_raw(KEEPALIVE_RESPONSE).await {
                            warn!(error = ?e, src = %remote_addr, "Error sending keepalive response");
                        }
                        continue;
                    }
                    debug!(src = %remote_addr, "websocket binary message received");
                    match SipMessage::try_from(bin) {
                        Ok(sip_msg) => {
                            if let Err(e) = sender.send(TransportEvent::Incoming(
                                sip_msg,
                                sip_connection.clone(),
                                remote_addr.clone(),
                            )) {
                                warn!(error = ?e, src = %remote_addr, "Error sending incoming message");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, src = %remote_addr, "Error parsing SIP message from binary");
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let mut sink = self.inner.ws_sink.lock().await;
                    if let Err(e) = sink.send(Message::Pong(data)).await {
                        warn!(error = %e, src = %remote_addr, "Error sending pong");
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    debug!(src = %remote_addr, "WebSocket connection closed by peer");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, src = %remote_addr, "WebSocket error");
                    break;
                }
                _ => {}
            }
        }

        debug!(src = %remote_addr, "WebSocket serve_loop exiting");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut sink = self.inner.ws_sink.lock().await;
        sink.send(Message::Close(None)).await?;
        Ok(())
    }
}

impl fmt::Display for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = match self.inner.remote_addr.r#type {
            Some(rsip::transport::Transport::Wss) => "WSS",
            _ => "WS",
        };
        write!(f, "{} {}", transport, self.inner.remote_addr)
    }
}

impl fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
