use axum::extract::ws::Message;
use axum::extract::ws::WebSocket;
use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::response::Html;
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use get_if_addrs::get_if_addrs;
use rsip::headers::UntypedHeader;
use rsip::prelude::{HeadersExt, ToTypedHeader};
use rsip::SipMessage;
use rsipstack::dialog::DialogId;
use rsipstack::rsip_ext::{extract_uri_from_contact, RsipHeadersExt};
use rsipstack::transaction::endpoint::EndpointInnerRef;
use rsipstack::transaction::key::{TransactionKey, TransactionRole};
use rsipstack::transaction::transaction::Transaction;
use rsipstack::transaction::TransactionReceiver;
use rsipstack::transport::channel::ChannelConnection;
use rsipstack::transport::tcp_listener::TcpListenerConnection;
use rsipstack::transport::udp::UdpConnection;
#[cfg(feature = "websocket")]
use rsipstack::transport::websocket::WebSocketListenerConnection;
use rsipstack::transport::SipAddr;
use rsipstack::transport::{SipConnection, TransportEvent};
use rsipstack::{header_pop, Error, Result};
use rsipstack::{transport::TransportLayer, EndpointBuilder};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{env, vec};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

/// A SIP proxy server that supports UDP, TCP and WebSocket clients
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// SIP address
    #[arg(long)]
    addr: Option<String>,
    /// SIP port
    #[arg(long, default_value = "25060")]
    port: u16,

    /// External IP address
    #[arg(long)]
    external_ip: Option<String>,

    /// TCP port
    #[arg(long)]
    tcp_port: Option<u16>,

    /// WebSocket port
    #[arg(long)]
    ws_port: Option<u16>,

    /// HTTP server port for web interface
    #[arg(long)]
    http_port: Option<u16>,
}

#[derive(Clone)]
struct User {
    username: String,
    destination: SipAddr,
}
struct AppStateInner {
    users: Mutex<HashMap<String, User>>,
    sessions: Mutex<HashSet<DialogId>>,
    endpoint_ref: EndpointInnerRef,
}
#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .try_init()
        .ok();
    if let Err(e) = dotenv::dotenv() {
        info!("Failed to load .env file: {}", e);
    }
    let args = Args::parse();

    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.clone());

    let external_ip = args
        .external_ip
        .unwrap_or(env::var("EXTERNAL_IP").unwrap_or_default());

    let external = if external_ip.is_empty() {
        None
    } else {
        Some(format!("{}:{}", external_ip, args.port).parse()?)
    };
    let addr = match args.addr {
        Some(addr) => addr.parse::<std::net::IpAddr>()?,
        None => get_if_addrs()?
            .iter()
            .find(|i| !i.is_loopback())
            .map(|i| match i.addr {
                get_if_addrs::IfAddr::V4(ref addr) => Ok(std::net::IpAddr::V4(addr.ip)),
                _ => Err(Error::Error("No IPv4 address found".to_string())),
            })
            .unwrap_or(Err(Error::Error("No interface found".to_string())))?,
    };

    let connection = UdpConnection::create_connection(
        format!("{}:{}", addr, args.port).parse()?,
        external.clone(),
        None,
    )
    .await?;
    transport_layer.add_transport(connection.into());
    info!("Added UDP transport on {}:{}", addr, args.port);

    if let Some(tcp_port) = args.tcp_port {
        let local_addr = SipAddr {
            addr: format!("{}:{}", addr, tcp_port)
                .parse::<std::net::SocketAddr>()?
                .into(),
            r#type: Some(rsip::transport::Transport::Tcp),
        };
        let external_addr = if !external_ip.is_empty() {
            Some(format!("{}:{}", external_ip, tcp_port).parse::<std::net::SocketAddr>()?)
        } else {
            None
        };
        let tcp_listener = TcpListenerConnection::new(local_addr.clone(), external_addr).await?;
        transport_layer.add_transport(tcp_listener.into());
        info!("Added TCP transport on {}", local_addr.addr);
    }

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(token.clone())
        .with_transport_layer(transport_layer)
        .build();

    let app_state = AppState {
        inner: Arc::new(AppStateInner {
            users: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashSet::new()),
            endpoint_ref: endpoint.inner.clone(),
        }),
    };
    // Start HTTP server if http_port is specified
    let http_server_handle = if let Some(http_port) = args.http_port {
        let app = create_http_app(app_state.clone());
        let http_addr = format!("0.0.0.0:{}", http_port).parse::<SocketAddr>()?;
        info!("Starting HTTP server on {}", http_addr);
        let listener = tokio::net::TcpListener::bind(http_addr).await?;
        Some(tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        }))
    } else {
        None
    };

    if let Some(ws_port) = args.ws_port {
        #[cfg(feature = "websocket")]
        {
            let local_addr = SipAddr {
                addr: format!("{}:{}", addr, ws_port)
                    .parse::<std::net::SocketAddr>()?
                    .into(),
                r#type: Some(rsip::transport::Transport::Ws),
            };
            let external_addr = if !external_ip.is_empty() {
                Some(format!("{}:{}", external_ip, ws_port).parse::<std::net::SocketAddr>()?)
            } else {
                None
            };
            let ws_listener =
                WebSocketListenerConnection::new(local_addr.clone(), external_addr, false).await?;
            app_state
                .inner
                .endpoint_ref
                .transport_layer
                .add_transport(ws_listener.into());

            info!("Added WebSocket transport on {}", local_addr.addr);
        }
        #[cfg(not(feature = "websocket"))]
        {
            warn!("WebSocket feature not enabled");
        }
    }

    let incoming = endpoint.incoming_transactions()?;
    select! {
        _ = endpoint.serve() => {
            info!("proxy endpoint finished");
        }
        r = process_incoming_request(app_state, incoming) => {
            info!("serve loop finished {:?}", r);
        }
        _ = async {
            if let Some(handle) = http_server_handle {
                handle.await.unwrap();
            } else {
                std::future::pending().await
            }
        } => {
            info!("HTTP server finished");
        }
    }
    Ok(())
}

async fn process_incoming_request(
    state: AppState,
    mut incoming: TransactionReceiver,
) -> Result<()> {
    while let Some(mut tx) = incoming.recv().await {
        info!("Received transaction: {:?}", tx.key);
        let state_ref = state.clone();
        match tx.original.method {
            rsip::Method::Invite => {
                tokio::spawn(async move {
                    handle_invite(state_ref, tx).await?;
                    Ok::<_, Error>(())
                });
            }
            rsip::Method::Bye => {
                tokio::spawn(async move {
                    handle_bye(state_ref, tx).await?;
                    Ok::<_, Error>(())
                });
            }
            rsip::Method::Register => {
                handle_register(state_ref, tx).await?;
            }
            rsip::Method::Ack => {
                info!("received out of transaction ack: {:?}", tx.original.method);
                let dialog_id = DialogId::try_from(&tx.original)?;
                if !state_ref.inner.sessions.lock().await.contains(&dialog_id) {
                    tx.reply(rsip::StatusCode::NotAcceptable).await?;
                    continue;
                }
                // forward ACK
                let callee = tx
                    .original
                    .to_header()?
                    .uri()?
                    .auth
                    .map(|a| a.user)
                    .unwrap_or_default();
                let target = state_ref.inner.users.lock().await.get(&callee).cloned();
                let target = match target {
                    Some(u) => u,
                    None => {
                        info!("ack user not found: {}", callee);
                        tx.reply(rsip::StatusCode::NotAcceptable).await?;
                        continue;
                    }
                };
                // send to target
                let mut ack_req = tx.original.clone();
                let via = tx.endpoint_inner.get_via(None, None)?;
                ack_req.headers.push_front(via.into());
                let key = TransactionKey::from_request(&ack_req, TransactionRole::Client)
                    .expect("client_transaction");
                let mut ack_tx =
                    Transaction::new_client(key, ack_req, tx.endpoint_inner.clone(), None);
                ack_tx.destination = Some(target.destination);
                ack_tx.send().await?;
            }
            rsip::Method::Options => {
                info!(
                    "ignoring out of dialog OPTIONS request: {:?}",
                    tx.original.method
                );
                // do nothing for OPTIONS, may be a attack from scanner
                // tx.reply(rsip::StatusCode::NotAcceptable).await?;
            }
            _ => {
                tx.reply(rsip::StatusCode::NotAcceptable).await?;
            }
        }
    }
    Ok::<_, Error>(())
}

impl TryFrom<&rsip::Request> for User {
    type Error = Error;
    fn try_from(req: &rsip::Request) -> Result<Self> {
        let contact = extract_uri_from_contact(req.contact_header()?.value())?;
        let via = req.via_header()?.typed()?;

        let username = req
            .from_header()?
            .uri()?
            .user()
            .unwrap_or_default()
            .to_string();

        let mut destination = SipAddr {
            r#type: Some(via.transport),
            addr: contact.host_with_port,
        };

        via.params.iter().for_each(|param| match param {
            rsip::Param::Transport(t) => {
                destination.r#type = Some(t.clone());
            }
            rsip::Param::Received(r) => match r.value().try_into() {
                Ok(addr) => destination.addr.host = addr,
                Err(_) => {}
            },
            rsip::Param::Other(o, Some(v)) => {
                if o.value().eq_ignore_ascii_case("rport") {
                    match v.value().try_into() {
                        Ok(port) => destination.addr.port = Some(port),
                        Err(_) => {}
                    }
                }
            }
            _ => {}
        });

        Ok(User {
            username,
            destination,
        })
    }
}

async fn handle_register(state: AppState, mut tx: Transaction) -> Result<()> {
    let user = match User::try_from(&tx.original) {
        Ok(u) => u,
        Err(e) => {
            info!("failed to parse contact: {:?}", e);
            return tx.reply(rsip::StatusCode::BadRequest).await;
        }
    };

    let orig_contact_uri = extract_uri_from_contact(tx.original.contact_header()?.value())?;
    let contact = rsip::typed::Contact {
        display_name: None,
        uri: orig_contact_uri,
        params: vec![rsip::Param::Expires("60".into())],
    };
    match tx.original.expires_header() {
        Some(expires) => match expires.value().parse::<u32>() {
            Ok(v) => {
                if v == 0 {
                    // remove user
                    info!("unregistered user: {} -> {}", user.username, contact);
                    state.inner.users.lock().await.remove(&user.username);
                    return tx.reply(rsip::StatusCode::OK).await;
                }
            }
            Err(_) => {}
        },
        None => {}
    }

    info!("Registered user: {} -> {}", user.username, user.destination);
    state
        .inner
        .users
        .lock()
        .await
        .insert(user.username.clone(), user);

    let headers = vec![contact.into(), rsip::Header::Expires(60.into())];
    tx.reply_with(rsip::StatusCode::OK, headers, None).await
}

async fn handle_invite(state: AppState, mut tx: Transaction) -> Result<()> {
    let caller = tx.original.from_header()?.uri()?.to_string();
    let callee = tx
        .original
        .to_header()?
        .uri()?
        .auth
        .map(|a| a.user)
        .unwrap_or_default();
    let target = state.inner.users.lock().await.get(&callee).cloned();

    let record_route = tx.endpoint_inner.get_record_route()?;

    let target = match target {
        Some(u) => u,
        None => {
            info!("user not found: {}", callee);
            tx.reply_with(rsip::StatusCode::NotFound, vec![record_route.into()], None)
                .await
                .ok();
            // wait for ACK
            while let Some(msg) = tx.receive().await {
                match msg {
                    rsip::message::SipMessage::Request(req) => match req.method {
                        rsip::Method::Ack => {
                            info!("received no-2xx ACK");
                            break;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            return Ok(());
        }
    };

    let mut inv_req = tx.original.clone();
    let via = tx.endpoint_inner.get_via(None, None)?;
    inv_req.headers.push_front(via.into());
    inv_req.headers.push_front(record_route.clone().into());
    let key = TransactionKey::from_request(&inv_req, TransactionRole::Client)
        .expect("client_transaction");

    info!("Forwarding INVITE to: {} -> {}", caller, target.destination);

    let mut inv_tx = Transaction::new_client(key, inv_req, tx.endpoint_inner.clone(), None);
    inv_tx.destination = Some(target.destination);

    // add Via
    inv_tx.send().await?;

    loop {
        if inv_tx.is_terminated() {
            break;
        }
        select! {
            msg = inv_tx.receive() => {
                info!("UAC Received message: {}", msg.as_ref().map(|m| m.to_string()).unwrap_or_default());
                if let Some(msg) = msg {
                    match msg {
                        rsip::message::SipMessage::Response(mut resp) => {
                            // pop first Via
                            header_pop!(resp.headers, rsip::Header::Via);
                            resp.headers.push_front(record_route.clone().into());
                            if resp.status_code.kind() == rsip::StatusCodeKind::Successful {
                                let dialog_id = DialogId::try_from(&resp)?;
                                info!("add session: {}", dialog_id);
                                state.inner.sessions.lock().await.insert(dialog_id);
                            }
                            tx.respond(resp).await?;
                        }
                        _ => {}
                    }
                }
            }
            msg = tx.receive() => {
                info!("UAS Received message: {}", msg.as_ref().map(|m| m.to_string()).unwrap_or_default());
                if let Some(msg) = msg {
                    match msg {
                        rsip::message::SipMessage::Request(req) => match req.method {
                            rsip::Method::Cancel => {
                                let mut cancel_req = req.clone();
                                if let Ok(invite_via) = inv_tx.original.via_header() {
                                    cancel_req.headers.push_front(invite_via.clone().into());
                                }
                                inv_tx.send_cancel(cancel_req).await?;
                            }
                            _ => {}
                        },
                        rsip::message::SipMessage::Response(_) => {}
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_bye(state: AppState, mut tx: Transaction) -> Result<()> {
    let caller = tx.original.from_header()?.uri()?.to_string();
    let callee = tx
        .original
        .to_header()?
        .uri()?
        .auth
        .map(|a| a.user)
        .unwrap_or_default();
    let target = state.inner.users.lock().await.get(&callee).cloned();
    let peer = match target {
        Some(u) => u,
        None => {
            info!("bye user not found: {}", callee);
            return tx.reply(rsip::StatusCode::NotFound).await;
        }
    };

    let mut inv_req = tx.original.clone();
    let via = tx.endpoint_inner.get_via(None, None)?;
    inv_req.headers.push_front(via.into());

    let key = TransactionKey::from_request(&inv_req, TransactionRole::Client)
        .expect("client_transaction");

    info!("Forwarding BYE to: {} -> {}", caller, peer.destination);

    let mut bye_tx = Transaction::new_client(key, inv_req, tx.endpoint_inner.clone(), None);
    bye_tx.destination = Some(peer.destination);

    bye_tx.send().await?;

    let dialog_id = DialogId::try_from(&bye_tx.original)?;
    if state.inner.sessions.lock().await.remove(&dialog_id) {
        info!("removed session: {}", dialog_id);
    }

    while let Some(msg) = bye_tx.receive().await {
        match msg {
            rsip::message::SipMessage::Response(mut resp) => {
                // pop first Via
                header_pop!(resp.headers, rsip::Header::Via);
                info!("UAC/BYE Forwarding response: {}", resp.to_string());
                tx.respond(resp).await?;
            }
            _ => {
                warn!("UAC/BYE Received request: {}", msg.to_string());
            }
        }
    }

    Ok(())
}

pub struct ClientAddr(SocketAddr);
impl ClientAddr {
    pub fn new(addr: SocketAddr) -> Self {
        ClientAddr(addr)
    }
}

impl<S> FromRequestParts<S> for ClientAddr
where
    S: Send + Sync,
{
    type Rejection = http::StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let mut remote_addr = match parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            Some(ConnectInfo(addr)) => addr.clone(),
            None => return Err(http::StatusCode::BAD_REQUEST),
        };

        for header in [
            "x-client-ip",
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
        ] {
            if let Some(value) = parts.headers.get(header) {
                if let Ok(ip) = value.to_str() {
                    // Handle comma-separated IPs (e.g. X-Forwarded-For can have multiple)
                    let first_ip = ip.split(',').next().unwrap_or(ip).trim();
                    remote_addr.set_ip(IpAddr::V4(first_ip.parse().unwrap()));
                    break;
                }
            }
        }
        Ok(ClientAddr(remote_addr))
    }
}

impl fmt::Display for ClientAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

async fn serve_index() -> impl IntoResponse {
    Html(include_str!("../assets/index.html"))
}

fn create_http_app(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/ws", get(websocket_handler))
        .with_state(state)
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
}

async fn websocket_handler(
    client_addr: ClientAddr,
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.protocols(["sip"])
        .on_upgrade(|socket| handle_websocket(client_addr, socket, state))
}

async fn handle_websocket(client_addr: ClientAddr, socket: WebSocket, _state: AppState) {
    let (ws_sink, mut ws_read) = socket.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));

    // Create a channel pair for bidirectional communication
    let (from_ws_tx, from_ws_rx) = mpsc::unbounded_channel();
    let (to_ws_tx, mut to_ws_rx) = mpsc::unbounded_channel();
    let transport_type = rsip::transport::Transport::Ws;
    // Create a unique SIP address for this WebSocket connection
    let local_addr = SipAddr {
        r#type: Some(transport_type),
        addr: client_addr.0.into(),
    };
    let ws_token = CancellationToken::new();
    // Create the ChannelConnection
    let connection = match ChannelConnection::create_connection(
        from_ws_rx,
        to_ws_tx,
        local_addr.clone(),
        Some(ws_token),
    )
    .await
    {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Failed to create channel connection: {:?}", e);
            return;
        }
    };

    let sip_connection = SipConnection::Channel(connection.clone());
    info!("Created WebSocket channel connection: {}", local_addr);
    _state
        .inner
        .endpoint_ref
        .transport_layer
        .add_connection(sip_connection.clone());

    // Use select! instead of spawning multiple tasks
    loop {
        select! {
            // Handle WebSocket -> Transport messages
            message = ws_read.next() => {
                match message {
                    Some(Ok(Message::Text(text))) => match SipMessage::try_from(text.as_str()) {
                        Ok(sip_msg) => {
                            info!(
                                "WebSocket received SIP message: {}",
                                sip_msg.to_string().lines().next().unwrap_or("")
                            );
                            let msg = match SipConnection::update_msg_received(
                                sip_msg,
                                client_addr.0.into(),
                                transport_type,
                            ) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    warn!("Error updating SIP via: {:?}", e);
                                    continue;
                                }
                            };
                            if let Err(e) = from_ws_tx.send(TransportEvent::Incoming(
                                msg,
                                sip_connection.clone(),
                                local_addr.clone(),
                            )) {
                                warn!("Error forwarding message to transport: {:?}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Error parsing SIP message from WebSocket: {}", e);
                        }
                    },
                    Some(Ok(Message::Binary(bin))) => match SipMessage::try_from(bin) {
                        Ok(sip_msg) => {
                            info!(
                                "WebSocket received binary SIP message: {}",
                                sip_msg.to_string().lines().next().unwrap_or("")
                            );
                            if let Err(e) = from_ws_tx.send(TransportEvent::Incoming(
                                sip_msg,
                                sip_connection.clone(),
                                local_addr.clone(),
                            )) {
                                warn!("Error forwarding binary message to transport: {:?}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Error parsing binary SIP message from WebSocket: {}", e);
                        }
                    },
                    Some(Ok(Message::Close(_))) => {
                        info!("WebSocket connection closed by client");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let mut sink = ws_sink.lock().await;
                        if let Err(e) = sink.send(Message::Pong(data)).await {
                            warn!("Error sending pong response: {}", e);
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Just acknowledge the pong
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        info!("WebSocket stream ended");
                        break;
                    }
                }
            }

            // Handle Transport -> WebSocket messages
            event = to_ws_rx.recv() => {
                match event {
                    Some(TransportEvent::Incoming(sip_msg, _, _)) => {
                        let message_text = sip_msg.to_string();
                        info!(
                            "Forwarding message to WebSocket: {}",
                            message_text.lines().next().unwrap_or("")
                        );
                        let mut sink = ws_sink.lock().await;
                        if let Err(e) = sink.send(Message::Text(message_text.into())).await {
                            warn!("Error sending message to WebSocket: {}", e);
                            break;
                        }
                    }
                    Some(TransportEvent::New(_)) => {
                        // Handle new connection events if needed
                    }
                    Some(TransportEvent::Closed(_)) => {
                        info!("Transport connection closed");
                        break;
                    }
                    None => {
                        info!("Transport channel closed");
                        break;
                    }
                }
            }
        }
    }
    info!("WebSocket connection handler exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsipstack::transport::udp::UdpConnection;
    use rsipstack::{transport::TransportLayer, EndpointBuilder};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_proxy_basic_functionality() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create test proxy
        let token = CancellationToken::new();
        let transport_layer = TransportLayer::new(token.clone());

        let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        transport_layer.add_transport(udp_conn.into());

        let _endpoint = EndpointBuilder::new()
            .with_cancel_token(token.clone())
            .with_transport_layer(transport_layer)
            .build();

        // Just verify the endpoint was created successfully
        assert!(!token.is_cancelled());

        token.cancel();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_proxy_state_management() {
        let endpoint = EndpointBuilder::new()
            .with_user_agent("MyApp/1.0")
            .with_timer_interval(Duration::from_millis(10))
            .with_allows(vec![rsip::Method::Invite, rsip::Method::Bye])
            .build();

        let state = AppState {
            inner: Arc::new(AppStateInner {
                users: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashSet::new()),
                endpoint_ref: endpoint.inner.clone(),
            }),
        };

        // Test user registration
        let user = User {
            username: "testuser".to_string(),
            destination: SipAddr {
                r#type: Some(rsip::transport::Transport::Udp),
                addr: rsip::HostWithPort {
                    host: rsip::Host::Domain("192.168.1.100".to_string().into()),
                    port: Some(5060.into()),
                },
            },
        };

        state
            .inner
            .users
            .lock()
            .await
            .insert(user.username.clone(), user.clone());

        // Verify user is stored
        let stored_user = state.inner.users.lock().await.get("testuser").cloned();
        assert!(stored_user.is_some());
        assert_eq!(stored_user.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_dialog_session_management() {
        let endpoint = EndpointBuilder::new()
            .with_user_agent("MyApp/1.0")
            .with_timer_interval(Duration::from_millis(10))
            .with_allows(vec![rsip::Method::Invite, rsip::Method::Bye])
            .build();
        let state = AppState {
            inner: Arc::new(AppStateInner {
                users: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashSet::new()),
                endpoint_ref: endpoint.inner.clone(),
            }),
        };

        // Create a test dialog ID
        let dialog_id = DialogId {
            call_id: "test-call-id".to_string(),
            from_tag: "local-tag".to_string(),
            to_tag: "remote-tag".to_string(),
        };

        state.inner.sessions.lock().await.insert(dialog_id.clone());

        assert!(state.inner.sessions.lock().await.contains(&dialog_id));

        // Remove session
        assert!(state.inner.sessions.lock().await.remove(&dialog_id));
        assert!(!state.inner.sessions.lock().await.contains(&dialog_id));
    }

    #[tokio::test]
    async fn test_args_parsing() {
        use clap::Parser;

        // Test parsing all arguments
        let args = Args::try_parse_from(&[
            "proxy",
            "--port",
            "5060",
            "--tcp-port",
            "5060",
            "--ws-port",
            "8080",
            "--http-port",
            "8000",
        ])
        .unwrap();

        assert_eq!(args.port, 5060);
        assert_eq!(args.tcp_port, Some(5060));
        assert_eq!(args.ws_port, Some(8080));
        assert_eq!(args.http_port, Some(8000));
    }

    #[tokio::test]
    async fn test_transport_layer_integration() {
        let _ = tracing_subscriber::fmt::try_init();

        let token = CancellationToken::new();
        let transport_layer = TransportLayer::new(token.clone());

        // Test that we can add UDP transport
        let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        transport_layer.add_transport(udp_conn.into());

        // Verify we can get addresses
        let addrs = transport_layer.get_addrs();
        assert!(!addrs.is_empty());

        token.cancel();
    }

    #[tokio::test]
    async fn test_channel_connection_creation() {
        use rsipstack::transport::channel::ChannelConnection;
        use rsipstack::transport::SipAddr;
        use rsipstack::transport::{SipConnection, TransportEvent};
        use tokio::sync::mpsc;

        let _ = tracing_subscriber::fmt::try_init();

        // Create channel pair like in handle_websocket
        let (to_transport_tx, to_transport_rx) = mpsc::unbounded_channel();
        let (from_transport_tx, mut from_transport_rx) = mpsc::unbounded_channel();

        // Create SIP address
        let local_addr = SipAddr {
            r#type: Some(rsip::transport::Transport::Ws),
            addr: rsip::HostWithPort {
                host: rsip::Host::Domain("test-websocket".to_string().into()),
                port: Some(8080.into()),
            },
        };

        // Create ChannelConnection
        let connection = ChannelConnection::create_connection(
            to_transport_rx,
            from_transport_tx.clone(),
            local_addr.clone(),
            None,
        )
        .await
        .expect("Should create channel connection");

        let sip_connection = SipConnection::Channel(connection.clone());

        // Verify connection properties
        assert_eq!(connection.get_addr(), &local_addr);
        assert!(sip_connection.is_reliable());

        // Test sending a simple message through the channel
        let test_register_req = rsip::Request {
            method: rsip::Method::Register,
            uri: rsip::uri::Uri {
                scheme: Some(rsip::Scheme::Sip),
                auth: Some(rsip::Auth {
                    user: "test".to_string(),
                    password: None,
                }),
                host_with_port: rsip::HostWithPort {
                    host: rsip::Host::Domain("example.com".to_string().into()),
                    port: None,
                },
                ..Default::default()
            },
            version: rsip::Version::V2,
            headers: rsip::Headers::default(),
            body: Vec::new(),
        };

        let test_message = rsip::SipMessage::Request(test_register_req);

        // Send test message to transport
        to_transport_tx
            .send(TransportEvent::Incoming(
                test_message,
                sip_connection.clone(),
                local_addr.clone(),
            ))
            .expect("Should send message");

        // Start serve loop in background
        let serve_handle = tokio::spawn({
            let connection = connection.clone();
            let from_transport_tx = from_transport_tx.clone();
            async move { connection.serve_loop(from_transport_tx).await }
        });

        // Verify we can receive the message
        if let Some(event) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            from_transport_rx.recv(),
        )
        .await
        .ok()
        .flatten()
        {
            match event {
                TransportEvent::Incoming(msg, _conn, addr) => {
                    assert_eq!(addr, local_addr);
                    if let rsip::SipMessage::Request(req) = msg {
                        assert_eq!(req.method, rsip::Method::Register);
                    } else {
                        panic!("Expected request message");
                    }
                }
                _ => panic!("Expected incoming message event"),
            }
        } else {
            panic!("Should receive message within timeout");
        }

        // Clean up
        drop(to_transport_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), serve_handle).await;
    }
}
