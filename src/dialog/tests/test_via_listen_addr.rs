//! In-dialog requests must advertise one of OUR listener addresses in the
//! Via (RFC 3261 §18.1.1), never a remote peer address leaked from the
//! transport connection cache. A SIP-over-WebSocket client rides a channel
//! connection whose `SipAddr` is the client's own ip:port (rustpbx registers
//! axum-upgraded WebSocket clients exactly that way); before the listen-only
//! fix, `via_addr_for_send_transport` matched that entry and pointed the Via
//! of every BYE / re-INVITE / UPDATE back at the client itself.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

use crate::dialog::{
    dialog::DialogInner,
    dialog_layer::DialogLayer,
    invitation::InviteOption,
    server_dialog::ServerInviteDialog,
    tests::test_dialog_states::{create_invite_request, create_test_endpoint},
    DialogId,
};
use crate::sip::prelude::{HeadersExt, ToTypedHeader};
use crate::sip::{Method, SipMessage, Transport};
use crate::transaction::key::TransactionRole;
use crate::transport::{
    channel::ChannelConnection, connection::TransportEvent, udp::UdpConnection, SipAddr,
    SipConnection, TransportLayer, WebSocketListenerConnection,
};

const CLIENT_HOST: &str = "10.0.0.9";
const CLIENT_PORT: u16 = 5555;

fn client_addr(transport: Transport) -> SipAddr {
    SipAddr {
        r#type: Some(transport),
        addr: crate::sip::HostWithPort {
            host: crate::sip::Host::IpAddr(CLIENT_HOST.parse().unwrap()),
            port: Some(CLIENT_PORT.into()),
        },
    }
}

async fn udp_only_endpoint(
    token: &CancellationToken,
) -> crate::Result<crate::transport::TransportLayer> {
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    transport_layer.add_transport(udp.into());
    Ok(transport_layer)
}

/// Attach a fake WS-client channel connection to the endpoint's transport
/// layer, exactly the way rustpbx registers axum-upgraded WebSocket clients:
/// the connection address is the *client's* address. Returns the connection,
/// its cancel token and the outgoing frame receiver (drained unless the
/// caller wants to inspect the frames).
async fn attach_client_channel(
    endpoint: &crate::transaction::endpoint::Endpoint,
    addr: SipAddr,
) -> (
    SipConnection,
    CancellationToken,
    tokio::sync::mpsc::UnboundedReceiver<TransportEvent>,
) {
    let (in_tx, in_rx) = unbounded_channel::<TransportEvent>();
    let (out_tx, out_rx) = unbounded_channel::<TransportEvent>();
    let token = CancellationToken::new();
    let conn = ChannelConnection::create_connection(in_rx, out_tx, addr, Some(token.child_token()))
        .await
        .expect("channel connection");
    let sip_conn = SipConnection::Channel(conn);
    endpoint.inner.transport_layer.add_connection(sip_conn.clone());
    // Keep the fake client's inbound sender alive: dropping it makes the
    // channel's read loop tear the connection down (and remove itself from
    // the transport table). Tests that want teardown cancel the returned
    // token instead.
    std::mem::forget(in_tx);
    (sip_conn, token, out_rx)
}

fn drain(mut out_rx: tokio::sync::mpsc::UnboundedReceiver<TransportEvent>) {
    tokio::spawn(async move { while out_rx.recv().await.is_some() {} });
}

async fn make_server_dialog(
    endpoint: &crate::transaction::endpoint::Endpoint,
    connection: Option<SipConnection>,
) -> crate::Result<ServerInviteDialog> {
    let dialog_id = DialogId {
        call_id: "via-listen-test".to_string(),
        local_tag: "srv-tag".to_string(),
        remote_tag: "cli-tag".to_string(),
    };
    let (tu_sender, _tu_receiver) = unbounded_channel();
    let (state_sender, _state_receiver) = unbounded_channel();
    let invite_req = create_invite_request(&dialog_id.remote_tag, "", &dialog_id.call_id);
    let inner = Arc::new(DialogInner::new(
        TransactionRole::Server,
        dialog_id,
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        None,
        tu_sender,
    )?);
    if let Some(conn) = connection {
        *inner.server_connection.lock() = Some(conn);
    }
    Ok(ServerInviteDialog { inner })
}

fn top_via(request: &crate::sip::Request) -> crate::sip::typed::Via {
    request
        .top_via_header()
        .expect("request has no Via")
        .typed()
        .expect("typed Via")
}

fn assert_listener_via(via: &crate::sip::typed::Via, listener: &SipAddr) {
    assert_eq!(
        via.uri.host_with_port.host.to_string(),
        listener.addr.host.to_string(),
        "Via host must be the listener address, not the client's"
    );
    assert_eq!(via.uri.host_with_port.port, listener.addr.port);
    assert_ne!(
        via.uri.host_with_port.host.to_string(),
        CLIENT_HOST,
        "Via must never carry the WS client's own address"
    );
}

/// Core guarantee: an in-dialog BYE built while a WS client channel is the
/// dialog's affinity connection still advertises the UDP listener's address
/// (with the request's transport token) — never the client's address.
#[tokio::test]
async fn test_bye_via_ignores_ws_client_connection_addr() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let listener = endpoint
        .inner
        .transport_layer
        .get_listen_addrs()
        .first()
        .cloned()
        .expect("udp listener");

    let (conn, _token, out_rx) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    drain(out_rx);
    let dialog = make_server_dialog(&endpoint, Some(conn)).await?;

    let bye = dialog
        .inner
        .make_request(Method::Bye, None, None, None, None, None)?;
    let via = top_via(&bye);
    assert_eq!(via.transport, Transport::Ws);
    assert_listener_via(&via, &listener);
    Ok(())
}

/// A second client behind the same NAT (identical connection address) must
/// not change the outcome, and each transaction keeps a unique branch.
#[tokio::test]
async fn test_bye_via_stable_with_duplicate_connection_addrs() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let listener = endpoint
        .inner
        .transport_layer
        .get_listen_addrs()
        .first()
        .cloned()
        .expect("udp listener");

    let (conn1, _token1, out_rx1) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    drain(out_rx1);
    let (conn2, _token2, out_rx2) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    drain(out_rx2);
    let _ = conn2; // same remote addr as conn1: the cache collision must not matter
    let dialog = make_server_dialog(&endpoint, Some(conn1)).await?;

    let bye1 = dialog
        .inner
        .make_request(Method::Bye, None, None, None, None, None)?;
    let via1 = top_via(&bye1);
    assert_listener_via(&via1, &listener);

    let bye2 = dialog
        .inner
        .make_request(Method::Bye, None, None, None, None, None)?;
    let via2 = top_via(&bye2);
    assert_eq!(
        via1.uri.host_with_port.host,
        via2.uri.host_with_port.host,
        "listener-derived Via is stable across requests"
    );
    assert_ne!(
        via1.branch().expect("branch"),
        via2.branch().expect("branch"),
        "each transaction keeps a unique branch"
    );
    Ok(())
}

/// With a real WS listener present (external address advertised), its
/// external address — not any connection address — is the Via sent-by.
#[tokio::test]
async fn test_bye_via_uses_ws_listener_external_addr() -> crate::Result<()> {
    let token = CancellationToken::new();
    let transport_layer = udp_only_endpoint(&token).await?;
    let ws_listener = WebSocketListenerConnection::new(
        "127.0.0.1:0".parse().unwrap(),
        Some("203.0.113.7:15073".parse().unwrap()),
        false,
    )
    .await?;
    transport_layer.add_transport(ws_listener.into());

    let endpoint = crate::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();

    let (conn, _token, out_rx) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    drain(out_rx);
    let dialog = make_server_dialog(&endpoint, Some(conn)).await?;

    let bye = dialog
        .inner
        .make_request(Method::Bye, None, None, None, None, None)?;
    let via = top_via(&bye);
    assert_eq!(via.transport, Transport::Ws);
    assert_eq!(via.uri.host_with_port.host.to_string(), "203.0.113.7");
    assert_eq!(via.uri.host_with_port.port, Some(15073.into()));
    Ok(())
}

/// A cancelled (dead) WS flow must not change the outcome either: the Via is
/// still listener-derived, and the affinity resolution reports no connection
/// so the request falls to the dial-back ladder.
#[tokio::test]
async fn test_cancelled_affinity_via_stays_listener() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (conn, conn_token, out_rx) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    drain(out_rx);
    let dialog = make_server_dialog(&endpoint, Some(conn)).await?;

    conn_token.cancel();
    assert!(
        dialog.inner.test_resolve_affinity_connection().is_none(),
        "cancelled flow must not be reused as affinity"
    );

    let bye = dialog
        .inner
        .make_request(Method::Bye, None, None, None, None, None)?;
    let via = top_via(&bye);
    assert_ne!(
        via.uri.host_with_port.host.to_string(),
        CLIENT_HOST,
        "Via must never carry the WS client's own address"
    );
    Ok(())
}

/// The transport connection cache must keep working for routing
/// (`get_addrs`) while the listener snapshot (`get_listen_addrs`) stays
/// constant no matter how many WS clients connect — the life-cycle shape of
/// the historical connection-table leak/OOM incidents.
#[tokio::test]
async fn test_listen_addrs_ignores_connection_churn() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let before = endpoint.inner.transport_layer.get_listen_addrs();
    let connections_before = endpoint.inner.transport_layer.get_addrs().len();

    for _ in 0..25 {
        let (_conn, _token, out_rx) =
            attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
        drain(out_rx);
    }

    assert_eq!(
        endpoint.inner.transport_layer.get_listen_addrs(),
        before,
        "listener snapshot must be immune to connection churn"
    );
    assert!(
        endpoint.inner.transport_layer.get_addrs().len() > connections_before,
        "connections must remain visible for routing"
    );
    Ok(())
}

/// Initial INVITEs toward a WS target go through the same listen-only
/// selection: the Via carries the UDP listener's address with a WS token —
/// not the WS peer's address the destination lookup matched.
#[tokio::test]
async fn test_initial_invite_via_ignores_connection_addr() -> crate::Result<()> {
    let token = CancellationToken::new();
    let transport_layer = udp_only_endpoint(&token).await?;
    let udp_listener = transport_layer.get_listen_addrs()[0].clone();
    let endpoint = crate::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();

    let (conn, _conn_token, mut out_rx) =
        attach_client_channel(&endpoint, client_addr(Transport::Ws)).await;
    let _ = conn;

    // The endpoint serve loop drives outbound transactions (initial send +
    // Timer A retransmits); without it the INVITE never leaves.
    let serve_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = serve_inner.serve().await;
    });

    // Probe: the destination lookup must resolve to the cached channel.
    let probed = endpoint
        .inner
        .transport_layer
        .lookup(&client_addr(Transport::Ws), None)
        .await;
    assert!(
        probed.is_ok(),
        "lookup must find the cached channel: {probed:?}"
    );

    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let (state_sender, _state_receiver) = unbounded_channel();
    let invite_option = InviteOption {
        caller: "sip:alice@example.com".try_into()?,
        callee: "sip:bob@example.com;transport=ws".try_into()?,
        contact: "sip:alice@127.0.0.1".try_into()?,
        // Production callers (rustpbx locator / dial-back) resolve the WS
        // peer to a concrete destination; a URI host string would parse as
        // `Host::Domain` and miss the connection cache keyed on `IpAddr`.
        destination: Some(client_addr(Transport::Ws)),
        ..Default::default()
    };
    let mut invite = tokio::spawn(async move {
        dialog_layer
            .do_invite(invite_option, state_sender)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    });

    // The INVITE is delivered over the channel connection matched by
    // destination; read it back from the channel's outgoing frames. If the
    // INVITE flow exits before any frame, surface its error instead of a
    // bare timeout.
    let req = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                frame = out_rx.recv() => match frame {
                    Some(TransportEvent::Incoming(SipMessage::Request(req), _, _))
                        if req.method == Method::Invite =>
                    {
                        break req;
                    }
                    Some(_) => continue,
                    None => panic!("channel closed before the INVITE"),
                },
                res = &mut invite => {
                    panic!("do_invite finished without sending a frame: {res:?}")
                }
            }
        }
    })
    .await
    .expect("timeout waiting for the INVITE");

    let via = top_via(&req);
    assert_eq!(via.transport, Transport::Ws);
    assert_eq!(
        via.uri.host_with_port.host.to_string(),
        udp_listener.addr.host.to_string()
    );
    assert_eq!(via.uri.host_with_port.port, udp_listener.addr.port);
    assert_ne!(via.uri.host_with_port.host.to_string(), CLIENT_HOST);

    // Drop the INVITE transaction task: it keeps waiting for a response the
    // test never sends.
    invite.abort();
    Ok(())
}
