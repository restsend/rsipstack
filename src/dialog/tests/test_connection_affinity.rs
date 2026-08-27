//! Connection-affinity regression tests (RFC 5626 / RFC 7118 §6.2)
//!
//! Reproduces the production failure observed with JsSIP/WebRTC clients:
//!
//! * A browser places a call over WSS. Its Contact URI is a random flow token
//!   under `.invalid` (RFC 7118 B.1) and must never be resolved for routing —
//!   the browser is only reachable through the original WSS connection.
//! * After the remote (RTP) leg hangs up, the proxy sends a BYE on the caller
//!   dialog. Previously `send_dialog_request` created a fresh client
//!   transaction with no connection, attempted DNS resolution of the
//!   `.invalid` Request-URI/Contact, failed, and Timer A retransmitted the
//!   BYE forever ("no connection, will retry on timer") until Timer B gave up:
//!   the browser never received it and the dialog stayed open.
//!
//! The fix stores the connection that delivered the dialog-forming request
//! (`DialogInner::server_connection`) and reuses it for in-dialog requests.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use crate::dialog::{
    dialog::{DialogInner, DialogState, TerminatedReason},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
    DialogId,
};
use crate::sip::{
    headers::{CSeq, CallId, Contact, From, MaxForwards, Route, To, Via},
    prelude::{HeadersExt, ToTypedHeader},
    Host, HostWithPort, Method, Request, Response, SipMessage, StatusCode, Transport, Version,
};
use crate::transaction::{
    endpoint::EndpointBuilder,
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{
    channel::ChannelConnection,
    udp::{UdpConnection, UdpInner},
    SipAddr, SipConnection, TransportEvent, TransportLayer,
};

/// WSS-style INVITE as emitted by browser stacks (JsSIP): `.invalid` Via /
/// Contact hosts (RFC 7118 B.1) plus an `ob` marker (RFC 5626).
fn create_wss_invite_request(from_tag: &str, to_tag: &str, call_id: &str, branch: &str) -> Request {
    Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:+12761187472182@58.246.19.74:6988").unwrap(),
        headers: vec![
            Via::new(format!("SIP/2.0/WSS vfa095afrt10.invalid;branch={branch}").as_str()).into(),
            CSeq::new("2421 INVITE").into(),
            From::new(format!("<sip:agent@pbx.example.com>;tag={from_tag}").as_str()).into(),
            To::new(format!("<sip:+12761187472182@58.246.19.74:6988>;tag={to_tag}").as_str())
                .into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:skpn0n1b@vfa095afrt10.invalid;transport=ws;ob>").into(),
            MaxForwards::new("69").into(),
        ]
        .into(),
        version: Version::V2,
        body: b"v=0\r\no=- 449672722 449672723 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_vec(),
    }
}

fn plain_udp_invite(from_tag: &str, call_id: &str, via: &str) -> Request {
    Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com:5060").unwrap(),
        headers: vec![
            Via::new(via).into(),
            CSeq::new("1 INVITE").into(),
            From::new(format!("Alice <sip:alice@example.com>;tag={from_tag}").as_str()).into(),
            To::new("Bob <sip:bob@example.com>").into(),
            CallId::new(call_id).into(),
            // Unroutable host on purpose: normal resolution must fail so the
            // code under test has to fall back to something else.
            Contact::new("<sip:alice@alice.invalid:5060>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: Version::V2,
        body: vec![],
    }
}

fn server_dialog(
    endpoint_inner: crate::transaction::endpoint::EndpointInnerRef,
    role: TransactionRole,
    initial: Request,
    local_contact: &str,
) -> DialogInner {
    let id = DialogId::try_from((&initial, role)).unwrap();
    let (tu_tx, _tu_rx) = unbounded_channel();
    let (state_tx, _state_rx) = unbounded_channel();
    let mut id_local = id;
    if role == TransactionRole::Server && id_local.local_tag.is_empty() {
        // DialogId::try_from yields an empty local tag before the layer
        // assigns one; any non-empty tag keeps the To/From headers tagged.
        id_local.local_tag = "local-tag".into();
    }
    DialogInner::new(
        role,
        id_local,
        initial,
        endpoint_inner,
        state_tx,
        None,
        Some(crate::sip::Uri::try_from(local_contact).unwrap()),
        tu_tx,
    )
    .unwrap()
}

/// Endpoint whose transport layer has only an internal loopback UDP socket:
/// any *address-based* lookup / new-connection attempt toward a foreign host
/// fails, so requests can reach the asserted wire exclusively through an
/// explicitly wired connection (or the explicit fallback dial-back).
async fn create_endpoint_without_transports(
) -> crate::Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    // A minimal local socket so make_request can build its own Via/Contact
    // (`get_addrs()`); it deliberately cannot route to external hosts.
    // The address must be explicitly transport-typed for TransportLayer
    // lookups to treat it as a usable UDP socket.
    let local = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = {
        let sock = local.local_addr()?;
        SipAddr {
            r#type: Some(Transport::Udp),
            addr: crate::sip::HostWithPort {
                host: Host::IpAddr(sock.ip()),
                port: Some(sock.port().into()),
            },
        }
    };
    let udp_conn = UdpConnection::attach(
        UdpInner {
            conn: local,
            addr: local_addr,
        },
        None,
        Some(token.child_token()),
    )
    .await;
    tl.inner.add_listener(udp_conn.into());

    Ok(EndpointBuilder::new()
        .with_user_agent("rsipstack-affinity-test")
        .with_transport_layer(tl)
        .build())
}

fn wss_flow_addr(port: u16) -> SipAddr {
    SipAddr {
        r#type: Some(Transport::Wss),
        addr: HostWithPort {
            host: Host::IpAddr(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            port: Some(port.into()),
        },
    }
}

/// Creates a ChannelConnection emulating a browser's WSS flow and registers
/// it with the endpoint's transport layer so bidirectional traffic works:
///
/// * the stack sending over the connection surfaces as
///   [`TransportEvent::Incoming`] on `wire_rx` (the "browser" side),
/// * pushing an event into `in_tx` injects inbound traffic into the stack.
struct WssFlow {
    sip_conn: SipConnection,
    wire_rx: UnboundedReceiver<TransportEvent>,
    in_tx: UnboundedSender<TransportEvent>,
    addr: SipAddr,
    /// Cancellation handle of the flow; cancelling simulates the browser
    /// dropping its WebSocket connection.
    cancel: CancellationToken,
}

async fn create_wss_flow(
    endpoint_inner: &crate::transaction::endpoint::EndpointInnerRef,
    addr: SipAddr,
) -> WssFlow {
    let cancel = CancellationToken::new();
    let (in_tx, in_rx) = unbounded_channel::<TransportEvent>();
    let (out_tx, out_rx) = unbounded_channel();
    let conn =
        ChannelConnection::create_connection(in_rx, out_tx, addr.clone(), Some(cancel.clone()))
            .await
            .expect("channel flow connection");
    let sip_conn = SipConnection::Channel(conn);
    // Registers the connection and starts its serve_loop toward the endpoint.
    endpoint_inner
        .transport_layer
        .add_connection(sip_conn.clone());
    WssFlow {
        sip_conn,
        wire_rx: out_rx,
        in_tx,
        addr,
        cancel,
    }
}

#[tokio::test]
async fn test_server_dialog_bye_is_delivered_over_initial_connection() {
    // ── arrange ────────────────────────────────────────────────────────────
    // WSS INVITE arrives from a browser over the flow connection; afterwards
    // we hang up that leg exactly like rustpbx does when the remote RTP leg
    // sends its own BYE.
    let endpoint = create_endpoint_without_transports().await.unwrap();
    let endpoint_inner = endpoint.inner.clone();
    let dialog_layer = DialogLayer::new(endpoint_inner.clone());
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let mut flow = create_wss_flow(&endpoint.inner, wss_flow_addr(38_013)).await;

    let invite =
        create_wss_invite_request("h45rr596ko", "", "affinity-bye-callid", "z9hG4bK8544229");
    let key = TransactionKey::from_request(&invite, TransactionRole::Server).unwrap();
    let tx = Transaction::new_server(
        key,
        invite.clone(),
        endpoint.inner.clone(),
        Some(flow.sip_conn.clone()),
    );

    let (state_tx, mut state_rx) = unbounded_channel();
    let dialog = dialog_layer
        .get_or_create_server_invite(
            &tx,
            state_tx,
            None,
            Some(crate::sip::Uri::try_from("sip:pbx@pbx.example.com:5060").unwrap()),
        )
        .expect("dialog created");

    // Connection affinity must be recorded at creation time...
    assert!(
        dialog.inner.server_connection.lock().is_some(),
        "server dialog must remember the incoming connection"
    );
    // ...and be selected as the outgoing path for reliable transports.
    assert!(dialog.inner.test_resolve_affinity_connection().is_some());

    // Confirm the dialog, then hang it up.
    let id = dialog.id();
    dialog
        .inner
        .transition(DialogState::Confirmed(id.clone(), Response::default()))
        .expect("confirm dialog");
    assert!(dialog.inner.is_confirmed());

    let bye_dialog = dialog.clone();
    let bye_handle = tokio::spawn(async move {
        bye_dialog
            .bye_with_headers(None)
            .await
            .expect("bye_with_headers must succeed")
    });

    // ── act + assert: BYE reaches the wire of the ORIGINAL connection ──────
    // No DNS of `.invalid`, no Timer A retransmission loop, no fallback.
    let event = tokio::time::timeout(Duration::from_secs(3), flow.wire_rx.recv())
        .await
        .expect("BYE must be forwarded over the initial connection")
        .expect("connection sender alive");

    let bye_req = match event {
        TransportEvent::Incoming(SipMessage::Request(req), _transport, _src) => {
            assert_eq!(req.method, Method::Bye);
            assert_eq!(
                req.uri.host_with_port.host.to_string(),
                "vfa095afrt10.invalid",
                "remote target must remain the recorded browser Contact"
            );
            assert_eq!(
                req.cseq_header()
                    .expect("cseq")
                    .typed()
                    .expect("typed cseq")
                    .method,
                Method::Bye
            );
            let via = req.via_header().expect("via").typed().expect("typed via");
            assert!(via.branch().is_some(), "outgoing BYE must carry a branch");
            req
        }
        other => panic!("expected outgoing BYE request, got {other:?}"),
    };

    // ── complete the handshake: the browser answers 200 OK for our BYE ─────
    let ok_response = Response {
        status_code: StatusCode::OK,
        version: Version::V2,
        headers: vec![
            bye_req.via_header().unwrap().clone().into(),
            bye_req.from_header().unwrap().clone().into(),
            bye_req.to_header().unwrap().clone().into(),
            bye_req.call_id_header().unwrap().clone().into(),
            bye_req.cseq_header().unwrap().clone().into(),
            crate::sip::headers::ContentLength::from(0u32).into(),
        ]
        .into(),
        body: vec![],
    };
    flow.in_tx
        .send(TransportEvent::Incoming(
            SipMessage::Response(ok_response),
            flow.sip_conn.clone(),
            flow.addr.clone(),
        ))
        .expect("inbound injection");

    // The dialog reports termination (UAS-initiated ⇒ UasBye). Earlier state
    // echoes (Calling/Confirmed from setup) may be queued ahead of it.
    let deadline = Duration::from_secs(2);
    let mut terminated_reason = None;
    while let Ok(Some(state)) = tokio::time::timeout(deadline, state_rx.recv()).await {
        if let DialogState::Terminated(_, reason) = state {
            terminated_reason = Some(reason);
            break;
        }
    }
    let reason = terminated_reason.expect("dialog must terminate after 200 OK for BYE");
    assert!(matches!(reason, TerminatedReason::UasBye));
    // ...and bye() returns cleanly.
    tokio::time::timeout(Duration::from_secs(1), bye_handle)
        .await
        .expect("bye task to finish")
        .ok();
}

#[tokio::test]
async fn test_client_dialogs_do_not_use_affinity() {
    // A UAC resolves its own next hops; it must not adopt whatever socket was
    // involved when the dialog responses arrived.
    let endpoint = create_endpoint_without_transports().await.unwrap();

    let initial = plain_udp_invite(
        "alice-tag",
        "client-no-affinity",
        "SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKclient1",
    );
    let inner = Arc::new(server_dialog(
        endpoint.inner.clone(),
        TransactionRole::Client,
        initial,
        "sip:uac@example.com",
    ));

    let flow = create_wss_flow(&endpoint.inner, wss_flow_addr(38_014)).await;
    inner.set_server_connection(Some(flow.sip_conn));

    assert!(
        inner.test_resolve_affinity_connection().is_none(),
        "client dialogs must not use connection affinity"
    );
}

#[tokio::test]
async fn test_affinity_skips_unreliable_udp_connections() {
    // UDP keeps classic destination-based routing: never pin in-dialog
    // traffic to whichever socket happened to deliver the first packet.
    let endpoint = create_endpoint_without_transports().await.unwrap();

    let initial = plain_udp_invite(
        "alice-tag",
        "udp-affinity-check",
        "SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKudp1",
    );
    let inner = Arc::new(server_dialog(
        endpoint.inner.clone(),
        TransactionRole::Server,
        initial,
        "sip:bob@example.com",
    ));

    let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .unwrap();
    inner.set_server_connection(Some(SipConnection::Udp(udp_conn)));

    assert!(
        inner.test_resolve_affinity_connection().is_none(),
        "UDP connections must not be used for affinity routing"
    );
}

#[tokio::test]
async fn test_affinity_requires_recorded_reliable_server_connection() {
    let endpoint = create_endpoint_without_transports().await.unwrap();

    let initial = create_wss_invite_request("t1", "", "guards-callid", "z9hG4bKguard");
    let inner = Arc::new(server_dialog(
        endpoint.inner.clone(),
        TransactionRole::Server,
        initial,
        "sip:bob@example.com",
    ));

    // Nothing recorded yet → None.
    assert!(inner.test_resolve_affinity_connection().is_none());

    // Reliable connection recorded on a server dialog → selected.
    let flow = create_wss_flow(&endpoint.inner, wss_flow_addr(38_015)).await;
    inner.set_server_connection(Some(flow.sip_conn));
    assert!(inner.test_resolve_affinity_connection().is_some());

    // With a route set present (loose-routing proxy in path), affinity must
    // yield to route-set based resolution.
    inner
        .route_set
        .lock()
        .push(Route::from("sip:proxy.example.com;lr"));
    assert!(
        inner.test_resolve_affinity_connection().is_none(),
        "route set must take precedence over raw flow affinity"
    );
}

#[tokio::test]
async fn test_restored_dialog_falls_back_to_initial_via_dialback() {
    // Snapshot-restored dialogs have no persisted connection. When their
    // Contact cannot be routed either, send_dialog_request dials back to the
    // source recorded in the initial request's Via (`received` + `rport`).
    //
    // Here the INVITE claims an unroutable Contact but truthfully reports its
    // transport source as 127.0.0.1:<probe port>. The BYE must surface there
    // as a datagram via the endpoint's UDP listener socket.

    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
    let probe_port = probe.local_addr().unwrap().port();

    // Endpoint needs ≥1 UDP listener so lookup against a UDP target falls
    // back to using the listener's socket for transmission.
    let dummy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dummy_sock = dummy.local_addr().unwrap();
    let udp_conn = UdpConnection::attach(
        UdpInner {
            conn: dummy,
            addr: SipAddr {
                r#type: Some(Transport::Udp),
                addr: crate::sip::HostWithPort {
                    host: Host::IpAddr(dummy_sock.ip()),
                    port: Some(dummy_sock.port().into()),
                },
            },
        },
        None,
        Some(token.child_token()),
    )
    .await;
    tl.inner.add_listener(udp_conn.into());

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-fallback-test")
        .with_transport_layer(tl)
        .build();

    let via = format!(
        "SIP/2.0/UDP caller.invalid:5060;branch=z9hG4bKfallback1;received=127.0.0.1;rport={probe_port}"
    );
    let invite = plain_udp_invite("restored-tag", "fallback-dialback", &via);

    let inner = Arc::new(server_dialog(
        endpoint.inner.clone(),
        TransactionRole::Server,
        invite,
        "sip:bob@bob.example.com:5060",
    ));
    // Simulate snapshot restore: no remembered connection.
    assert!(inner.test_resolve_affinity_connection().is_none());

    let id = inner.id.lock().clone();
    inner
        .transition(DialogState::Confirmed(id.clone(), Response::default()))
        .unwrap();
    assert!(inner.is_confirmed());

    // No responder will answer the BYE here — we only assert delivery.
    let _bye_handle = tokio::spawn(async move {
        let dialog = InviteDialog::from_inner(inner);
        if let Err(e) = dialog.bye_with_headers(None).await {
            std::eprintln!("[DBG] fallback bye error: {e}");
        }
        std::eprintln!("[DBG] fallback bye finished");
    });

    // Retransmissions may duplicate the packet while we wait for a response
    // nobody sends; receiving at least one BYE proves the dial-back worked.
    let deadline = Duration::from_secs(3);
    let mut buf = [0u8; 2048];
    loop {
        let (len, _peer) = tokio::time::timeout(deadline, probe.recv_from(&mut buf))
            .await
            .expect("BYE dial-back datagram must reach the Via-received address")
            .expect("recv ok");
        let text = String::from_utf8_lossy(&buf[..len]);
        if text.starts_with("BYE ") {
            break;
        }
    }
}

/// A cancelled (dead) WebSocket flow must not cause affinity retransmissions
/// into a dead socket, and the dial-back ladder must still deliver the BYE
/// through tier 1 — the address captured from the connection at creation —
/// even when the INVITE's Via carries NO received/rport parameters
/// (`build_via_received` legitimately omits them when the sent-by host and
/// port already match the real source, RFC 3581 corner).
#[tokio::test]
async fn test_bye_survives_cancelled_flow_without_received_via_param() {
    let endpoint = create_endpoint_without_transports().await.unwrap();
    let endpoint_inner = endpoint.inner.clone();
    let dialog_layer = DialogLayer::new(endpoint_inner.clone());
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    // INVITE without received/rport on its Via.
    let invite =
        create_wss_invite_request("nocall123", "", "cancelled-flow-callid", "z9hG4bKnorecv1");
    assert!(invite.via_header().unwrap().to_string().len() > 0);

    let mut flow = create_wss_flow(&endpoint.inner, wss_flow_addr(38_016)).await;
    let key = TransactionKey::from_request(&invite, TransactionRole::Server).unwrap();
    let tx = Transaction::new_server(
        key,
        invite.clone(),
        endpoint.inner.clone(),
        Some(flow.sip_conn.clone()),
    );

    let (state_tx, _state_rx) = unbounded_channel();
    let dialog = dialog_layer
        .get_or_create_server_invite(
            &tx,
            state_tx,
            None,
            Some(crate::sip::Uri::try_from("sip:pbx@pbx.example.com:5060").unwrap()),
        )
        .expect("dialog created");

    // Creation captured BOTH the connection and its structural remote address.
    assert!(dialog.inner.server_connection.lock().is_some());
    assert_eq!(
        dialog.inner.dialback_target.lock().as_ref(),
        Some(&flow.addr),
        "dial-back target must be captured structurally at creation"
    );

    let id = dialog.id();
    dialog
        .inner
        .transition(DialogState::Confirmed(id.clone(), Response::default()))
        .expect("confirm dialog");

    // Browser drops the connection before we hang up the leg.
    flow.cancel.cancel();
    assert!(
        dialog.inner.test_resolve_affinity_connection().is_none(),
        "a cancelled flow must be rejected by the affinity filter"
    );
    // The structural address survives the dead flow object.
    assert!(
        dialog.inner.dialback_target.lock().is_some(),
        "dial-back target must outlive the connection"
    );

    let bye_dialog = dialog.clone();
    tokio::spawn(async move {
        let _ = bye_dialog.bye_with_headers(None).await;
    });

    // Tier-① dial-back resolves to the registered WSS channel flow and the
    // BYE is delivered there — no DNS of `.invalid`, no Timer A limbo.
    let event = tokio::time::timeout(Duration::from_secs(3), flow.wire_rx.recv())
        .await
        .expect("BYE must reach the flow via tier-1 dial-back despite no Via params")
        .expect("connection sender alive");

    match event {
        TransportEvent::Incoming(SipMessage::Request(req), _transport, _src) => {
            assert_eq!(req.method, Method::Bye);
        }
        other => panic!("expected outgoing BYE request, got {other:?}"),
    }
}
