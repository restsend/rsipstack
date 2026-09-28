//! In-dialog requests sent over TCP must carry a TCP Via (RFC 3261 §18.1.1:
//! the Via transport is the transport the request is sent over). The initial
//! INVITE already picks the listener that matches the target transport
//! (`make_invite_request`); BYE / re-INVITE / UPDATE built by the dialog used
//! the endpoint's first listener, which is UDP on a UDP+TCP endpoint.
use crate::dialog::{
    dialog_layer::DialogLayer, invitation::InviteOption, invite_dialog::InviteDialog,
};
use crate::sip::{
    prelude::{HeadersExt, ToTypedHeader},
    Method, Request, SipMessage, Transport, Uri,
};
use crate::transport::{tcp_listener::TcpListenerConnection, udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

/// Read SIP messages (no bodies) off a TCP stream until one is a request
/// with `method`.
async fn recv_request(stream: &mut TcpStream, buf: &mut Vec<u8>, method: Method) -> Request {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let raw: Vec<u8> = buf.drain(..end + 4).collect();
            let text = String::from_utf8(raw).expect("non utf-8 SIP message");
            if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text.as_str()) {
                if req.method == method {
                    return req;
                }
            }
            continue;
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
            .expect("read failed");
        assert!(n > 0, "connection closed while waiting for {method}");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn response(req: &Request, code: u16, reason: &str, extra: &str) -> String {
    let to = req.to_header().unwrap().value().to_string();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={PEER_TAG}")
    };
    format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {to}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         {extra}\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
    )
}

fn via_transport(req: &Request) -> Transport {
    req.top_via_header().unwrap().typed().unwrap().transport
}

/// A UAC endpoint listening on UDP (first) and TCP establishes a dialog with
/// a TCP peer. `record_route` makes the peer insert a Record-Route, so the
/// in-dialog requests follow the route set instead of the INVITE's flow.
async fn establish(
    token: &CancellationToken,
    record_route: bool,
) -> crate::Result<(InviteDialog, TcpStream, Vec<u8>)> {
    let peer = TcpListener::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    transport_layer.add_transport(udp.into());
    let tcp_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let tcp = TcpListenerConnection::new(format!("127.0.0.1:{tcp_port}").parse()?, None).await?;
    transport_layer.add_transport(tcp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let (state_sender, _state_receiver) = unbounded_channel();
    let invite_option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{peer_addr};transport=tcp").as_str())?,
        contact: Uri::try_from(format!("sip:alice@127.0.0.1:{tcp_port};transport=tcp").as_str())?,
        ..Default::default()
    };
    let invite = tokio::spawn(async move {
        dialog_layer
            .do_invite(invite_option, state_sender)
            .await
            .map(|(dialog, resp)| (dialog, resp.map(|r| r.status_code)))
    });

    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), peer.accept())
        .await
        .expect("timeout waiting for the INVITE connection")?;
    let mut buf = Vec::new();
    let req = recv_request(&mut stream, &mut buf, Method::Invite).await;
    assert_eq!(
        via_transport(&req),
        Transport::Tcp,
        "the initial INVITE over TCP carries a TCP Via"
    );
    let mut extra = format!("Contact: <sip:bob@{peer_addr};transport=tcp>\r\n");
    if record_route {
        extra.push_str(&format!(
            "Record-Route: <sip:{peer_addr};transport=tcp;lr>\r\n"
        ));
    }
    stream
        .write_all(response(&req, 200, "OK", &extra).as_bytes())
        .await?;
    recv_request(&mut stream, &mut buf, Method::Ack).await;

    let (dialog, status) = tokio::time::timeout(Duration::from_secs(2), invite)
        .await
        .expect("do_invite timed out")
        .expect("do_invite panicked")?;
    assert_eq!(status, Some(crate::sip::StatusCode::OK));
    Ok((dialog, stream, buf))
}

async fn assert_in_dialog_requests_use_tcp_via(record_route: bool) -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog, mut stream, mut buf) = establish(&token, record_route).await?;
    // A 2xx to a re-INVITE carries a Contact (RFC 3261 §12.1.1, §13.3.1.4).
    let contact = format!(
        "Contact: <sip:bob@{};transport=tcp>\r\n",
        stream.local_addr()?
    );

    let reinvite = {
        let dialog = dialog.clone();
        tokio::spawn(async move { dialog.reinvite(None, None).await })
    };
    let req = recv_request(&mut stream, &mut buf, Method::Invite).await;
    assert_eq!(
        via_transport(&req),
        Transport::Tcp,
        "a re-INVITE sent over TCP must carry a TCP Via, got: {}",
        req.via_header().unwrap().value()
    );
    stream
        .write_all(response(&req, 200, "OK", &contact).as_bytes())
        .await?;
    recv_request(&mut stream, &mut buf, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), reinvite)
        .await
        .expect("reinvite timed out")
        .expect("reinvite panicked")?;

    let bye = {
        let dialog = dialog.clone();
        tokio::spawn(async move { dialog.bye().await })
    };
    let req = recv_request(&mut stream, &mut buf, Method::Bye).await;
    assert_eq!(
        via_transport(&req),
        Transport::Tcp,
        "a BYE sent over TCP must carry a TCP Via, got: {}",
        req.via_header().unwrap().value()
    );
    stream
        .write_all(response(&req, 200, "OK", "").as_bytes())
        .await?;
    tokio::time::timeout(Duration::from_secs(2), bye)
        .await
        .expect("bye timed out")
        .expect("bye panicked")?;

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_in_dialog_requests_over_tcp_flow_carry_tcp_via() -> crate::Result<()> {
    assert_in_dialog_requests_use_tcp_via(false).await
}

#[tokio::test]
async fn test_in_dialog_requests_over_tcp_route_carry_tcp_via() -> crate::Result<()> {
    assert_in_dialog_requests_use_tcp_via(true).await
}

/// Maps every target to a fixed UDP address, as a locator that decides the
/// transport at send time would.
struct UdpLocator(crate::transport::SipAddr);

#[async_trait::async_trait]
impl crate::transaction::endpoint::TargetLocator for UdpLocator {
    async fn locate(&self, _uri: &Uri) -> crate::Result<crate::transport::SipAddr> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn test_in_dialog_via_is_left_to_the_locator() -> crate::Result<()> {
    use crate::dialog::{dialog::DialogInner, DialogId};
    use crate::sip::headers::{CSeq, CallId, Contact, From, MaxForwards, To, Via};
    use crate::transaction::key::TransactionRole;

    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let udp_addr = udp.get_addr().clone();
    transport_layer.add_transport(udp.into());
    let tcp = TcpListenerConnection::new("127.0.0.1:5999".parse()?, None).await?;
    transport_layer.add_transport(tcp.into());
    let mut builder = EndpointBuilder::new();
    builder
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .with_target_locator(Box::new(UdpLocator(udp_addr)));
    let endpoint = builder.build();

    let initial = Request {
        method: Method::Invite,
        uri: Uri::try_from("sip:bob@192.0.2.10:5060;transport=tcp")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKlocator").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=alice-tag").into(),
            To::new("<sip:bob@example.com>;tag=bob-tag").into(),
            CallId::new("via-locator").into(),
            Contact::new("<sip:alice@127.0.0.1:5060>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    };
    let id = DialogId::try_from((&initial, TransactionRole::Client))?;
    let (tu_tx, _tu_rx) = unbounded_channel();
    let (state_tx, _state_rx) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Client,
        id,
        initial,
        endpoint.inner.clone(),
        state_tx,
        None,
        Some(Uri::try_from("sip:alice@127.0.0.1:5060")?),
        tu_tx,
    )?;
    *inner.remote_uri.lock() = Uri::try_from("sip:bob@192.0.2.10:5060;transport=tcp")?;

    let bye = inner.make_request(Method::Bye, None, None, None, None, None)?;
    assert_eq!(
        via_transport(&bye),
        Transport::Udp,
        "with a target locator the transport is decided at send time; keep the default Via"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_dialback_retry_keeps_the_via_on_its_transport() -> crate::Result<()> {
    use crate::dialog::{
        dialog::{DialogInner, DialogState},
        DialogId,
    };
    use crate::sip::headers::{CSeq, CallId, Contact, From, MaxForwards, To, Via};
    use crate::transaction::key::TransactionRole;

    // A server dialog received over UDP whose Contact names TCP: when the TCP
    // target cannot be reached, the BYE is dialed back over the recorded UDP
    // source, and its Via must say UDP.
    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    transport_layer.add_transport(udp.into());
    let tcp = TcpListenerConnection::new("127.0.0.1:5999".parse()?, None).await?;
    transport_layer.add_transport(tcp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let probe_port = probe.local_addr()?.port();
    let closed_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let initial = Request {
        method: Method::Invite,
        uri: Uri::try_from("sip:bob@127.0.0.1:5060")?,
        headers: vec![
            Via::new(
                format!("SIP/2.0/UDP caller.invalid:5060;branch=z9hG4bKdialback;received=127.0.0.1;rport={probe_port}")
                    .as_str(),
            )
            .into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=alice-tag").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("via-dialback").into(),
            Contact::new(format!("<sip:alice@127.0.0.1:{closed_port};transport=tcp>").as_str())
                .into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    };
    let mut id = DialogId::try_from((&initial, TransactionRole::Server))?;
    id.local_tag = "local-tag".into();
    let (tu_tx, _tu_rx) = unbounded_channel();
    let (state_tx, _state_rx) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Server,
        id.clone(),
        initial,
        endpoint.inner.clone(),
        state_tx,
        None,
        Some(Uri::try_from("sip:bob@127.0.0.1:5060")?),
        tu_tx,
    )?;
    *inner.remote_uri.lock() =
        Uri::try_from(format!("sip:alice@127.0.0.1:{closed_port};transport=tcp").as_str())?;
    inner.transition(DialogState::Confirmed(id, Default::default()))?;
    let dialog = InviteDialog::from_inner(std::sync::Arc::new(inner));
    tokio::spawn(async move { dialog.bye().await });

    let mut buf = [0u8; 4096];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), probe.recv_from(&mut buf))
            .await
            .expect("the BYE must be dialed back to the recorded UDP source")?;
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text.as_str()) {
            if req.method == Method::Bye {
                assert_eq!(
                    via_transport(&req),
                    Transport::Udp,
                    "a BYE dialed back over UDP must carry a UDP Via, got: {}",
                    req.via_header().unwrap().value()
                );
                assert!(
                    !req.via_header().unwrap().value().contains("alias"),
                    "a UDP Via carries no TCP alias parameter"
                );
                break;
            }
        }
    }
    token.cancel();
    Ok(())
}
