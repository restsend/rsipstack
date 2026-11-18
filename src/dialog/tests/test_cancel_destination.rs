//! A UAC dialog whose INVITE went to an explicit `InviteOption::destination`
//! (an outbound proxy or trunk next hop) must send its CANCEL to that same
//! address, port and transport (RFC 3261 §9.1), not to wherever the
//! Request-URI resolves. Here the Request-URI host does not resolve at all,
//! so a CANCEL that follows it never arrives.
use crate::dialog::{dialog::DialogState, dialog_layer::DialogLayer, invitation::InviteOption};
use crate::sip::{prelude::HeadersExt, typed::Route, Method, Request, SipMessage, Uri};
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

/// Receive the next request with `method` on the raw peer socket within
/// `wait`, skipping anything else.
async fn recv_request(socket: &UdpSocket, method: Method, wait: Duration) -> (Request, SocketAddr) {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            if req.method == method {
                return (req, from);
            }
        }
    }
}

/// Build a response to `req` as the peer UA, adding the peer's To tag.
fn response(req: &Request, code: u16, reason: &str, contact: &str) -> String {
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
         Contact: <{contact}>\r\n\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
    )
}

async fn reply(socket: &UdpSocket, to: SocketAddr, req: &Request, code: u16, reason: &str) {
    let contact = format!("sip:bob@{}", socket.local_addr().unwrap());
    socket
        .send_to(response(req, code, reason, &contact).as_bytes(), to)
        .await
        .expect("send_to failed");
}

/// A UAC whose INVITE names an unresolvable Request-URI host and goes to the
/// raw `peer` socket as its explicit next hop.
async fn setup(
    token: &CancellationToken,
) -> crate::Result<(Arc<DialogLayer>, InviteOption, UdpSocket)> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uac_addr = udp.get_addr().addr.clone();
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from("sip:+15551234567@carrier.invalid")?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        destination: Some(SipAddr::from(peer.local_addr()?)),
        ..Default::default()
    };
    Ok((
        Arc::new(DialogLayer::new(endpoint.inner.clone())),
        option,
        peer,
    ))
}

/// Sends the INVITE, answers it with 180 from the peer and waits for Early.
async fn ringing(
    token: &CancellationToken,
    preloaded_route: bool,
) -> crate::Result<(
    Arc<DialogLayer>,
    UdpSocket,
    Request,
    tokio::task::JoinHandle<()>,
)> {
    let (dialog_layer, mut option, peer) = setup(token).await?;
    if preloaded_route {
        option.destination = None;
        let route = Route::parse(&format!("<sip:{};lr>", peer.local_addr()?))?;
        option.route_set.push(route);
    }
    let wait = Duration::from_secs(2);
    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move {
        let _ = layer.do_invite(option, state_sender).await;
    });
    let (inv, uac) = recv_request(&peer, Method::Invite, wait).await;
    assert_eq!(inv.uri.to_string(), "sip:+15551234567@carrier.invalid");
    assert_eq!(inv.route_header().is_some(), preloaded_route);
    reply(&peer, uac, &inv, 180, "Ringing").await;
    tokio::time::timeout(wait, async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Early(_, _)) {
                return;
            }
        }
    })
    .await
    .expect("no Early state");
    Ok((dialog_layer, peer, inv, invite))
}

fn assert_cancels(cancel: &Request, invite: &Request) {
    assert_eq!(cancel.uri, invite.uri);
    assert_eq!(cancel.route_header(), invite.route_header());
    assert_eq!(
        cancel.call_id_header().unwrap().value(),
        invite.call_id_header().unwrap().value()
    );
    assert_eq!(
        cancel.via_header().unwrap().value(),
        invite.via_header().unwrap().value()
    );
}

#[tokio::test]
async fn test_explicit_cancel_goes_to_the_invite_destination() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog_layer, peer, inv, invite) = ringing(&token, false).await?;
    let call_id = inv.call_id_header()?.value().to_string();
    let dialogs = dialog_layer.get_client_dialog_by_call_id(&call_id);
    assert_eq!(dialogs.len(), 1);
    let dialog = dialogs[0].clone();
    let cancelling = tokio::spawn(async move { dialog.cancel().await });
    let (cancel, uac) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    reply(&peer, uac, &cancel, 200, "OK").await;
    cancelling.await.expect("cancel task")?;
    invite.abort();
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_dropped_invite_cancel_goes_to_the_invite_destination() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (_dialog_layer, peer, inv, invite) = ringing(&token, false).await?;
    invite.abort();
    let _ = invite.await;
    let (cancel, _) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_cancel_goes_to_the_preloaded_route() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog_layer, peer, inv, invite) = ringing(&token, true).await?;
    let dialog = dialog_layer
        .get_client_dialog_by_call_id(inv.call_id_header()?.value())
        .pop()
        .expect("early client dialog");
    let cancelling = tokio::spawn(async move { dialog.cancel().await });
    let (cancel, uac) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    reply(&peer, uac, &cancel, 200, "OK").await;
    cancelling.await.expect("cancel task")?;
    invite.abort();
    token.cancel();
    Ok(())
}
