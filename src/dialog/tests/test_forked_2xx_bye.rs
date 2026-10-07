//! RFC 3261 §13.2.2.4: a 2xx to the INVITE with a new To tag establishes its
//! own dialog. The UAC keeps a single session (the first 2xx's): the
//! transaction ACKs the forked 2xx with its own tag and remote target, and
//! the dialog layer ends the extra branch with a BYE built from that
//! response's Contact. No dialog is registered for the branch and the
//! confirmed dialog's state is untouched.

use crate::dialog::dialog_layer::DialogLayer;
use crate::dialog::invitation::InviteOption;
use crate::dialog::DialogId;
use crate::sip::prelude::HeadersExt;
use crate::sip::{Method, Request, SipMessage, Uri};
use crate::transport::udp::UdpConnection;
use crate::transport::TransportLayer;
use crate::EndpointBuilder;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

/// Receive the next request of `method` at `peer`.
async fn next_request(
    peer: &UdpSocket,
    method: Method,
    what: &str,
) -> (Request, std::net::SocketAddr) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, from) = tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for the {what}"))
            .expect("peer socket error");
        let Ok(SipMessage::Request(req)) = SipMessage::try_from(&buf[..len]) else {
            continue;
        };
        if req.method == method {
            return (req, from);
        }
    }
}

/// Answer a request the way the peer UA would (top Via honored).
async fn reply_ok(
    peer: &UdpSocket,
    req: &Request,
    from: std::net::SocketAddr,
) -> crate::Result<()> {
    let ok = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
        req.via_header()?.value(),
        req.from_header()?.value(),
        req.to_header()?.value(),
        req.call_id_header()?.value(),
        req.cseq_header()?.value(),
    );
    peer.send_to(ok.as_bytes(), from).await?;
    Ok(())
}

/// RFC 3261 §13.2.2.4: a forked 2xx (To tag `tag-b`) is ACKed with its own
/// tag and remote target (the transaction's job, pinned here end to end) and
/// then ended with a BYE built from its Contact — without touching the
/// confirmed dialog or registering the forked branch.
#[tokio::test]
async fn test_forked_2xx_is_byed_without_touching_the_confirmed_dialog() -> crate::Result<()> {
    let token = CancellationToken::new();
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let uac_addr = udp.get_addr().get_socketaddr()?;
    let contact = Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?;
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(tl)
        .with_option(crate::transaction::endpoint::EndpointOption {
            t1: Duration::from_millis(10),
            t1x64: Duration::from_millis(640),
            ..Default::default()
        })
        .build();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { inner.serve().await });

    let layer = DialogLayer::new(endpoint.inner.clone());
    let (state_sender, mut states) = unbounded_channel();
    let invite = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{}", peer.local_addr()?).as_str())?,
        contact,
        ..Default::default()
    };
    // A second handle over the same layer state, for the assertions below
    // (DialogLayer is not Clone; the registry lives in the shared inner).
    let assert_layer = DialogLayer {
        endpoint: layer.endpoint.clone(),
        inner: layer.inner.clone(),
    };
    let do_invite = tokio::spawn(async move { layer.do_invite(invite, state_sender).await });

    // The INVITE arrives; branch A answers with tag-a.
    let mut buf = vec![0u8; 4096];
    let (len, from) = tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
        .await
        .expect("timeout waiting for the INVITE")?;
    let invite_req = match SipMessage::try_from(&buf[..len])? {
        SipMessage::Request(req) if req.method == Method::Invite => req,
        other => panic!("expected the INVITE, got {other}"),
    };
    let ok_a = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=tag-a\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <sip:bob-a@{}>\r\nContent-Length: 0\r\n\r\n",
        invite_req.via_header()?.value(),
        invite_req.from_header()?.value(),
        invite_req.to_header()?.value(),
        invite_req.call_id_header()?.value(),
        invite_req.cseq_header()?.value(),
        peer.local_addr()?,
    );
    peer.send_to(ok_a.as_bytes(), from).await?;

    let (dialog, _) = tokio::time::timeout(Duration::from_secs(3), do_invite)
        .await
        .expect("timeout waiting for do_invite")
        .expect("do_invite task panicked")?;
    assert!(dialog.inner.state.lock().is_confirmed());
    while states.try_recv().is_ok() {}

    let confirmed = dialog.id();
    assert_eq!(confirmed.remote_tag, "tag-a");

    // Branch B forks in: same Call-ID, new To tag, own Contact.
    let ok_b = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=tag-b\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <sip:bob-b@{}>\r\nContent-Length: 0\r\n\r\n",
        invite_req.via_header()?.value(),
        invite_req.from_header()?.value(),
        invite_req.to_header()?.value(),
        invite_req.call_id_header()?.value(),
        invite_req.cseq_header()?.value(),
        peer.local_addr()?,
    );
    peer.send_to(ok_b.as_bytes(), uac_addr).await?;

    // The first ACK confirms branch A; the forked 2xx is then ACKed with
    // its own tag and Contact as R-URI.
    let (mut ack, _) = next_request(&peer, Method::Ack, "forked ACK").await;
    while !ack
        .to_header()
        .ok()
        .and_then(|to| to.tag().ok().flatten())
        .is_some_and(|tag| tag.value() == "tag-b")
    {
        (ack, _) = next_request(&peer, Method::Ack, "forked ACK").await;
    }
    let ack_to = ack.to_header()?.value().to_string();
    assert!(ack_to.contains(";tag=tag-b"), "ACK To: {ack_to}");
    assert!(
        ack.uri.to_string().contains("bob-b"),
        "ACK R-URI must be the forked Contact: {}",
        ack.uri
    );

    // The forked branch is then ended with a BYE from its own Contact.
    let (bye, from) = next_request(&peer, Method::Bye, "forked-branch BYE").await;
    let bye_to = bye.to_header()?.value().to_string();
    assert!(bye_to.contains(";tag=tag-b"), "BYE To: {bye_to}");
    assert!(
        bye.uri.to_string().contains("bob-b"),
        "BYE R-URI must be the forked Contact: {}",
        bye.uri
    );
    let cseq = bye.cseq_header()?.value().to_string();
    assert_eq!(cseq, "2 BYE", "BYE CSeq continues the forked dialog's");
    assert_eq!(
        bye.call_id_header()?.value(),
        invite_req.call_id_header()?.value()
    );
    // The forked callee answers the BYE like a real UA would.
    reply_ok(&peer, &bye, from).await?;

    // A retransmission of the forked 2xx (in flight before its ACK landed)
    // must not trigger a second BYE.
    peer.send_to(ok_b.as_bytes(), uac_addr).await?;
    let mut buf = vec![0u8; 4096];
    let quiet_until = tokio::time::Instant::now() + Duration::from_millis(400);
    loop {
        let remaining = quiet_until.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, peer.recv_from(&mut buf)).await {
            Err(_) => break, // the quiet window elapsed: no duplicate BYE
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((len, _))) => {
                if let Ok(SipMessage::Request(req)) = SipMessage::try_from(&buf[..len]) {
                    assert_ne!(
                        req.method,
                        Method::Bye,
                        "duplicate BYE for a retransmitted forked 2xx"
                    );
                }
            }
        }
    }

    // The confirmed dialog is untouched: no new state notifications, no
    // dialog registered for the forked branch, and the dialog still works.
    assert!(
        states.try_recv().is_err(),
        "the forked 2xx must not touch the confirmed dialog's state"
    );
    let forked_id = DialogId {
        call_id: confirmed.call_id.clone(),
        local_tag: confirmed.local_tag.clone(),
        remote_tag: "tag-b".to_string(),
    };
    assert!(
        assert_layer.get_dialog(&forked_id).is_none(),
        "the forked branch must not be registered as a dialog"
    );
    assert!(dialog.inner.state.lock().is_confirmed());

    // The confirmed dialog is still usable: a BYE ends it normally.
    let dialog2 = dialog.clone();
    let bye_task = tokio::spawn(async move { dialog2.bye().await });
    let (bye, _) = next_request(&peer, Method::Bye, "confirmed-dialog BYE").await;
    assert!(
        bye.to_header()?.value().to_string().contains(";tag=tag-a"),
        "the confirmed dialog's BYE keeps tag-a: {}",
        bye.to_header()?.value()
    );
    reply_ok(&peer, &bye, uac_addr).await?;
    tokio::time::timeout(Duration::from_secs(3), bye_task)
        .await
        .expect("timeout waiting for bye()")
        .expect("bye task panicked")?;
    assert!(dialog.inner.state.lock().is_terminated());
    token.cancel();
    Ok(())
}
