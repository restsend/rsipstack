use super::test_dialog_states::{create_invite_request, create_test_endpoint};
use crate::dialog::{dialog::DialogInner, server_dialog::ServerInviteDialog, DialogId};
use crate::sip::headers::*;
use crate::sip::{Header, Method, Request, SipMessage, StatusCode};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{
    channel::ChannelConnection, connection::TransportEvent, SipAddr, SipConnection,
};
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn server_dialog_handles_prack_request() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-prack".to_string(),
        local_tag: "bob-tag".to_string(),
        remote_tag: "alice-tag".to_string(),
    };

    let invite_req = create_invite_request(&dialog_id.remote_tag, "", &dialog_id.call_id);

    let dialog_inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
        tu_sender,
    )?;

    let mut server_dialog = ServerInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Build PRACK request
    let prack_request = Request {
        method: Method::PRack,
        uri: crate::sip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKprack01").into(),
            CSeq::new("2 PRACK").into(),
            From::new(&format!(
                "Alice <sip:alice@example.com>;tag={}",
                dialog_id.remote_tag
            ))
            .into(),
            To::new(&format!(
                "Bob <sip:bob@example.com>;tag={}",
                dialog_id.local_tag
            ))
            .into(),
            CallId::new(&dialog_id.call_id).into(),
            Header::Other("RAck".into(), "1 1 INVITE".into()),
            Contact::new("<sip:alice@198.51.100.1:5060>").into(),
            MaxForwards::new("70").into(),
            Header::ContentLength((0u32).into()),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    };

    let key = TransactionKey::from_request(&prack_request, TransactionRole::Server)?;

    let (_, incoming_rx) = unbounded_channel();
    let (transport_tx, mut transport_rx) = unbounded_channel();

    let sip_addr: SipAddr = crate::sip::HostWithPort::try_from("127.0.0.1:5060")?.into();

    let channel =
        ChannelConnection::create_connection(incoming_rx, transport_tx, sip_addr.clone(), None)
            .await?;
    let connection = SipConnection::Channel(channel);

    let mut tx =
        Transaction::new_server(key, prack_request, endpoint.inner.clone(), Some(connection));
    tx.destination = Some(sip_addr.clone());

    server_dialog.handle(&mut tx).await?;

    let event = timeout(Duration::from_secs(1), transport_rx.recv())
        .await
        .expect("timeout waiting for PRACK response")
        .expect("transport event");
    match event {
        TransportEvent::Incoming(SipMessage::Response(resp), _, _) => {
            assert_eq!(resp.status_code, StatusCode::OK);
        }
        other => panic!("unexpected transport event: {other:?}"),
    }

    Ok(())
}

/// RFC 3262: a UAS may send a second reliable 183 with a new RSeq and the
/// same SDP. The UAC must PRACK each one; the second is not a retransmission.
#[tokio::test]
async fn client_dialog_pracks_each_reliable_provisional() -> crate::Result<()> {
    use crate::dialog::{dialog_layer::DialogLayer, invitation::InviteOption};
    use crate::sip::prelude::HeadersExt;
    use crate::transport::{udp::UdpConnection, TransportLayer};
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;

    let token = CancellationToken::new();
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
    let endpoint = crate::EndpointBuilder::new()
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { inner.serve().await });
    let layer = DialogLayer::new(endpoint.inner.clone());
    let option = InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com")?,
        callee: crate::sip::Uri::try_from(format!("sip:bob@{}", peer.local_addr()?).as_str())?,
        contact: crate::sip::Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        support_prack: true,
        ..Default::default()
    };
    let (state_sender, _states) = unbounded_channel();
    let invite = tokio::spawn(async move { layer.do_invite(option, state_sender).await });

    async fn recv(peer: &UdpSocket, method: Method) -> (Request, std::net::SocketAddr) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, from) = timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
                .unwrap();
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
                if req.method == method {
                    return (req, from);
                }
            }
        }
    }
    let reply = |req: &Request, status: &str, extra: &str, body: &str| {
        format!(
            "SIP/2.0 {status}\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=bob\r\nCall-ID: {}\r\n\
             CSeq: {}\r\nContact: <sip:bob@{}>\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            req.via_header().unwrap().value(),
            req.from_header().unwrap().value(),
            req.to_header()
                .unwrap()
                .value()
                .split(";tag=")
                .next()
                .unwrap(),
            req.call_id_header().unwrap().value(),
            req.cseq_header().unwrap().value(),
            peer.local_addr().unwrap(),
            body.len(),
        )
    };

    let (inv, uac) = recv(&peer, Method::Invite).await;
    assert!(inv.header_contains_token("Supported", "100rel"));
    let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n";
    for rseq in [1u32, 2] {
        let extra = format!("Require: 100rel\r\nRSeq: {rseq}\r\nContent-Type: application/sdp\r\n");
        let progress = reply(&inv, "183 Session Progress", &extra, sdp);
        peer.send_to(progress.as_bytes(), uac).await?;
        let (prack, from) = recv(&peer, Method::PRack).await;
        assert_eq!(prack.rack_value().map(|(r, _, _)| r), Some(rseq));
        peer.send_to(reply(&prack, "200 OK", "", "").as_bytes(), from)
            .await?;
    }
    invite.abort();
    token.cancel();
    Ok(())
}
