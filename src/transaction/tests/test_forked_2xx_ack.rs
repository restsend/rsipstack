//! Forked 2xx handling in the client Accepted state (RFC 6026 §7.2 +
//! RFC 3261 §13.2.2.4 / §12.2.1.1): a 2xx with a new To tag establishes a
//! different dialog, and the ACK generated for it MUST carry that dialog's
//! To tag, remote target (Contact) and route set — retransmissions of the
//! *same* 2xx re-send the *same* ACK.
use crate::sip::{headers::*, prelude::HeadersExt, Method, SipMessage};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::Result;
use std::time::Duration;
use tokio::net::UdpSocket;

fn make_invite(peer: std::net::SocketAddr) -> Result<crate::sip::Request> {
    Ok(crate::sip::Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from(format!("sip:bob@{peer}").as_str())?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-forked").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=forked-from").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("forked-2xx@test").into(),
            MaxForwards::new("70").into(),
            Contact::new("<sip:alice@127.0.0.1:5060>").into(),
            ContentLength::new("0").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    })
}

/// A 200 OK for `invite` with the given To tag and a Contact that identifies
/// the branch (`user@peer` — the R-URI the ACK for it must carry).
fn ok_200(invite: &crate::sip::Request, tag: &str, peer: std::net::SocketAddr) -> String {
    format!(
        "SIP/2.0 200 OK\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {};tag={tag}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <sip:{tag}@{peer};transport=udp>\r\n\
         Content-Length: 0\r\n\r\n",
        invite.via_header().unwrap().value(),
        invite.from_header().unwrap().value(),
        invite.to_header().unwrap().value(),
        invite.call_id_header().unwrap().value(),
        invite.cseq_header().unwrap().value(),
        peer = peer,
    )
}

/// The next datagram starting with `prefix` ("ACK"), within `wait`.
async fn next_ack(socket: &UdpSocket, buf: &mut [u8], wait: Duration) -> String {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("no ACK arrived within {wait:?}");
        }
        let Ok(Ok((len, _))) = tokio::time::timeout(deadline - now, socket.recv_from(buf)).await
        else {
            panic!("no ACK arrived within {wait:?}");
        };
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        if text.starts_with("ACK") {
            return text;
        }
    }
}

/// A forked 2xx (new To tag) must be ACKed with *its* To tag and remote
/// target — not with the cached ACK of the first branch (RFC 3261
/// §13.2.2.4, §12.2.1.1).
#[tokio::test]
async fn test_forked_2xx_is_acked_with_its_own_tag_and_target() -> Result<()> {
    let _token = tokio_util::sync::CancellationToken::new();
    let tl = crate::transport::TransportLayer::new(tokio_util::sync::CancellationToken::new());
    let udp =
        crate::transport::udp::UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None)
            .await?;
    tl.add_transport(udp.into());
    let endpoint = crate::transaction::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    let endpoint_inner = endpoint.inner.clone();
    let serve_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = serve_inner.serve().await;
    });

    let peer_sock = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = peer_sock.local_addr()?;

    let invite = make_invite(peer)?;
    let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
    let client_inner = endpoint_inner.clone();
    let client_invite = invite.clone();
    let client = async move {
        let mut tx =
            Transaction::new_client(key.clone(), client_invite, client_inner.clone(), None);
        tx.send().await?;

        // Branch A's 2xx parks the transaction in Accepted (auto-ACK fired).
        let first = tokio::time::timeout(Duration::from_secs(2), tx.receive())
            .await
            .expect("timeout waiting for the 200")
            .expect("transaction ended before the 200");
        match &first {
            SipMessage::Response(resp) => {
                assert_eq!(resp.status_code.code(), 200);
                assert_eq!(
                    resp.to_header().unwrap().tag().unwrap().unwrap().value(),
                    "tag-a"
                );
            }
            other => panic!("expected the first 200 OK, got {other}"),
        }
        assert_eq!(tx.state, crate::transaction::TransactionState::Accepted);

        // Branch B's forked 2xx is delivered to the TU (§7.2) and re-ACKed.
        let second = tokio::time::timeout(Duration::from_secs(3), tx.receive())
            .await
            .expect("timeout waiting for the forked 200")
            .expect("transaction ended before the forked 200");
        match &second {
            SipMessage::Response(resp) => {
                assert_eq!(resp.status_code.code(), 200);
                assert_eq!(
                    resp.to_header().unwrap().tag().unwrap().unwrap().value(),
                    "tag-b"
                );
            }
            other => panic!("expected the forked 200 OK, got {other}"),
        }
        assert_eq!(tx.state, crate::transaction::TransactionState::Accepted);
        Ok::<(), crate::Error>(())
    };
    let client_task = tokio::spawn(client);

    let mut buf = vec![0u8; 4096];

    // Branch A answers.
    let Ok(Ok((len, src))) =
        tokio::time::timeout(Duration::from_secs(2), peer_sock.recv_from(&mut buf)).await
    else {
        panic!("timeout waiting for the INVITE");
    };
    assert!(buf[..len].starts_with(b"INVITE"));
    peer_sock
        .send_to(ok_200(&invite, "tag-a", peer).as_bytes(), src)
        .await?;

    // The UAC ACKs branch A with A's To tag and A's Contact as R-URI.
    let ack_a = next_ack(&peer_sock, &mut buf, Duration::from_secs(2)).await;
    assert!(
        ack_a.contains(";tag=tag-a"),
        "the ACK for branch A must carry A's To tag, got {ack_a}"
    );
    assert!(
        ack_a.contains("sip:tag-a@"),
        "the ACK for branch A must target A's Contact, got {ack_a}"
    );

    // Branch B forks in with a different To tag.
    peer_sock
        .send_to(ok_200(&invite, "tag-b", peer).as_bytes(), src)
        .await?;

    // The ACK for branch B must carry B's To tag and B's Contact as R-URI
    // (RFC 3261 §13.2.2.4: an ACK per 2xx; §12.2.1.1: built from that
    // dialog's remote target).
    let ack_b = next_ack(&peer_sock, &mut buf, Duration::from_secs(2)).await;
    assert!(
        ack_b.contains(";tag=tag-b"),
        "the ACK for branch B must carry B's To tag, got {ack_b}"
    );
    assert!(
        ack_b.contains("sip:tag-b@"),
        "the ACK for branch B must target B's Contact, got {ack_b}"
    );
    assert!(
        !ack_b.contains(";tag=tag-a"),
        "the ACK for branch B must not carry branch A's tag, got {ack_b}"
    );

    client_task
        .await
        .expect("client task panicked")
        .expect("client failed");

    serve.abort();
    Ok(())
}
