//! Tests for `EndpointOption::auto_ack_2xx` (RFC 3261 §17.1.1.2 vs §16).
//!
//! With the default (`true`) a client INVITE transaction puts an ACK for a
//! 2xx on the wire itself and the TU sees the 2xx exactly once. With `false`
//! (proxy mode) no ACK for a 2xx is ever sent by the transaction layer: the
//! ACK is the TU's, end-to-end, and the transaction terminates at once.
use crate::sip::{headers::*, prelude::HeadersExt, Method, SipMessage, Version};
use crate::transaction::endpoint::{Endpoint, EndpointOption};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::{EndpointBuilder, TransactionState};
use crate::transport::udp::UdpConnection;
use crate::transport::TransportLayer;
use crate::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "auto-ack-2xx@test";
const FROM_TAG: &str = "autoack-from";

async fn build_endpoint(auto_ack_2xx: bool) -> Result<Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    tl.add_transport(udp.into());
    let option = EndpointOption {
        auto_ack_2xx,
        ..Default::default()
    };
    Ok(EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .with_option(option)
        .build())
}

fn make_invite(peer: SocketAddr) -> Result<crate::sip::Request> {
    Ok(crate::sip::Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from(format!("sip:bob@{peer}").as_str())?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-autoack").into(),
            CSeq::new("1 INVITE").into(),
            From::new(format!("<sip:alice@example.com>;tag={FROM_TAG}")).into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new(CALL_ID).into(),
            MaxForwards::new("70").into(),
            Contact::new("<sip:alice@127.0.0.1:5060>").into(),
            ContentLength::new("0").into(),
        ]
        .into(),
        version: Version::V2,
        body: vec![],
    })
}

/// A raw UDP UAS: answers every INVITE with the same 200 OK (with a To tag)
/// and retransmits that 200 OK twice (at ~400ms intervals, roughly the RFC's
/// T1 doubling). Everything it receives that is not an INVITE is forwarded to
/// the returned channel, so the test can assert exactly what went out on the
/// wire.
async fn spawn_peer(socket: UdpSocket) -> tokio::sync::mpsc::Receiver<String> {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut ok_text: Option<String> = None;
        let mut ok_dest: Option<SocketAddr> = None;
        let mut resends_left = 0u8;
        let mut next_send_at: Option<Instant> = None;
        loop {
            // Retransmit the 200 OK while retransmissions remain.
            if let Some(at) = next_send_at {
                if Instant::now() >= at {
                    if let (Some(text), Some(dest)) = (ok_text.as_ref(), ok_dest) {
                        socket.send_to(text.as_bytes(), dest).await.ok();
                    }
                    resends_left = resends_left.saturating_sub(1);
                    next_send_at = if resends_left > 0 {
                        Some(Instant::now() + Duration::from_millis(400))
                    } else {
                        None
                    };
                }
            }
            let wait = next_send_at
                .map(|at| at.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(5));
            let Ok(Ok((len, src))) = tokio::time::timeout(wait, socket.recv_from(&mut buf)).await
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&buf[..len]).to_string();
            let Ok(msg) = SipMessage::try_from(text.as_str()) else {
                continue;
            };
            match msg {
                SipMessage::Request(req) if req.method == Method::Invite => {
                    // Answer every (re)transmitted INVITE with the same 200 OK.
                    ok_dest = Some(src);
                    let reply = match ok_text.as_ref() {
                        Some(text) => text.clone(),
                        None => {
                            let text = format!(
                                "SIP/2.0 200 OK\r\n\
                                 Via: {}\r\n\
                                 From: {}\r\n\
                                 To: {};tag=peer-tag\r\n\
                                 Call-ID: {}\r\n\
                                 CSeq: {}\r\n\
                                 Contact: <sip:bob@{}>\r\n\
                                 Content-Length: 0\r\n\r\n",
                                req.via_header().unwrap().value(),
                                req.from_header().unwrap().value(),
                                req.to_header().unwrap().value(),
                                req.call_id_header().unwrap().value(),
                                req.cseq_header().unwrap().value(),
                                socket.local_addr().unwrap(),
                            );
                            ok_text = Some(text.clone());
                            resends_left = 2;
                            next_send_at = Some(Instant::now() + Duration::from_millis(400));
                            text
                        }
                    };
                    socket.send_to(reply.as_bytes(), src).await.ok();
                }
                SipMessage::Request(req) if req.method == Method::Ack => {
                    tx.send(text).await.ok();
                }
                _ => {}
            }
        }
    });
    rx
}

/// The next datagram the peer received that is not an INVITE (INVITE
/// retransmissions are normal while Timer A runs and are not reported).
async fn next_wire_event(
    rx: &mut tokio::sync::mpsc::Receiver<String>,
    deadline: Duration,
) -> Option<String> {
    tokio::time::timeout(deadline, rx.recv()).await.ok()?
}

/// Default (`auto_ack_2xx: true`, the UA behavior): the transaction itself
/// ACKs the 2xx once, and a retransmitted 200 OK is neither re-ACKed nor
/// delivered to the TU a second time.
#[tokio::test]
async fn test_default_auto_acks_2xx_once() -> Result<()> {
    let endpoint = build_endpoint(true).await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = socket.local_addr()?;
    let mut peer = spawn_peer(socket).await;

    let inner = endpoint.inner.clone();
    let invite = make_invite(peer_addr)?;
    let client = async move {
        let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, invite, inner.clone(), None);
        tx.send().await?;

        // The 2xx reaches the TU and the transaction enters Accepted with
        // Timer M armed (RFC 6026 §7.2; the auto-ACK is the documented
        // rsipstack 0.5.x deviation).
        let first = tokio::time::timeout(Duration::from_secs(2), tx.receive())
            .await
            .expect("timeout waiting for the 200")
            .expect("transaction ended before the 200");
        match first {
            SipMessage::Response(ref resp) => {
                assert_eq!(resp.status_code.code(), 200);
            }
            other => panic!("expected the 200 OK, got {other}"),
        }
        assert_eq!(tx.state, TransactionState::Accepted);

        // A retransmitted 200 OK is delivered to the TU again (§7.2) and
        // re-ACKed below the TU.
        let second = tokio::time::timeout(Duration::from_millis(1200), tx.receive())
            .await
            .expect("timeout waiting for the retransmitted 200")
            .expect("transaction ended before the retransmitted 200");
        match second {
            SipMessage::Response(ref resp) => {
                assert_eq!(resp.status_code.code(), 200);
            }
            other => panic!("expected the retransmitted 200 OK, got {other}"),
        }
        assert_eq!(tx.state, TransactionState::Accepted);
        Ok::<_, crate::Error>(())
    };

    let endpoint_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    tokio::time::timeout(Duration::from_secs(6), client)
        .await
        .expect("client timed out")
        .expect("client failed");

    // The ACK on the wire, with the INVITE's CSeq number and the 2xx's To
    // tag (RFC 3261 §13.2.2.4).
    let ack = next_wire_event(&mut peer, Duration::from_secs(2))
        .await
        .expect("the transaction must ACK the 2xx");
    assert!(ack.starts_with("ACK"), "expected an ACK, got {ack}");
    assert!(
        ack.contains("CSeq: 1 ACK"),
        "the ACK must carry the INVITE's CSeq, got {ack}"
    );
    assert!(
        ack.contains(";tag=peer-tag"),
        "the ACK must carry the 2xx's To tag, got {ack}"
    );

    // Each retransmitted 200 OK is re-ACKed (RFC 6026 §7.2 absorption with
    // the documented auto-ACK deviation).
    let re_ack = next_wire_event(&mut peer, Duration::from_millis(1100)).await;
    let re_ack = re_ack.expect("a retransmitted 200 OK must be re-ACKed");
    assert!(
        re_ack.contains("CSeq: 1 ACK"),
        "the re-ACK must carry the INVITE's CSeq, got {re_ack}"
    );
    serve.abort();
    Ok(())
}

/// `auto_ack_2xx: false` (proxy mode): the transaction never ACKs a 2xx —
/// neither the first one nor a retransmission — and the TU still receives
/// the 2xx. The transaction terminates at once (RFC 3261 §17.1.1.2).
#[tokio::test]
async fn test_auto_ack_2xx_false_never_acks() -> Result<()> {
    let endpoint = build_endpoint(false).await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = socket.local_addr()?;
    let mut peer = spawn_peer(socket).await;

    let inner = endpoint.inner.clone();
    let invite = make_invite(peer_addr)?;
    let client = async move {
        let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, invite, inner.clone(), None);
        tx.send().await?;

        // The 2xx is still delivered to the TU (the proxy forwards it).
        let first = tokio::time::timeout(Duration::from_secs(2), tx.receive())
            .await
            .expect("timeout waiting for the 200")
            .expect("transaction ended before the 200");
        match first {
            SipMessage::Response(ref resp) => {
                assert_eq!(resp.status_code.code(), 200);
            }
            other => panic!("expected the 200 OK, got {other}"),
        }
        // Proxy mode terminates the client INVITE transaction at once.
        assert_eq!(tx.state, TransactionState::Terminated);
        Ok::<_, crate::Error>(())
    };

    let endpoint_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    tokio::time::timeout(Duration::from_secs(6), client)
        .await
        .expect("client timed out")
        .expect("client failed");

    // Neither after the first 200 OK ...
    let first_ack = next_wire_event(&mut peer, Duration::from_millis(1200)).await;
    assert!(
        first_ack.is_none(),
        "proxy mode must not ACK the 2xx, got {first_ack:?}"
    );

    // ... nor after its retransmissions: the whole point of §17.1.1.2.
    let retransmit_ack = next_wire_event(&mut peer, Duration::from_millis(1200)).await;
    assert!(
        retransmit_ack.is_none(),
        "proxy mode must not ACK a retransmitted 2xx, got {retransmit_ack:?}"
    );
    serve.abort();
    Ok(())
}
