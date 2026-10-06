//! Tests for ACK matching on a server INVITE transaction (RFC 3261 §17.1.1.3,
//! §13.2.2.4): an ACK acknowledges only the INVITE with the same CSeq number.
//!
//! ACKs for 2xx are routed by dialog and CSeq (`waiting_ack_cseq`). A delayed
//! ACK of an earlier (re-)INVITE on the same dialog must not confirm the
//! transaction of the current re-INVITE or stop its 2xx retransmissions
//! (Timer G).

use crate::sip::headers::*;
use crate::sip::prelude::HeadersExt;
use crate::sip::{Method, SipMessage, StatusCode, Version};
use crate::transaction::TransactionState;
use crate::transport::udp::UdpConnection;
use crate::transport::{SipConnection, TransportLayer};
use crate::EndpointBuilder;
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

fn make_reinvite(transport: &str, cseq: u32) -> crate::sip::Request {
    crate::sip::Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@127.0.0.1").unwrap(),
        headers: vec![
            Via::new(format!(
                "SIP/2.0/{} 127.0.0.1:5060;branch=z9hG4bK-reinvite-{}",
                transport, cseq
            ))
            .into(),
            CSeq::new(format!("{} INVITE", cseq)).into(),
            From::new("Alice <sip:alice@example.com>;tag=aliceTagAck").into(),
            To::new("Bob <sip:bob@example.com>;tag=bobTagAck").into(),
            CallId::new("ack-cseq-test@example.com").into(),
            MaxForwards::new("70").into(),
            ContentLength::new("0").into(),
        ]
        .into(),
        version: Version::V2,
        body: Default::default(),
    }
}

/// A 2xx ACK on the dialog of `invite`: new branch, CSeq number `cseq`.
fn make_2xx_ack(invite: &crate::sip::Request, cseq: u32) -> crate::sip::Request {
    let mut headers = invite.headers.clone();
    for header in headers.iter_mut() {
        match header {
            crate::sip::Header::Via(via) => {
                let sent_by = via.value().split(';').next().unwrap().to_string();
                *via = Via::new(format!("{};branch=z9hG4bK-ack-{}", sent_by, cseq));
            }
            crate::sip::Header::CSeq(c) => {
                *c = CSeq::new(format!("{} ACK", cseq));
            }
            _ => {}
        }
    }
    crate::sip::Request {
        method: Method::Ack,
        uri: invite.uri.clone(),
        headers,
        version: invite.version,
        body: Default::default(),
    }
}

/// A delayed ACK of a previous re-INVITE (CSeq 1) must not confirm the
/// transaction of the current re-INVITE (CSeq 2): the 2xx keeps being
/// retransmitted (Timer G), and the ACK with the matching CSeq still
/// confirms the transaction.
#[tokio::test]
async fn test_server_invite_ignores_ack_with_other_cseq() {
    let token = CancellationToken::new();

    let server_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .expect("create server connection");
    let server_conn_sip: SipConnection = server_conn.into();
    let server_addr = server_conn_sip.get_addr().clone();

    let tl = TransportLayer::new(token.child_token());
    tl.add_transport(server_conn_sip);

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();

    let client_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .expect("create client connection");
    let client_conn_sip: SipConnection = client_conn.clone().into();

    let endpoint_inner = endpoint.inner.clone();
    let serve_handle = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    // Re-INVITE with CSeq 2 on an established dialog.
    let invite = make_reinvite("UDP", 2);
    client_conn_sip
        .send(invite.clone().into(), Some(&server_addr))
        .await
        .expect("send re-INVITE");

    let mut incoming = endpoint.incoming_transactions().expect("incoming");
    let mut tx = timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("timeout waiting for incoming transaction")
        .expect("no incoming transaction");
    assert_eq!(tx.original.method, Method::Invite);

    tx.reply(StatusCode::OK).await.expect("reply 200");
    assert_eq!(tx.state, TransactionState::Accepted);
    assert!(tx.timer_g.is_some(), "Timer G must run for 2xx over UDP");

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(2), client_conn.recv_raw(&mut buf))
        .await
        .expect("timeout waiting for 200")
        .expect("recv failed");
    assert!(String::from_utf8_lossy(&buf[..len]).starts_with("SIP/2.0 200"));

    // Delayed ACK of the previous re-INVITE (CSeq 1) on the same dialog.
    client_conn_sip
        .send(make_2xx_ack(&invite, 1).into(), Some(&server_addr))
        .await
        .expect("send stale ACK");

    // Drive the transaction past the first Timer G expiry (T1 = 500ms).
    let received = timeout(Duration::from_millis(1200), tx.receive()).await;
    assert!(
        received.is_err(),
        "an ACK with CSeq 1 must not be delivered by the CSeq 2 INVITE transaction, got {:?}",
        received.ok().flatten().map(|m| m.to_string())
    );
    assert_eq!(
        tx.state,
        TransactionState::Accepted,
        "an ACK with CSeq 1 must not confirm the CSeq 2 INVITE transaction"
    );
    assert!(tx.timer_g.is_some(), "Timer G must keep running");
    assert_eq!(
        endpoint.inner.waiting_ack.len(),
        1,
        "the dialog must still route ACKs to the CSeq 2 transaction"
    );
    assert_eq!(endpoint.inner.waiting_ack_cseq.len(), 1);

    // The 2xx was retransmitted by Timer G.
    let (len, _) = timeout(Duration::from_secs(1), client_conn.recv_raw(&mut buf))
        .await
        .expect("timeout waiting for 200 retransmission")
        .expect("recv failed");
    assert!(String::from_utf8_lossy(&buf[..len]).starts_with("SIP/2.0 200"));

    // The ACK with the matching CSeq confirms the transaction.
    client_conn_sip
        .send(make_2xx_ack(&invite, 2).into(), Some(&server_addr))
        .await
        .expect("send ACK");

    let msg = timeout(Duration::from_secs(2), tx.receive())
        .await
        .expect("timeout waiting for ACK")
        .expect("transaction ended before ACK");
    match msg {
        SipMessage::Request(req) => {
            assert_eq!(req.method, Method::Ack);
            assert_eq!(req.cseq_header().unwrap().seq().unwrap(), 2);
        }
        other => panic!("expected ACK, got {}", other),
    }
    // A matching ACK ends the Accepted transaction: retransmissions stop,
    // the waiting_ack entry is removed, and late retransmitted ACKs /
    // INVITE retransmissions are absorbed via finished_transactions.
    assert_eq!(tx.state, TransactionState::Terminated);
    assert!(tx.timer_g.is_none(), "Timer G must stop once ACKed");
    assert_eq!(endpoint.inner.waiting_ack.len(), 0);
    assert_eq!(endpoint.inner.waiting_ack_cseq.len(), 0);

    token.cancel();
    serve_handle.abort();
}

/// The same over TCP: a delayed ACK must neither confirm the transaction nor
/// reach the TU, and the dialog must keep routing ACKs to the current INVITE.
#[tokio::test]
async fn test_server_invite_ignores_ack_with_other_cseq_over_tcp() {
    use crate::transport::tcp_listener::TcpListenerConnection;
    use tokio::io::AsyncWriteExt;
    let token = CancellationToken::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let tl = TransportLayer::new(token.child_token());
    tl.add_transport(
        TcpListenerConnection::new(server_addr, None)
            .await
            .unwrap()
            .into(),
    );
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    endpoint
        .inner
        .transport_layer
        .serve_listens()
        .await
        .unwrap();
    let endpoint_inner = endpoint.inner.clone();
    let serve_handle = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let mut incoming = endpoint.incoming_transactions().expect("incoming");
    let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();

    let invite = make_reinvite("TCP", 2);
    stream
        .write_all(invite.to_string().as_bytes())
        .await
        .unwrap();
    let mut tx = timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("timeout waiting for incoming transaction")
        .expect("no incoming transaction");
    tx.reply(StatusCode::OK).await.expect("reply 200");
    assert_eq!(tx.state, TransactionState::Accepted);

    // Delayed ACK of CSeq 1, then the ACK of CSeq 2, on the ordered stream:
    // the first ACK the transaction delivers must be the CSeq 2 one.
    let acks = make_2xx_ack(&invite, 1).to_string() + &make_2xx_ack(&invite, 2).to_string();
    stream.write_all(acks.as_bytes()).await.unwrap();
    let msg = timeout(Duration::from_secs(2), tx.receive())
        .await
        .expect("timeout waiting for ACK")
        .expect("transaction ended before ACK");
    match msg {
        SipMessage::Request(req) => {
            assert_eq!(req.method, Method::Ack);
            assert_eq!(req.cseq_header().unwrap().seq().unwrap(), 2);
        }
        other => panic!("expected ACK, got {}", other),
    }
    // A matching ACK ends the Accepted transaction (see the UDP variant).
    assert_eq!(tx.state, TransactionState::Terminated);
    assert_eq!(endpoint.inner.waiting_ack.len(), 0);
    assert_eq!(endpoint.inner.waiting_ack_cseq.len(), 0);

    token.cancel();
    serve_handle.abort();
}
