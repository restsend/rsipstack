//! Issue #129 regression guard (RFC 7118 §5): with a UAC on a
//! connection-oriented transport, the ACK for a 200 OK must reuse the flow
//! the 2xx arrived on — never dial a new connection towards the
//! Record-Route / Contact target, which is frequently an address the client
//! cannot reach (record-routing edge proxies advertise their own address).
//! A connect attempt there stalls the transaction for the OS connect
//! timeout; the ACK must go out at once on the existing flow, also when the
//! UAS retransmits the 200 OK.
use crate::sip::{headers::*, prelude::HeadersExt, Method, SipMessage, StatusCode, Version};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::EndpointBuilder;
use crate::transport::udp::UdpConnection;
use crate::transport::TransportLayer;
use crate::Result;
use std::convert::TryFrom;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Read one SIP message (no body) from a raw stream.
async fn read_message(stream: &mut TcpStream) -> crate::sip::SipMessage {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.expect("read message");
        assert!(n > 0, "peer closed before a full message");
        buf.extend_from_slice(&chunk[..n]);
    }
    let raw = String::from_utf8_lossy(&buf).to_string();
    SipMessage::try_from(raw.as_str()).expect("parse message")
}

fn make_invite(peer: std::net::SocketAddr) -> Result<crate::sip::Request> {
    Ok(crate::sip::Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from(format!("sip:bob@{peer};transport=tcp").as_str())?,
        headers: vec![
            Via::new("SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-flowreuse").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=flowreuse").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("flow-reuse@test").into(),
            MaxForwards::new("70").into(),
            Contact::new("<sip:alice@127.0.0.1:5060;transport=tcp>").into(),
            ContentLength::new("0").into(),
        ]
        .into(),
        version: Version::V2,
        body: vec![],
    })
}

/// The 200 OK the raw UAS answers with: its Contact and Record-Route point
/// at an address that cannot be reached (`203.0.113.1`, TEST-NET-3), as an
/// edge proxy would advertise.
fn ok_200(invite: &crate::sip::Request) -> String {
    format!(
        "SIP/2.0 200 OK\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {};tag=peer-tag\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Record-Route: <sip:203.0.113.1:5060;transport=tcp;lr>\r\n\
         Contact: <sip:bob@203.0.113.1:5060;transport=tcp>\r\n\
         Content-Length: 0\r\n\r\n",
        invite.via_header().unwrap().value(),
        invite.from_header().unwrap().value(),
        invite.to_header().unwrap().value(),
        invite.call_id_header().unwrap().value(),
        invite.cseq_header().unwrap().value(),
    )
}

fn is_ack(msg: &crate::sip::SipMessage) -> Option<String> {
    match msg {
        SipMessage::Request(req) if req.method == Method::Ack => Some(req.to_string()),
        _ => None,
    }
}

/// A UAC over TCP whose 200 OK carries an unreachable Contact/Record-Route:
/// the auto-ACK (and the re-ACK of a retransmitted 200 OK) must go out on
/// the existing flow, and the UAC must not open any further connection.
#[tokio::test]
async fn test_2xx_ack_reuses_the_inbound_flow_with_unreachable_target() -> Result<()> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer = listener.local_addr()?;

    // The raw UAS: answer the first flow, retransmit the 200 OK, and record
    // every ACK it sees. It never accepts a second connection.
    let peer_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept the UAC flow");
        let invite = match read_message(&mut stream).await {
            crate::sip::SipMessage::Request(req) if req.method == Method::Invite => req,
            other => panic!("expected the INVITE, got {other}"),
        };
        let ok = ok_200(&invite);
        stream.write_all(ok.as_bytes()).await.expect("send 200");

        let mut acks: Vec<String> = Vec::new();
        // Wait for the auto-ACK ...
        acks.push(is_ack(&read_message(&mut stream).await).expect("expected the auto-ACK"));
        // ... retransmit the same 200 OK and expect the re-ACK on this flow.
        stream
            .write_all(ok.as_bytes())
            .await
            .expect("retransmit 200");
        acks.push(is_ack(&read_message(&mut stream).await).expect("expected the re-ACK"));

        // Anything after that must stay on this flow, too.
        let mut extra = tokio::time::timeout(Duration::from_millis(700), async {
            loop {
                let _ = read_message(&mut stream).await;
            }
        })
        .await;
        let _ = &mut extra;
        acks
    });

    let inner = endpoint.inner.clone();
    let endpoint_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let client = async move {
        let invite = make_invite(peer)?;
        let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, invite, inner.clone(), None);
        tx.send().await?;

        let started = std::time::Instant::now();
        let first = tokio::time::timeout(Duration::from_secs(2), tx.receive())
            .await
            .expect("timeout waiting for the 200")
            .expect("transaction ended before the 200");
        match first {
            SipMessage::Response(ref resp) => {
                assert_eq!(resp.status_code, StatusCode::OK);
            }
            other => panic!("expected the 200 OK, got {other}"),
        }
        // The ACK must have gone out at once on the existing flow: if the
        // transaction had tried to reach the unreachable Contact instead, the
        // connect would stall well past this bound.
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "the 200 OK must surface to the TU without a connect stall, took {:?}",
            started.elapsed()
        );
        Ok::<_, crate::Error>(())
    };

    tokio::time::timeout(Duration::from_secs(8), client)
        .await
        .expect("client timed out")
        .expect("client failed");

    let acks = tokio::time::timeout(Duration::from_secs(5), peer_task)
        .await
        .expect("peer task timed out")
        .expect("peer task panicked");

    assert_eq!(acks.len(), 2, "expected the auto-ACK and the re-ACK");
    for ack in &acks {
        assert!(ack.starts_with("ACK"), "expected an ACK, got {ack}");
        assert!(
            ack.contains("CSeq: 1 ACK"),
            "the ACK must carry the INVITE's CSeq, got {ack}"
        );
    }
    // The re-ACK of the retransmitted 200 OK must carry the retransmission's
    // To tag and still have gone out on this same flow (it did: the peer saw
    // it without opening any other connection).
    assert!(
        acks[1].contains(";tag=peer-tag"),
        "the re-ACK must carry the 2xx's To tag, got {}",
        acks[1]
    );

    serve.abort();
    token.cancel();
    Ok(())
}
