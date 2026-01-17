use super::create_test_endpoint;
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
    TransactionState,
};
use rsip::{headers::*, Response, SipMessage, StatusCode};

#[tokio::test]
async fn test_multiple_provisional_responses() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Create INVITE request
    let invite_req = rsip::Request {
        method: rsip::Method::Invite,
        uri: rsip::Uri::try_from("sip:test.example.com:5060").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP test.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: Default::default(),
    };
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Client)?;

    let mut tx = Transaction::new_client(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        None,
    );

    // 1. Send first 183 Session Progress (no body)
    let resp1 = Response {
        version: rsip::Version::V2,
        status_code: StatusCode::SessionProgress, // 183
        headers: vec![
            Via::new("SIP/2.0/UDP test.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>;tag=asdf").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
        ]
        .into(),
        body: vec![],
    };

    tx.tu_sender
        .send(TransactionEvent::Received(
            SipMessage::Response(resp1.clone()),
            None,
        ))
        .unwrap();

    let received1 = tx.receive().await.expect("Should receive first 183");
    if let SipMessage::Response(r) = received1 {
        assert_eq!(r.status_code, StatusCode::SessionProgress);
    } else {
        panic!("Expected response");
    }
    assert_eq!(tx.state, TransactionState::Proceeding);
    assert!(
        tx.last_ack.is_none(),
        "Should not send ACK for provisional response"
    );

    // 2. Send second 183 Session Progress (with body)
    let resp2 = Response {
        version: rsip::Version::V2,
        status_code: StatusCode::SessionProgress, // 183
        headers: vec![
            Via::new("SIP/2.0/UDP test.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>;tag=asdf").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
        ].into(),
        body: b"v=0\r\no=- 2890844526 2890844526 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n".to_vec(),
    };

    tx.tu_sender
        .send(TransactionEvent::Received(
            SipMessage::Response(resp2.clone()),
            None,
        ))
        .unwrap();

    let received2 = tx
        .receive()
        .await
        .expect("Should receive second 183 with SDP");
    if let SipMessage::Response(r) = received2 {
        assert_eq!(r.status_code, StatusCode::SessionProgress);
        assert_eq!(r.body, resp2.body);
    } else {
        panic!("Expected response");
    }
    assert_eq!(tx.state, TransactionState::Proceeding);
    assert!(
        tx.last_ack.is_none(),
        "Should not send ACK for provisional response"
    );

    // 3. Send exact retransmission of second 183 (should be ignored)
    tx.tu_sender
        .send(TransactionEvent::Received(
            SipMessage::Response(resp2.clone()),
            None,
        ))
        .unwrap();

    // We need a way to check that it's ignored without blocking forever.
    // Since receive() is async and waits for next event, we can use a timeout or check if there are events.
    // Actually, we can just push a different response and see if we get it IMMEDIATELY (meaning the previous one was indeed ignored or processed).
    // Better: use tokio::time::timeout

    let result = tokio::time::timeout(std::time::Duration::from_millis(100), tx.receive()).await;
    assert!(result.is_err(), "Should have timed out (response ignored)");

    Ok(())
}
