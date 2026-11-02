//! RFC 3261 §17.1.2.2: Timer E backs off to T2 and survives provisional replies.
//! Drive the endpoint's scheduled timer events explicitly, avoiding wall-clock
//! timing assertions while still checking the retransmitted UDP packets.
use crate::{
    sip::{Method, Request, SipMessage, StatusCode},
    transaction::{
        key::{TransactionKey, TransactionRole},
        transaction::{Transaction, TransactionEvent},
        EndpointBuilder, TransactionState, TransactionTimer,
    },
    transport::{channel::ChannelConnection, udp::UdpConnection, SipAddr, SipConnection},
};
use std::time::Duration;
use tokio::{net::UdpSocket, sync::mpsc::unbounded_channel, time::timeout};

fn request(method: Method) -> Request {
    Request::try_from(
        format!(
            "{method} sip:peer@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-timer-e\r\n\
         From: <sip:alice@localhost>;tag=alice\r\n\
         To: <sip:bob@localhost>\r\n\
         Call-ID: timer-e@localhost\r\n\
         CSeq: 1 {method}\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n"
        )
        .as_str(),
    )
    .unwrap()
}

fn transaction(method: Method, connection: SipConnection) -> Transaction {
    let endpoint = EndpointBuilder::new().build();
    let request = request(method);
    let key = TransactionKey::from_request(&request, TransactionRole::Client).unwrap();
    Transaction::new_client(key, request, endpoint.inner, Some(connection))
}

async fn udp_transaction(method: Method) -> (Transaction, UdpSocket, Vec<u8>) {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let connection = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .unwrap();
    let mut tx = transaction(method, connection.into());
    tx.destination = Some(SipAddr::from(peer.local_addr().unwrap()));
    tx.send().await.unwrap();
    let first = packet(&peer).await;
    (tx, peer, first)
}

async fn packet(peer: &UdpSocket) -> Vec<u8> {
    let mut buffer = [0; 4096];
    let (length, _) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .expect("missing retransmitted request")
        .unwrap();
    buffer[..length].to_vec()
}

async fn fire_retry(tx: &mut Transaction, expected_ms: u64) {
    let id = tx.timer_a.take().expect("request retry must stay armed");
    let timer = tx
        .endpoint_inner
        .timers
        .cancel(id)
        .expect("scheduled retry");
    match &timer {
        TransactionTimer::TimerA(key, duration) => {
            assert_eq!(key, &tx.key);
            assert_eq!(*duration, Duration::from_millis(expected_ms));
        }
        other => panic!("unexpected retry timer: {other}"),
    }
    tx.tu_sender.send(TransactionEvent::Timer(timer)).unwrap();
    // End this receive() turn after the timer is handled. The event does not
    // transition or drop the transaction; subsequent events can still be driven.
    tx.tu_sender
        .send(TransactionEvent::Terminate(tx.key.clone()))
        .unwrap();
    assert!(tx.receive().await.is_none());
}

async fn response(tx: &mut Transaction, status: StatusCode) {
    let response = tx
        .endpoint_inner
        .make_response(&tx.original, status.clone(), None);
    tx.tu_sender
        .send(TransactionEvent::Received(response.into(), None))
        .unwrap();
    match tx.receive().await {
        Some(SipMessage::Response(response)) => assert_eq!(response.status_code, status),
        other => panic!("expected response, got {other:?}"),
    }
}

#[tokio::test]
async fn non_invite_retries_cap_at_t2_and_stop_on_final_response() {
    for method in [Method::Options, Method::Register, Method::Bye] {
        let (mut tx, peer, first) = udp_transaction(method).await;
        let deadline = tx.timer_b;
        // The old implementation schedules 8s after the first 4s retry.
        for interval in [500, 1000, 2000, 4000, 4000, 4000] {
            fire_retry(&mut tx, interval).await;
            assert_eq!(packet(&peer).await, first, "same request/CSeq/branch");
            assert_eq!(tx.timer_b, deadline, "Timer F must not be extended");
        }
        response(&mut tx, StatusCode::OK).await;
        assert!(tx.timer_a.is_none());
        assert!(tx.timer_b.is_none());
    }
}

#[tokio::test]
async fn options_retries_continue_at_t2_after_any_provisional_response() {
    for provisional in [
        StatusCode::Trying,
        StatusCode::Ringing,
        StatusCode::SessionProgress,
    ] {
        let (mut tx, peer, first) = udp_transaction(Method::Options).await;
        let retry = tx.timer_a;
        let deadline = tx.timer_b;
        response(&mut tx, provisional).await;
        assert_eq!(tx.state, TransactionState::Proceeding);
        assert_eq!(tx.timer_a, retry, "keep the pending Timer E expiration");
        assert_eq!(tx.timer_b, deadline, "keep the original Timer F deadline");
        // An outstanding E fires at its existing deadline; subsequent E
        // intervals in Proceeding must be T2 (not another doubled interval).
        for interval in [500, 4000, 4000] {
            fire_retry(&mut tx, interval).await;
            assert_eq!(packet(&peer).await, first);
            assert_eq!(tx.timer_b, deadline);
        }
        // Model a lost final response: the UAS returns it on a retransmission.
        response(&mut tx, StatusCode::OK).await;
        assert!(tx.timer_a.is_none());
        assert!(tx.timer_b.is_none());
    }
}

#[tokio::test]
async fn further_provisional_responses_do_not_postpone_non_invite_timers() {
    let (mut tx, peer, first) = udp_transaction(Method::Options).await;
    response(&mut tx, StatusCode::Trying).await;
    fire_retry(&mut tx, 500).await;
    assert_eq!(packet(&peer).await, first);
    let retry = tx.timer_a;
    let deadline = tx.timer_b;
    for status in [
        StatusCode::SessionProgress,
        StatusCode::Ringing,
        StatusCode::Trying,
    ] {
        response(&mut tx, status).await;
        assert_eq!(tx.state, TransactionState::Proceeding);
        assert_eq!(tx.timer_a, retry);
        assert_eq!(tx.timer_b, deadline);
    }
    fire_retry(&mut tx, 4000).await;
    assert_eq!(packet(&peer).await, first);
}

#[tokio::test]
async fn non_invite_timeout_survives_provisional_responses_and_stops_retries() {
    for provisional in [
        None,
        Some(StatusCode::Trying),
        Some(StatusCode::SessionProgress),
    ] {
        let (mut tx, _peer, _first) = udp_transaction(Method::Options).await;
        let deadline = tx.timer_b;
        if let Some(status) = provisional {
            response(&mut tx, status).await;
        }
        assert_eq!(tx.timer_b, deadline);
        let timer = tx.endpoint_inner.timers.cancel(deadline.unwrap()).unwrap();
        assert!(matches!(timer, TransactionTimer::TimerB(_)));
        tx.tu_sender.send(TransactionEvent::Timer(timer)).unwrap();
        match tx.receive().await {
            Some(SipMessage::Response(response)) => {
                assert_eq!(response.status_code, StatusCode::RequestTimeout);
            }
            other => panic!("expected timeout response, got {other:?}"),
        }
        assert!(tx.timer_a.is_none());
        assert!(tx.timer_b.is_none());
    }
}

#[tokio::test]
async fn invite_backoff_and_stopping_on_provisional_response_are_unchanged() {
    let (mut tx, peer, first) = udp_transaction(Method::Invite).await;
    for interval in [500, 1000, 2000, 4000, 8000, 16000] {
        fire_retry(&mut tx, interval).await;
        assert_eq!(packet(&peer).await, first);
    }
    response(&mut tx, StatusCode::Trying).await;
    assert_eq!(tx.state, TransactionState::Trying);
    assert!(tx.timer_a.is_none());
    assert!(tx.timer_b.is_none());
    let timer_c = tx.timer_c.expect("INVITE Timer C must remain active");
    response(&mut tx, StatusCode::Ringing).await;
    assert_eq!(tx.timer_c, Some(timer_c));
    assert!(tx.timer_a.is_none());
}

#[tokio::test]
async fn reliable_non_invite_transport_never_arms_retransmissions() {
    // ChannelConnection is treated as reliable by SipConnection, like TCP/TLS.
    let (_incoming_tx, incoming) = unbounded_channel();
    let (outgoing, mut sent) = unbounded_channel();
    let connection = ChannelConnection::create_connection(
        incoming,
        outgoing,
        SipAddr::from("127.0.0.1:5060".parse::<std::net::SocketAddr>().unwrap()),
        None,
    )
    .await
    .unwrap();
    let mut tx = transaction(Method::Options, connection.into());
    tx.send().await.unwrap();
    assert!(sent.try_recv().is_ok());
    assert!(tx.timer_a.is_none());
    let deadline = tx.timer_b;
    for status in [StatusCode::Trying, StatusCode::SessionProgress] {
        response(&mut tx, status).await;
        assert!(tx.timer_a.is_none());
        assert_eq!(tx.timer_b, deadline);
    }
    response(&mut tx, StatusCode::OK).await;
    assert!(tx.timer_a.is_none());
    assert!(tx.timer_b.is_none());
    assert!(sent.try_recv().is_err());
}
