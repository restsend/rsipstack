//! RFC 3261 §§7.3.1, 18.3 and 25.1: message boundaries and Content-Length.
use crate::sip::{HeadersExt, Request, Response, SipMessage, StatusCode};
use crate::transport::{
    stream::{SipCodec, SipCodecType},
    udp::UdpConnection,
    TransportEvent,
};
use bytes::BytesMut;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{timeout, Duration};
use tokio_util::codec::Decoder;

fn wire(start: &str, via: &str, length: &str, body: &[u8]) -> Vec<u8> {
    let method = if start.starts_with("SIP/") {
        "INVITE"
    } else {
        start.split_whitespace().next().unwrap()
    };
    let mut bytes = format!("{start}\r\nVia: SIP/2.0/UDP {via};branch=z9hG4bK-framing\r\nFrom: <sip:a@example.com>;tag=a\r\nTo: <sip:b@example.com>\r\nCall-ID: framing\r\nCSeq: 1 {method}\r\nContent-Type: application/sdp\r\n{length}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn packet(response: bool, length: &str, body: &[u8]) -> Vec<u8> {
    wire(
        if response {
            "SIP/2.0 200 OK"
        } else {
            "INVITE sip:b@example.com SIP/2.0"
        },
        "127.0.0.1:5060",
        length,
        body,
    )
}
fn body(message: SipMessage) -> Vec<u8> {
    match message {
        SipMessage::Request(r) => r.body,
        SipMessage::Response(r) => r.body,
    }
}
#[test]
fn datagram_without_length_preserves_all_octets() {
    for response in [false, true] {
        let bytes = packet(response, "", b"v=0\r\n\xff\0");
        assert_eq!(
            body(SipMessage::try_from(bytes.as_slice()).unwrap()),
            b"v=0\r\n\xff\0"
        );
    }
}
#[test]
fn request_and_response_conversions_preserve_missing_length_body() {
    assert_eq!(
        Request::try_from(packet(false, "", b"abc")).unwrap().body,
        b"abc"
    );
    assert_eq!(
        Response::try_from(packet(true, "", b"abc")).unwrap().body,
        b"abc"
    );
}
#[test]
fn truncated_datagram_is_rejected() {
    for response in [false, true] {
        for bytes in [b"".as_slice(), b"ab"] {
            assert!(
                SipMessage::try_from(packet(response, "Content-Length: 3\r\n", bytes)).is_err()
            );
        }
    }
}
#[test]
fn invalid_lengths_are_rejected() {
    for response in [false, true] {
        for value in [
            "",
            "xyz",
            "-1",
            "+3",
            "3 0",
            "3,3",
            "9999999999999999999999999999999999999",
        ] {
            assert!(
                SipMessage::try_from(packet(
                    response,
                    &format!("Content-Length: {value}\r\n"),
                    b"abc"
                ))
                .is_err(),
                "accepted {value:?}"
            );
        }
    }
}
#[test]
fn duplicate_lengths_are_rejected_including_compact_alias() {
    for length in [
        "Content-Length: 3\r\nContent-Length: 3\r\n",
        "Content-Length: 3\r\nl: 2\r\n",
        "l: 0\r\nL: 0\r\n",
    ] {
        assert!(SipMessage::try_from(packet(false, length, b"abc")).is_err());
    }
}
#[test]
fn explicit_length_discards_only_trailing_octets() {
    for response in [false, true] {
        for (length, expected) in [
            ("Content-Length: 0\r\n", b"".as_slice()),
            ("Content-Length: 2\r\n", b"\xff\0"),
            ("l: 003\r\n", b"\xff\0a"),
            ("cOnTeNt-LeNgTh \t: \r\n\t3\r\n", b"\xff\0a"),
        ] {
            assert_eq!(
                body(SipMessage::try_from(packet(response, length, b"\xff\0abc")).unwrap()),
                expected
            );
        }
    }
}
#[test]
fn stream_requires_valid_single_length() {
    for length in [
        "",
        "Content-Length: -1\r\n",
        "Content-Length: +3\r\n",
        "Content-Length: 3\r\nl: 3\r\n",
    ] {
        let mut bytes = BytesMut::from(packet(false, length, b"abc").as_slice());
        assert!(SipCodec::new().decode(&mut bytes).is_err());
    }
}
#[test]
fn stream_waits_for_body_and_preserves_next_message() {
    let mut codec = SipCodec::new();
    let mut bytes =
        BytesMut::from(packet(false, "Content-Length \t: \r\n\t3\r\n", b"a").as_slice());
    assert!(codec.decode(&mut bytes).unwrap().is_none());
    bytes.extend_from_slice(b"bc");
    let next = packet(true, "l: 0\r\n", b"");
    bytes.extend_from_slice(&next);
    let Some(SipCodecType::Message(message)) = codec.decode(&mut bytes).unwrap() else {
        panic!("missing message")
    };
    assert_eq!(body(message), b"abc");
    assert_eq!(bytes.as_ref(), next);
    assert!(codec.decode(&mut bytes).unwrap().is_some());
    assert!(bytes.is_empty());
}
#[test]
fn stream_rejects_length_overflow_without_panicking() {
    let mut bytes = BytesMut::from(
        packet(false, &format!("Content-Length: {}\r\n", usize::MAX), b"").as_slice(),
    );
    assert!(SipCodec::new().decode(&mut bytes).is_err());
}

async fn malformed_udp(start: &str, length: &str, expect_response: bool, rport: bool) {
    let server = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (sender, mut incoming) = unbounded_channel();
    let server_addr = server.get_addr().get_socketaddr().unwrap();
    let via = format!(
        "{}{}",
        peer.local_addr().unwrap(),
        if rport { ";rport" } else { "" }
    );
    let invalid = wire(start, &via, length, b"ab");
    let check = async {
        peer.send_to(&invalid, server_addr).await.unwrap();
        peer.send_to(&packet(false, "", b"barrier"), server_addr)
            .await
            .unwrap();
        let Some(TransportEvent::Incoming(message, _, _)) = incoming.recv().await else {
            panic!("no incoming message")
        };
        assert_eq!(
            body(message),
            b"barrier",
            "malformed packet reached application"
        );
        let mut buf = [0; 4096];
        if expect_response {
            let (n, _) = peer.recv_from(&mut buf).await.unwrap();
            let response = Response::try_from(&buf[..n]).unwrap();
            assert_eq!(response.status_code, StatusCode::BadRequest);
            assert_eq!(response.cseq_header().unwrap().value(), "1 INVITE");
            assert!(response.body.is_empty());
            let tag = response.to_header().unwrap().tag().unwrap().unwrap();
            assert_eq!(
                response.via_header().unwrap().value().contains("rport="),
                rport
            );
            peer.send_to(&invalid, server_addr).await.unwrap();
            let (n, _) = peer.recv_from(&mut buf).await.unwrap();
            assert_eq!(
                Response::try_from(&buf[..n])
                    .unwrap()
                    .to_header()
                    .unwrap()
                    .tag()
                    .unwrap(),
                Some(tag)
            );
        } else {
            assert!(timeout(Duration::from_millis(30), peer.recv_from(&mut buf))
                .await
                .is_err());
        }
    };
    timeout(Duration::from_secs(2), async {
        tokio::select! { _ = server.serve_loop(sender) => panic!("server stopped"), _ = check => {} }
    }).await.unwrap();
}
#[tokio::test]
async fn udp_truncated_request_gets_400() {
    for rport in [false, true] {
        malformed_udp(
            "INVITE sip:b@example.com SIP/2.0",
            "Content-Length: 3\r\n",
            true,
            rport,
        )
        .await;
    }
}
#[tokio::test]
async fn udp_invalid_length_gets_400() {
    malformed_udp(
        "INVITE sip:b@example.com SIP/2.0",
        "Content-Length: xyz\r\n",
        true,
        true,
    )
    .await;
}
#[tokio::test]
async fn udp_truncated_response_is_silently_discarded() {
    malformed_udp("SIP/2.0 200 OK", "Content-Length: 3\r\n", false, true).await;
}
#[tokio::test]
async fn udp_malformed_ack_never_gets_response() {
    malformed_udp(
        "ACK sip:b@example.com SIP/2.0",
        "Content-Length: 3\r\n",
        false,
        true,
    )
    .await;
}

#[tokio::test]
async fn udp_malformed_cancel_never_gets_stateless_response() {
    malformed_udp(
        "CANCEL sip:b@example.com SIP/2.0",
        "Content-Length: 3\r\n",
        false,
        true,
    )
    .await;
}
