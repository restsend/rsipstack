use crate::sip::{prelude::HeadersExt, SipMessage};
use crate::transport::{
    connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
    stream::{SipCodec, MAX_SIP_MESSAGE_SIZE},
};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

/// Test SipCodec decoding of single message
#[test]
fn test_sip_codec_single_message() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    buffer.extend_from_slice(test_message.as_bytes());

    let result = codec.decode(&mut buffer).expect("decode should succeed");
    assert!(result.is_some(), "Should decode a message");

    let msg = result.unwrap();
    match msg {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.method, crate::sip::Method::Register);
        }
        _ => panic!("Expected request message"),
    }

    // Buffer should be empty after consuming the message
    assert_eq!(
        buffer.len(),
        0,
        "Buffer should be empty after consuming message"
    );
}

/// Test SipCodec handling of TCP packet fragmentation
#[test]
fn test_sip_codec_fragmented_message() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    // Send message in fragments
    let fragment1 = &test_message[..50];
    let fragment2 = &test_message[50..100];
    let fragment3 = &test_message[100..];

    // First fragment
    buffer.extend_from_slice(fragment1.as_bytes());
    let result = codec.decode(&mut buffer).expect("decode should not fail");
    assert!(result.is_none(), "Should not decode incomplete message");

    // Second fragment
    buffer.extend_from_slice(fragment2.as_bytes());
    let result = codec.decode(&mut buffer).expect("decode should not fail");
    assert!(result.is_none(), "Should not decode incomplete message");

    // Third fragment completes the message
    buffer.extend_from_slice(fragment3.as_bytes());
    let result = codec.decode(&mut buffer).expect("decode should succeed");
    assert!(result.is_some(), "Should decode complete message");

    let msg = result.unwrap();
    match msg {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.method, crate::sip::Method::Register);
        }
        _ => panic!("Expected request message"),
    }
}

/// Test SipCodec handling of multiple messages in one buffer (TCP packet coalescing)
#[test]
fn test_sip_codec_multiple_messages() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let message1 = "REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test1\r\n\
                    From: <sip:alice@example.com>;tag=test1\r\n\
                    To: <sip:alice@example.com>\r\n\
                    Call-ID: test-call-id-1\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Contact: <sip:alice@127.0.0.1:5060>\r\n\
                    Max-Forwards: 70\r\n\
                    Content-Length: 0\r\n\r\n";

    let message2 = "REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test2\r\n\
                    From: <sip:bob@example.com>;tag=test2\r\n\
                    To: <sip:bob@example.com>\r\n\
                    Call-ID: test-call-id-2\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Contact: <sip:bob@127.0.0.1:5060>\r\n\
                    Max-Forwards: 70\r\n\
                    Content-Length: 0\r\n\r\n";

    // Add both messages to buffer
    buffer.extend_from_slice(message1.as_bytes());
    buffer.extend_from_slice(message2.as_bytes());

    // First decode
    let result1 = codec
        .decode(&mut buffer)
        .expect("first decode should succeed");
    assert!(result1.is_some(), "Should decode first message");

    let msg1 = result1.unwrap();
    match msg1 {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.call_id_header().unwrap().value(), "test-call-id-1");
        }
        _ => panic!("Expected request message"),
    }

    // Second decode
    let result2 = codec
        .decode(&mut buffer)
        .expect("second decode should succeed");
    assert!(result2.is_some(), "Should decode second message");

    let msg2 = result2.unwrap();
    match msg2 {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.call_id_header().unwrap().value(), "test-call-id-2");
        }
        _ => panic!("Expected request message"),
    }

    // Buffer should be empty after consuming both messages
    assert_eq!(
        buffer.len(),
        0,
        "Buffer should be empty after consuming all messages"
    );
}

/// Test SipCodec keepalive handling
#[test]
fn test_sip_codec_keepalive() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    // Test keepalive request
    buffer.extend_from_slice(KEEPALIVE_REQUEST);
    let result = codec.decode(&mut buffer).expect("decode should succeed");
    assert!(result.is_some(), "Should decode keepalive request");

    match result.unwrap() {
        crate::transport::stream::SipCodecType::KeepaliveRequest => {
            // Expected
        }
        _ => panic!("Expected keepalive request"),
    }
    assert_eq!(buffer.len(), 0, "Keepalive should be consumed from buffer");

    // Test keepalive response
    buffer.extend_from_slice(KEEPALIVE_RESPONSE);
    let result = codec.decode(&mut buffer).expect("decode should succeed");
    assert!(result.is_some(), "Should decode keepalive response");

    match result.unwrap() {
        crate::transport::stream::SipCodecType::KeepaliveResponse => {
            // Expected
        }
        _ => panic!("Expected keepalive response"),
    }
    assert_eq!(buffer.len(), 0, "Keepalive should be consumed from buffer");
}

/// Test SipCodec encoding
#[test]
fn test_sip_codec_encoding() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let test_message = "REGISTER sip:example.com SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
                        From: <sip:alice@example.com>;tag=test\r\n\
                        To: <sip:alice@example.com>\r\n\
                        Call-ID: test-call-id\r\n\
                        CSeq: 1 REGISTER\r\n\
                        Contact: <sip:alice@127.0.0.1:5060>\r\n\
                        Max-Forwards: 70\r\n\
                        Content-Length: 0\r\n\r\n";

    let sip_message = SipMessage::try_from(test_message).expect("parse SIP message");

    codec
        .encode(sip_message, &mut buffer)
        .expect("encode should succeed");

    assert_eq!(
        String::from_utf8_lossy(&buffer),
        test_message,
        "Encoded message should match original"
    );
}

/// Test error handling for malformed messages
#[test]
fn test_sip_codec_malformed_message() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let malformed_message = "INVALID MESSAGE\r\n\r\n";

    buffer.extend_from_slice(malformed_message.as_bytes());

    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Should error on malformed message");

    // Buffer should be cleared or partially consumed
    // The exact behavior depends on implementation
}

/// Test message size limit
#[test]
fn test_sip_codec_size_limit() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    // Create a message larger than the limit without complete headers (no \r\n\r\n)
    let large_content = "A".repeat(70000);
    let incomplete_large_message = format!(
        "MESSAGE sip:example.com SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test\r\n\
         From: <sip:alice@example.com>;tag=test\r\n\
         To: <sip:alice@example.com>\r\n\
         Call-ID: test-call-id\r\n\
         CSeq: 1 MESSAGE\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n{}",
        large_content.len(),
        large_content // No \r\n\r\n ending to trigger size check
    );

    buffer.extend_from_slice(incomplete_large_message.as_bytes());

    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Should error on oversized message");
}

/// Test SipCodec handling of multiple messages in one buffer (TCP packet coalescing)
#[test]
fn test_sip_codec_multiple_messages_with_bodies() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::new();

    let message1 = "REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test1\r\n\
                    From: <sip:alice@example.com>;tag=test1\r\n\
                    To: <sip:alice@example.com>\r\n\
                    Call-ID: test-call-id-1\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Contact: <sip:alice@127.0.0.1:5060>\r\n\
                    Max-Forwards: 70\r\n\
                    Content-Length: 11\r\n\r\nHello world";

    let message2 = "REGISTER sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test2\r\n\
                    From: <sip:bob@example.com>;tag=test2\r\n\
                    To: <sip:bob@example.com>\r\n\
                    Call-ID: test-call-id-2\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Contact: <sip:bob@127.0.0.1:5060>\r\n\
                    Max-Forwards: 70\r\n\
                    Content-Length: 6\r\n\r\nfoobar";

    // Add both messages to buffer
    buffer.extend_from_slice(message1.as_bytes());
    buffer.extend_from_slice(message2.as_bytes());

    // First decode
    let result1 = codec
        .decode(&mut buffer)
        .expect("first decode should succeed");
    assert!(result1.is_some(), "Should decode first message");

    let msg1 = result1.unwrap();
    match msg1 {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.call_id_header().unwrap().value(), "test-call-id-1");
        }
        _ => panic!("Expected request message"),
    }

    // Second decode
    let result2 = codec
        .decode(&mut buffer)
        .expect("second decode should succeed");
    assert!(result2.is_some(), "Should decode second message");

    let msg2 = result2.unwrap();
    match msg2 {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.call_id_header().unwrap().value(), "test-call-id-2");
        }
        _ => panic!("Expected request message"),
    }

    // Buffer should be empty after consuming both messages
    assert_eq!(
        buffer.len(),
        0,
        "Buffer should be empty after consuming all messages"
    );
}

/// Minimal request head used by the framing regression tests.
const FRAMING_REQUEST_HEAD: &str = "OPTIONS sip:a@b SIP/2.0\r\n\
    Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-framing\r\n\
    From: <sip:alice@example.com>;tag=framing\r\n\
    To: <sip:alice@example.com>\r\n\
    Call-ID: framing-test\r\n\
    CSeq: 1 OPTIONS\r\n\
    Max-Forwards: 70\r\n";

fn framing_request(content_length: &str) -> String {
    format!("{FRAMING_REQUEST_HEAD}Content-Length: {content_length}\r\n\r\n")
}

/// A Content-Length of usize::MAX must be rejected, not overflow the length
/// addition (which panics when overflow checks are enabled).
#[test]
fn test_sip_codec_rejects_content_length_overflow() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::from(framing_request(&usize::MAX.to_string()).as_bytes());
    assert!(codec.decode(&mut buffer).is_err());
}

/// The literal value from the report must not panic on any target; on 64-bit
/// it parses as usize::MAX, on 32-bit it fails to parse.
#[test]
fn test_sip_codec_rejects_decimal_content_length_overflow() {
    let mut codec = SipCodec::new();
    let mut buffer = BytesMut::from(framing_request("18446744073709551615").as_bytes());
    assert!(codec.decode(&mut buffer).is_err());
}

/// A declared body larger than the message limit is rejected before the
/// connection waits for (or buffers) the body.
#[test]
fn test_sip_codec_rejects_declared_body_over_limit() {
    let mut codec = SipCodec::new();
    let mut buffer =
        BytesMut::from(framing_request(&(MAX_SIP_MESSAGE_SIZE + 1).to_string()).as_bytes());
    assert!(codec.decode(&mut buffer).is_err());
}

/// Two Content-Length headers are ambiguous framing (RFC 4475 §3.3.9).
#[test]
fn test_sip_codec_rejects_duplicate_content_length() {
    for second in ["Content-Length: 0\r\n", "l: 0\r\n"] {
        let message = format!("{FRAMING_REQUEST_HEAD}Content-Length: 0\r\n{second}\r\n");
        let mut buffer = BytesMut::from(message.as_bytes());
        assert!(
            SipCodec::new().decode(&mut buffer).is_err(),
            "duplicate Content-Length must be rejected: {second:?}"
        );
    }
}

/// A valid pipelined message must still be framed exactly after the first
/// message body, with the second message starting at the buffer offset.
#[test]
fn test_sip_codec_pipelined_messages_stay_aligned() {
    let first = format!("{FRAMING_REQUEST_HEAD}Content-Length: 5\r\n\r\nhello");
    let second = framing_request("0");
    let mut buffer = BytesMut::from(format!("{first}{second}").as_bytes());
    let mut codec = SipCodec::new();

    let decoded = codec.decode(&mut buffer).unwrap().unwrap();
    match decoded {
        crate::transport::stream::SipCodecType::Message(SipMessage::Request(req)) => {
            assert_eq!(req.body, b"hello");
        }
        _ => panic!("Expected request message"),
    }
    assert!(
        buffer.starts_with(b"OPTIONS sip:a@b SIP/2.0\r\n"),
        "second message must start at the buffer offset"
    );

    assert!(codec.decode(&mut buffer).unwrap().is_some());
    assert!(buffer.is_empty());
}
