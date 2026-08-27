use crate::sip::{headers::*, prelude::HeadersExt, SipMessage, Transport};
use crate::transport::SipConnection;
use std::net::SocketAddr;

/// Test Via received parameter handling for different transport protocols
#[test]
fn test_via_received_udp() {
    let register_req = create_test_request("SIP/2.0/UDP");
    let addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Udp)
        .expect("update_msg_received for UDP");

    match msg {
        SipMessage::Request(req) => {
            let via_header = req.via_header().expect("via header");
            let typed_via = via_header.typed().expect("typed via");

            // UDP should always add received parameter
            assert!(
                typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "UDP should add received parameter"
            );
            assert!(
                typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Rport(Some(_)))),
                "UDP should add rport parameter"
            );
        }
        _ => panic!("Expected request message"),
    }
}

#[test]
fn test_via_received_tcp() {
    let register_req = create_test_request("SIP/2.0/TCP");
    let addr: SocketAddr = "127.0.0.1:5060".parse().unwrap(); // Same as Via header

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tcp)
        .expect("update_msg_received for TCP");

    match msg {
        SipMessage::Request(req) => {
            let via_header = req.via_header().expect("via header");
            let typed_via = via_header.typed().expect("typed via");

            // TCP should not add received parameter if source matches Via
            assert!(
                !typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "TCP should not add received parameter when addresses match"
            );
        }
        _ => panic!("Expected request message"),
    }
}

#[test]
fn test_via_received_tcp_different_addr() {
    let register_req = create_test_request("SIP/2.0/TCP");
    let addr: SocketAddr = "192.168.1.100:5060".parse().unwrap(); // Different from Via header

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tcp)
        .expect("update_msg_received for TCP");

    match msg {
        SipMessage::Request(req) => {
            let via_header = req.via_header().expect("via header");
            let typed_via = via_header.typed().expect("typed via");

            // TCP should add received parameter if source differs from Via
            assert!(
                typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "TCP should add received parameter when addresses differ"
            );
        }
        _ => panic!("Expected request message"),
    }
}

#[test]
fn test_via_received_tls() {
    let register_req = create_test_request("SIP/2.0/TLS");
    let addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tls)
        .expect("update_msg_received for TLS");

    match msg {
        SipMessage::Request(req) => {
            let via_header = req.via_header().expect("via header");
            let typed_via = via_header.typed().expect("typed via");

            // TLS should add received parameter only if host differs
            assert!(
                typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "TLS should add received parameter when host differs"
            );
        }
        _ => panic!("Expected request message"),
    }
}

#[test]
fn test_via_received_ws() {
    let register_req = create_test_request("SIP/2.0/WS");
    let addr: SocketAddr = "192.168.1.100:80".parse().unwrap();

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Ws)
        .expect("update_msg_received for WS");

    match msg {
        SipMessage::Request(req) => {
            let via_header = req.via_header().expect("via header");
            let typed_via = via_header.typed().expect("typed via");

            // WS should handle received parameter like other connection-oriented protocols
            assert!(
                typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "WS should add received parameter when host differs"
            );
        }
        _ => panic!("Expected request message"),
    }
}

#[test]
fn test_via_response_not_modified() {
    let response = crate::sip::message::Response {
        status_code: crate::sip::StatusCode::try_from(200).unwrap(),
        headers: vec![Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test").into()].into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    };

    let addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();

    let msg = SipConnection::update_msg_received(response.into(), addr, Transport::Udp)
        .expect("update_msg_received for response");

    // Response messages should not be modified
    match msg {
        SipMessage::Response(_) => {
            // This is expected - responses are not modified
        }
        _ => panic!("Expected response message"),
    }
}

/// RFC 3581 §4: when the client requests rport, the server MUST echo
/// rport=<actual source port> even when the Via host matches and no
/// received parameter is needed.
#[test]
fn test_via_rport_echoed_when_host_matches_tcp() {
    let mut register_req = create_test_request("SIP/2.0/TCP");
    register_req.headers =
        vec![Via::new("SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test;rport").into()].into();
    let addr: SocketAddr = "127.0.0.1:5060".parse().unwrap(); // Same as Via header

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tcp)
        .expect("update_msg_received for TCP");

    match msg {
        SipMessage::Request(req) => {
            let typed_via = req.via_header().unwrap().typed().unwrap();
            assert!(
                !typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "no received when host matches"
            );
            let has_rport = typed_via
                .params
                .iter()
                .any(|p| matches!(p, crate::sip::Param::Rport(Some(5060))));
            assert!(has_rport, "requested rport must be echoed with actual port");
        }
        _ => panic!("Expected request message"),
    }
}

/// RFC 3581 §4: reliable transport where only the port differs — no received
/// parameter, but a requested rport must still be echoed.
#[test]
fn test_via_rport_echoed_when_only_port_differs() {
    let mut register_req = create_test_request("SIP/2.0/TCP");
    register_req.headers =
        vec![Via::new("SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-test;rport").into()].into();
    let addr: SocketAddr = "127.0.0.1:65000".parse().unwrap();

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tcp)
        .expect("update_msg_received for TCP");

    match msg {
        SipMessage::Request(req) => {
            let typed_via = req.via_header().unwrap().typed().unwrap();
            assert!(
                !typed_via
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Received(_))),
                "host matches: no received param"
            );
            let has_rport = typed_via
                .params
                .iter()
                .any(|p| matches!(p, crate::sip::Param::Rport(Some(65_000))));
            assert!(has_rport, "rport must carry the real source port");
        }
        _ => panic!("Expected request message"),
    }
}

/// No rport requested → exact address match keeps the Via untouched.
#[test]
fn test_via_untouched_without_rport_request_on_exact_match() {
    let register_req = create_test_request("SIP/2.0/TCP"); // no rport param
    let addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();

    let msg = SipConnection::update_msg_received(register_req.into(), addr, Transport::Tcp)
        .expect("update_msg_received for TCP");

    match msg {
        SipMessage::Request(req) => {
            let raw = req.via_header().unwrap().to_string();
            assert!(
                !raw.contains("received=") && !raw.contains("rport"),
                "exact match without rport request must not mutate Via, got: {raw}"
            );
        }
        _ => panic!("Expected request message"),
    }
}

fn create_test_request(via_proto: &str) -> crate::sip::message::Request {
    crate::sip::message::Request {
        method: crate::sip::method::Method::Register,
        uri: crate::sip::Uri {
            scheme: Some(crate::sip::Scheme::Sip),
            host_with_port: crate::sip::HostWithPort::try_from("example.com:5060")
                .expect("host_port parse"),
            ..Default::default()
        },
        headers: vec![
            Via::new(&format!("{} 127.0.0.1:5060;branch=z9hG4bK-test", via_proto)).into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    }
}
