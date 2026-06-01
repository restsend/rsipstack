use crate::sip::{headers::*, prelude::HeadersExt, HostWithPort, SipMessage};
use crate::transport::{SipAddr, SipConnection};

#[test]
fn test_via_received() {
    let register_req = crate::sip::message::Request {
        method: crate::sip::method::Method::Register,
        uri: crate::sip::Uri {
            scheme: Some(crate::sip::Scheme::Sip),
            host_with_port: crate::sip::HostWithPort::try_from("127.0.0.1:2025")
                .expect("host_port parse")
                .into(),
            ..Default::default()
        },
        headers: vec![Via::new("SIP/2.0/TLS restsend.com:5061;branch=z9hG4bKnashd92").into()]
            .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    };

    let (_, parse_addr) =
        SipConnection::parse_target_from_via(&register_req.via_header().expect("via_header"))
            .expect("get_target_socketaddr");

    let addr = HostWithPort {
        host: "restsend.com".parse().unwrap(),
        port: Some(5061.into()),
    };
    assert_eq!(parse_addr, addr);

    let addr = "127.0.0.1:1234".parse().unwrap();
    let msg = SipConnection::update_msg_received(
        register_req.into(),
        addr,
        crate::sip::transport::Transport::Udp,
    )
    .expect("update_msg_received");

    match msg {
        SipMessage::Request(req) => {
            let (_, parse_addr) =
                SipConnection::parse_target_from_via(&req.via_header().expect("via_header"))
                    .expect("get_target_socketaddr");
            assert_eq!(parse_addr, addr.into());
        }
        _ => {}
    }
}

#[test]
fn parse_target_from_via_uses_topmost_value() {
    let via = Via::new(
        "SIP/2.0/UDP 10.0.13.70:5060;received=172.22.22.80;rport=5062,SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKproxy",
    );

    let (_, parse_addr) =
        SipConnection::parse_target_from_via(&via).expect("get_target_socketaddr");

    let addr = HostWithPort {
        host: "172.22.22.80".parse().unwrap(),
        port: Some(5062.into()),
    };
    assert_eq!(parse_addr, addr);
}

#[test]
fn parse_target_from_via_keeps_quoted_comma_in_first_value() {
    let via = Via::new(
        "SIP/2.0/UDP 10.0.13.70:5060;received=172.22.22.80;rport=5062;note=\"edge, \\\"one\\\"\",SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKproxy",
    );

    let (_, parse_addr) =
        SipConnection::parse_target_from_via(&via).expect("get_target_socketaddr");

    let addr = HostWithPort {
        host: "172.22.22.80".parse().unwrap(),
        port: Some(5062.into()),
    };
    assert_eq!(parse_addr, addr);
}

#[test]
fn build_via_received_updates_first_value_only() {
    let mut via = Via::new(
        "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKfirst,SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKsecond",
    );

    SipConnection::build_via_received(
        &mut via,
        "192.0.2.10:5062".parse().unwrap(),
        crate::sip::Transport::Udp,
    )
    .unwrap();

    assert_eq!(
        via.value(),
        "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKfirst;received=192.0.2.10;rport=5062,SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKsecond"
    );
}

#[test]
fn test_sipaddr() {
    let addr = "sip:proxy1.example.org:25060;transport=tcp";
    let uri = crate::sip::Uri::try_from(addr).expect("parse uri");
    let sipaddr = SipAddr::try_from(&uri).expect("SipAddr::try_from");
    assert_eq!(sipaddr.r#type, Some(crate::sip::transport::Transport::Tcp));
    assert_eq!(
        sipaddr.addr,
        crate::sip::HostWithPort {
            host: "proxy1.example.org".parse().unwrap(),
            port: Some(25060.into()),
        }
    );
}
