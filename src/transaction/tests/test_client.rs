use crate::sip::{headers::*, prelude::HeadersExt, Header, Response, SipMessage, Uri};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transport::udp::UdpConnection;
use crate::{transport::TransportEvent, Result};
use std::convert::TryFrom;
use std::time::Duration;
use tokio::{select, sync::mpsc::unbounded_channel, time::sleep};
use tracing::info;

fn make_invite_request(uri: &str) -> Result<crate::sip::Request> {
    Ok(crate::sip::Request {
        method: crate::sip::Method::Invite,
        uri: Uri::try_from(uri)?,
        headers: vec![
            Via::new("SIP/2.0/TCP uac.example.com:5060;branch=z9hG4bK1").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("callid@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    })
}

#[tokio::test]
async fn test_client_transaction() -> Result<()> {
    let endpoint = super::create_test_endpoint(Some("127.0.0.1:0")).await?;
    let server_addr = endpoint
        .get_addrs()
        .get(0)
        .expect("must has connection")
        .to_owned();
    info!("server addr: {}", server_addr);

    let peer_server = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_server_loop = async {
        let (sender, mut recevier) = unbounded_channel();
        select! {
            _ = async {
                if let Some(event) = recevier.recv().await {
                    match event {
                        TransportEvent::Incoming(msg, connection, _) => {
                            info!("recv request: {}", msg);
                            assert!(msg.is_request());
                            match msg {
                                SipMessage::Request(req) => {
                                    let headers = req.headers.clone();
                                    let response = SipMessage::Response(crate::sip::message::Response {
                                        version: crate::sip::Version::V2,
                                        status_code:crate::sip::StatusCode::Trying,
                                        headers: headers.clone(),
                                        body: Default::default(),
                                    });
                                    connection.send(response, None).await.expect("send trying");
                                    sleep(Duration::from_millis(100)).await;

                                    let response = SipMessage::Response(crate::sip::message::Response {
                                        version: crate::sip::Version::V2,
                                        status_code:crate::sip::StatusCode::OK,
                                        headers,
                                        body: Default::default(),
                                    });
                                    connection.send(response, None).await.expect("send Ok");
                                    sleep(Duration::from_secs(1)).await;
                                }
                                _ => {
                                    assert!(false, "must not reach here");
                                }
                            }
                        }
                        _ => {}
                    }
                } else {
                    assert!(false, "must not reach here");
                }
            } => {}
            _ = peer_server.serve_loop(sender) => {
                assert!(false, "must not reach here");
            }
        }
    };

    let recv_loop = async {
        let register_req = crate::sip::message::Request {
            method: crate::sip::method::Method::Register,
            uri: crate::sip::Uri {
                scheme: Some(crate::sip::Scheme::Sip),
                host_with_port: peer_server.get_addr().addr.clone(),
                ..Default::default()
            },
            headers: vec![
                Via::new("SIP/2.0/TLS restsend.com:5061;branch=z9hG4bKnashd92").into(),
                CSeq::new("1 REGISTER").into(),
                From::new("Bob <sips:bob@restsend.com>;tag=ja743ks76zlflH").into(),
                CallId::new("1j9FpLxk3uxtm8tn@restsend.com").into(),
            ]
            .into(),
            version: crate::sip::Version::V2,
            body: Default::default(),
        };

        let key = TransactionKey::from_request(&register_req, TransactionRole::Client)
            .expect("client_transaction");
        let mut tx = Transaction::new_client(key, register_req, endpoint.inner.clone(), None);
        tx.send().await.expect("send request");

        while let Some(resp) = tx.receive().await {
            info!("Received response: {:?}", resp);
        }
    };

    select! {
        _ = recv_loop => {}
        _ = peer_server_loop => {
            assert!(false, "must not reach here");
        }
        _ = endpoint.serve() => {
            assert!(false, "must not reach here");
        }
        _ = sleep(Duration::from_secs(1)) => {
            assert!(false, "timeout waiting");
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_make_ack_uses_contact_and_reversed_route_order() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP uac.example.com:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:proxy1.example.com:5060;transport=tcp;lr>\r\n\
Record-Route: <sip:proxy2.example.com:5070;transport=tcp;lr>\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;

    let expected_uri = Uri::try_from("sip:uas@192.0.2.55:5080;transport=tcp")?;
    assert_eq!(ack.uri, expected_uri, "ACK must target the remote Contact");

    // Check Content-Length
    let content_length: String = ack
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::ContentLength(content_length) => Some(content_length.value().to_string()),
            _ => None,
        })
        .next()
        .expect("ACK must include a Content-Length header");

    assert_eq!(content_length, "0", "Content-Length of ACK must be 0");
    let routes: Vec<String> = ack
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert_eq!(
        routes,
        vec![
            "<sip:proxy2.example.com:5070;transport=TCP;lr>".to_string(),
            "<sip:proxy1.example.com:5060;transport=TCP;lr>".to_string()
        ],
        "ACK Route headers must follow the reversed Record-Route order"
    );

    Ok(())
}

#[tokio::test]
async fn test_make_ack_accepts_comma_separated_record_route() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:3.4.5.6:24364;r2=on;lr;ftag=Xq5kaQn5;did=9e8.3362>,<sip:3.4.5.6:21827;r2=on;lr;ftag=Xq5kaQn5;did=9e8.3362>,<sip:1.2.40.7:21827;lr;ftag=Xq5kaQn5;did=9e8.ab21>\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;transport=udp>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;

    let routes: Vec<String> = ack
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert_eq!(
        routes,
        vec![
            "<sip:1.2.40.7:21827;lr;ftag=Xq5kaQn5;did=9e8.ab21>".to_string(),
            "<sip:3.4.5.6:21827;r2=on;lr;ftag=Xq5kaQn5;did=9e8.3362>".to_string(),
            "<sip:3.4.5.6:24364;r2=on;lr;ftag=Xq5kaQn5;did=9e8.3362>".to_string(),
        ],
        "ACK Route headers must follow the reversed Record-Route order"
    );

    let destination = ack.destination();
    let expected_destination = Uri::try_from("sip:1.2.40.7:21827;lr;ftag=Xq5kaQn5;did=9e8.ab21")?;
    assert_eq!(
        destination, expected_destination,
        "First Route entry must determine the transport destination",
    );

    Ok(())
}

#[tokio::test]
async fn test_make_ack_updates_first_combined_via_value_only() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bKfirst,SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKsecond\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;transport=udp>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;
    let via = ack.via_header()?.value();

    assert!(via.starts_with("SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK"));
    assert!(!via.contains("z9hG4bKfirst"));
    assert!(via.contains(",SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKsecond"));

    Ok(())
}

#[tokio::test]
async fn test_make_ack_preserves_du_param_with_colons_in_record_route() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:2.2.2.2;lr=on;ftag=d4nwJ0jF;du=sip:1.2.3.4:5060;did=893.d6d1>,<sip:4.5.6.7:32222;lr=on;ftag=d4nwJ0jF>\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;transport=udp>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;

    let expected_uri = Uri::try_from("sip:uas@192.0.2.55:5080")?;
    assert_eq!(
        ack.uri, expected_uri,
        "lr=on must be treated as loose routing so ACK targets Contact",
    );

    let routes: Vec<String> = ack
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert!(
        routes
            .iter()
            .any(|r| { r.contains("du=sip:1.2.3.4:5060") && r.contains("did=893.d6d1") }),
        "ACK Route headers must preserve du parameter values with colons and keep following params"
    );

    assert_eq!(
        routes,
        vec![
            "<sip:4.5.6.7:32222;lr=on;ftag=d4nwJ0jF>".to_string(),
            "<sip:2.2.2.2;lr=on;ftag=d4nwJ0jF;du=sip:1.2.3.4:5060;did=893.d6d1>".to_string(),
        ],
        "lr=on route set must be handled as loose routing and keep reversed Record-Route order",
    );

    Ok(())
}

#[tokio::test]
async fn test_make_ack_uses_contact_with_ob() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP uac.example.com:5060;branch=z9hG4bK1;rport=15060;received=1.2.3.4;\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;ob>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;
    let expected_uri = Uri::try_from("sip:uas@192.0.2.55:5080;ob")?;
    assert_eq!(ack.uri, expected_uri, "ACK must target the remote Contact");
    Ok(())
}

#[tokio::test]
async fn test_make_ack_uses_first_route_without_lr() -> Result<()> {
    let endpoint = super::create_test_endpoint(None).await?;

    let raw_response = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP uac.example.com:5060;branch=z9hG4bK1\r\n\
Record-Route: <sip:strict-proxy-1.example.com:5060>\r\n\
Record-Route: <sip:strict-proxy-2.example.com:5070>\r\n\
From: <sip:alice@example.com>;tag=from-tag\r\n\
To: <sip:bob@example.com>;tag=to-tag\r\n\
Call-ID: callid@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:uas@192.0.2.55:5080;transport=tcp>\r\n\
Content-Length: 0\r\n\r\n";

    let response = Response::try_from(raw_response)?;
    let invite = make_invite_request("sip:bob@example.com")?;
    let ack = endpoint.inner.make_ack(&invite, &response)?;

    assert_eq!(
        ack.uri,
        Uri::try_from("sip:strict-proxy-2.example.com:5070")?,
        "strict routing must place the first route set URI into the Request-URI"
    );

    let routes: Vec<String> = ack
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert_eq!(
        routes,
        vec![
            "<sip:strict-proxy-1.example.com:5060>".to_string(),
            "<sip:uas@192.0.2.55:5080;transport=TCP>".to_string(),
        ],
        "strict routing must place the remaining route set first and the remote target last"
    );

    Ok(())
}

#[tokio::test]
async fn test_invite_2xx_upstream_via_delivery_and_ack() -> Result<()> {
    use crate::transaction::transaction::TransactionEvent;
    use crate::transaction::{TransactionState, TransactionTimer};
    use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection};

    // Include comma-separated Via, quoted commas, and inconclusive values.
    for (via, extra_header, proxy) in [
        ("SIP/2.0/UDP proxy.example.com;branch=z9hG4bK1", true, true),
        ("SIP/2.0/UDP proxy.example.com;branch=z9hG4bK1, SIP/2.0/UDP caller.example.com;branch=z9hG4bKupstream", false, true),
        ("SIP/2.0/UDP ua.example.com;branch=z9hG4bK1;note=\"one, two\"", false, false),
        ("SIP/2.0/UDP ua.example.com;branch=z9hG4bK1, ", false, false),
    ] {
        for status in [crate::sip::StatusCode::OK, crate::sip::StatusCode::BusyHere] {
            let endpoint = super::create_test_endpoint(None).await?;
            let addr = SipAddr::from("127.0.0.1:5090".parse::<std::net::SocketAddr>()?);
            let (_incoming_tx, incoming_rx) = unbounded_channel();
            let (outgoing_tx, mut outgoing_rx) = unbounded_channel();
            let conn = SipConnection::Channel(ChannelConnection::create_connection(
                incoming_rx, outgoing_tx, addr.clone(), None,
            ).await?);
            let mut request = make_invite_request("sip:bob@127.0.0.1:5090")?;
            request.via_header_mut()?.replace(via);
            if extra_header {
                request.headers.push(Via::new("SIP/2.0/UDP caller.example.com;branch=z9hG4bKupstream").into());
            }
            let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
            let mut tx = Transaction::new_client(key.clone(), request.clone(), endpoint.inner.clone(), Some(conn.clone()));
            tx.send().await?;
            outgoing_rx.recv().await.expect("outgoing INVITE");
            let mut response = endpoint.inner.make_response(&request, status.clone(), None);
            response.to_header_mut()?.mut_tag(crate::transaction::make_tag())?;
            response.headers.push(Contact::new("<sip:bob@127.0.0.1:5090>").into());
            let suppress_ack = proxy && status == crate::sip::StatusCode::OK;
            let mut deadline = None;
            for iteration in 0..3 {
                if iteration == 2 {
                    // A forked response with the same status/body must also be delivered.
                    response.to_header_mut()?.mut_tag(crate::transaction::make_tag())?;
                }
                endpoint.inner.on_received_message(response.clone().into(), conn.clone(), &addr).await?;
                if iteration == 0 || suppress_ack {
                    let delivered = tokio::time::timeout(Duration::from_secs(1), tx.receive()).await
                        .expect("response must reach application").expect("response");
                    assert_eq!(delivered, SipMessage::Response(response.clone()));
                }
                if suppress_ack {
                    assert_eq!(tx.state, TransactionState::Completed);
                    assert!(tx.last_ack.is_none());
                    assert!(outgoing_rx.try_recv().is_err(), "proxy must not send ACK");
                    if iteration == 0 {
                        deadline = tx.timer_d;
                        assert!(deadline.is_some());
                    }
                    assert_eq!(tx.timer_d, deadline, "duplicates must not extend lifetime");
                } else {
                    assert_eq!(tx.state, TransactionState::Terminated);
                    let TransportEvent::Incoming(SipMessage::Request(ack), _, _) =
                        outgoing_rx.try_recv().expect("UA 2xx and proxy non-2xx require ACK") else {
                            panic!("expected ACK");
                        };
                    assert_eq!(ack.method, crate::sip::Method::Ack);
                }
            }
            if suppress_ack {
                tx.tu_sender.send(TransactionEvent::Timer(TransactionTimer::TimerD(key.clone()))).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), tx.receive()).await.unwrap().is_none());
                assert_eq!(tx.state, TransactionState::Terminated);
                assert!(!endpoint.inner.transactions.contains_key(&key));
                assert!(!endpoint.inner.finished_transactions.contains_key(&key));

                // A stale cached ACK must not ACK a late proxy 2xx either.
                let ack = endpoint.inner.make_ack(&request, &response)?;
                endpoint.inner.finished_transactions.insert(key.clone(), Some(ack.into()));
                endpoint.inner.on_received_message(response.clone().into(), conn.clone(), &addr).await?;
                assert!(outgoing_rx.try_recv().is_err(), "cached ACK must not acknowledge proxy 2xx");
            }
        }
    }
    Ok(())
}
