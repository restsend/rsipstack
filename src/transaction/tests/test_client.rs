use crate::rsip_ext::RsipResponseExt;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transport::udp::UdpConnection;
use crate::transport::SipAddr;
use crate::{transport::TransportEvent, Result};
use rsip::{headers::*, Header, Response, SipMessage, Uri};
use std::convert::TryFrom;
use std::time::Duration;
use tokio::{select, sync::mpsc::unbounded_channel, time::sleep};
use tracing::info;

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
                                    let response = SipMessage::Response(rsip::message::Response {
                                        version: rsip::Version::V2,
                                        status_code:rsip::StatusCode::Trying,
                                        headers: headers.clone(),
                                        body: Default::default(),
                                    });
                                    connection.send(response, None).await.expect("send trying");
                                    sleep(Duration::from_millis(100)).await;

                                    let response = SipMessage::Response(rsip::message::Response {
                                        version: rsip::Version::V2,
                                        status_code:rsip::StatusCode::OK,
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
        let register_req = rsip::message::Request {
            method: rsip::method::Method::Register,
            uri: rsip::Uri {
                scheme: Some(rsip::Scheme::Sip),
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
            version: rsip::Version::V2,
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
    let request_uri = response.remote_uri(None)?;
    let ack = endpoint.inner.make_ack(&response, request_uri)?;

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
            "<sip:proxy2.example.com:5070;transport=tcp;lr>".to_string(),
            "<sip:proxy1.example.com:5060;transport=tcp;lr>".to_string()
        ],
        "ACK Route headers must follow the reversed Record-Route order"
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
    let dest = SipAddr {
        r#type: Some(rsip::transport::Transport::Tcp),
        addr: "1.2.3.4:15060".try_into()?,
    };
    let request_uri = dest.try_into().expect("to uri failed");
    let ack = endpoint.inner.make_ack(&response, request_uri)?;
    let expected_uri = Uri::try_from("sip:1.2.3.4:15060;transport=tcp")?;
    assert_eq!(ack.uri, expected_uri, "ACK must target the remote Contact");
    Ok(())
}
