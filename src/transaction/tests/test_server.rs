use crate::sip::headers::*;
use crate::transport::SipConnection;
use crate::{
    transport::{udp::UdpConnection, TransportLayer},
    EndpointBuilder,
};
use std::time::Duration;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::test]
async fn test_server_transaction() {
    let token = CancellationToken::new();

    let mock_conn =
        UdpConnection::create_connection("127.0.0.1:0".parse().expect("parse addr"), None, None)
            .await
            .expect("create_connection");

    let mock_conn_sip: SipConnection = mock_conn.into();
    let addr = mock_conn_sip.get_addr().clone();

    let tl = TransportLayer::new(token.child_token());
    tl.add_transport(mock_conn_sip.clone());

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();

    let client_conn =
        UdpConnection::create_connection("127.0.0.1:0".parse().expect("parse addr"), None, None)
            .await
            .expect("create client connection");

    let client_conn_sip: SipConnection = client_conn.into();

    let send_loop = async {
        sleep(Duration::from_millis(50)).await;

        let register_req = crate::sip::message::Request {
            method: crate::sip::method::Method::Register,
            uri: crate::sip::Uri {
                scheme: Some(crate::sip::Scheme::Sip),
                host_with_port: crate::sip::HostWithPort::try_from(addr.addr.to_string())
                    .expect("host_port parse")
                    .into(),
                ..Default::default()
            },
            headers: vec![
                Via::new(&format!(
                    "SIP/2.0/UDP {};branch=z9hG4bKnashd92",
                    client_conn_sip.get_addr().addr
                ))
                .into(),
                CSeq::new("1 REGISTER").into(),
                From::new("Bob <sips:bob@restsend.com>;tag=ja743ks76zlflH").into(),
                CallId::new("1j9FpLxk3uxtm8tn@restsend.com").into(),
            ]
            .into(),
            version: crate::sip::Version::V2,
            body: Default::default(),
        };

        client_conn_sip
            .send(register_req.into(), Some(&addr))
            .await
            .expect("send");

        sleep(Duration::from_millis(100)).await;
        info!("Message sent, waiting for responses...");
    };

    let incoming_loop = async {
        let mut incoming = endpoint
            .incoming_transactions()
            .expect("incoming_transactions");
        let mut tx = incoming.recv().await.expect("incoming");
        assert_eq!(tx.original.method, crate::sip::method::Method::Register);
        let headers = tx.original.headers.clone();
        let done_response = crate::sip::Response {
            status_code: crate::sip::StatusCode::OK,
            version: crate::sip::Version::V2,
            headers,
            ..Default::default()
        };
        tx.send_trying().await.expect("send_trying");
        tx.respond(done_response).await.expect("respond 200");

        assert!(tx
            .endpoint_inner
            .finished_transactions
            .contains_key(&tx.key));
        sleep(Duration::from_secs(2)).await;
    };

    select! {
        _ = send_loop => {
        }
        _ = endpoint.serve()=> {}
        _ = incoming_loop => {
            assert!(false, "must not reach here");
        }
        _ = sleep(Duration::from_secs(1)) => {
            assert!(false, "timeout waiting");
        }
    }
}
