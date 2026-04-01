use crate::sip::headers::*;
use std::{sync::Arc, time::Duration};
use tokio::{select, time::sleep};

fn assert_send<T: Send>() {}

#[test]
fn test_send() {
    assert_send::<crate::transaction::Endpoint>();
}

#[tokio::test]
async fn test_endpoint_serve() {
    let endpoint = Arc::new(
        super::create_test_endpoint(None)
            .await
            .expect("create_test_endpoint"),
    );
    let endpoint_ref = endpoint.clone();
    tokio::spawn(async move {
        endpoint_ref.serve().await;
    });

    let mut incoming = endpoint
        .incoming_transactions()
        .expect("incoming_transactions");
    select! {
        _ = async {
            sleep(Duration::from_millis(100)).await;
            endpoint.shutdown();
        } => {
        }
        _ = async {
            while let Some(_) = incoming.recv().await {
                // Handle transaction
                break; // Exit for example
            }
        } => {
            assert!(false, "must not reach here");
        }
    }
    endpoint.shutdown();
}

#[tokio::test]
async fn test_endpoint_recvrequests() {
    let addr = "127.0.0.1:0";
    let endpoint = super::create_test_endpoint(Some(addr))
        .await
        .expect("create_test_endpoint");

    let addr = endpoint
        .get_addrs()
        .get(0)
        .expect("must has connection")
        .to_owned();

    let send_loop = async {
        let test_conn = crate::transport::udp::UdpConnection::create_connection(
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
        )
        .await
        .expect("create_connection");
        let register_req = crate::sip::message::Request {
            method: crate::sip::method::Method::Register,
            uri: crate::sip::Uri {
                scheme: Some(crate::sip::Scheme::Sips),
                auth: Some(crate::sip::Auth {
                    user: "bob".to_string(),
                    password: None,
                }),
                host_with_port: crate::sip::HostWithPort::try_from("restsend.com")
                    .expect("host_port parse")
                    .into(),
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
        let buf: String = register_req.try_into().expect("try_into");
        test_conn
            .send_raw(&buf.as_bytes(), &addr)
            .await
            .expect("send_raw");
        sleep(Duration::from_secs(1)).await;
    };

    let incoming_loop = async {
        let mut incoming = endpoint
            .incoming_transactions()
            .expect("incoming_transactions");
        incoming.recv().await.expect("incoming").original.clone()
    };

    select! {
        _ = send_loop => {
            assert!(false, "must not reach here");
        }
        _ = endpoint.serve()=> {}
        req = incoming_loop => {
            assert_eq!(req.method, crate::sip::method::Method::Register);
            assert_eq!(req.uri.to_string(), "sips:bob@restsend.com");
        }
    }
}
