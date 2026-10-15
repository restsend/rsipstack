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
            // Handle the transaction; this example exits on the first one.
            let _ = incoming.recv().await;
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

#[tokio::test]
async fn test_get_record_route_addr_override() {
    let endpoint = super::create_test_endpoint(Some("127.0.0.1:15060"))
        .await
        .expect("create_test_endpoint");

    let default_rr = endpoint.inner.get_record_route().expect("get_record_route");
    assert_eq!(default_rr.uri.to_string(), "sip:127.0.0.1:15060;lr");

    let override_addr = crate::transport::SipAddr {
        r#type: Some(crate::sip::Transport::Udp),
        addr: crate::sip::HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                127, 0, 0, 1,
            ))),
            port: Some(15061.into()),
        },
    };
    let override_rr = endpoint.inner.get_record_route_with_addr(override_addr);
    assert_eq!(override_rr.uri.to_string(), "sip:127.0.0.1:15061;lr");
}

#[tokio::test]
async fn test_serve_rejects_duplicate_udp_reader() -> Result<(), Box<dyn std::error::Error>> {
    use crate::transport::{udp::UdpConnection, TransportLayer};
    use tokio::sync::{mpsc, Semaphore};
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    let token = CancellationToken::new();
    let transport = TransportLayer::new(token.child_token());
    let udp =
        UdpConnection::create_connection("127.0.0.1:0".parse()?, None, Some(token.child_token()))
            .await?;
    let addr = udp.get_addr().get_socketaddr()?;
    transport.add_transport(udp.into());
    let gate = Arc::new(Semaphore::new(0));
    let (seen, mut packets) = mpsc::unbounded_channel();
    let reader_gate = gate.clone();
    transport.set_whitelist(move |_| {
        let seen = seen.clone();
        let gate = reader_gate.clone();
        async move {
            seen.send(()).unwrap();
            gate.acquire().await.unwrap().forget();
            false
        }
    });
    let endpoint = crate::EndpointBuilder::new()
        .with_transport_layer(transport)
        .with_cancel_token(token.child_token())
        .build();
    let inner = endpoint.inner.clone();
    let serving = tokio::spawn(async move { inner.serve().await });
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    // The whitelist blocks the first reader before it can receive again.
    peer.send_to(b"first packet", addr).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), packets.recv()).await?,
        Some(())
    );
    let second = timeout(Duration::from_secs(2), endpoint.inner.serve()).await?;
    assert!(matches!(second, Err(crate::Error::EndpointError(_))));
    peer.send_to(b"second packet", addr).await?;
    assert!(timeout(Duration::from_millis(100), packets.recv())
        .await
        .is_err());
    // Releasing the original reader lets it consume the queued packet.
    gate.add_permits(2);
    assert_eq!(
        timeout(Duration::from_secs(2), packets.recv()).await?,
        Some(())
    );
    token.cancel();
    timeout(Duration::from_secs(2), serving).await???;
    Ok(())
}
