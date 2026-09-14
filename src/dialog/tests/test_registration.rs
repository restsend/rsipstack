use crate::dialog::authenticate::Credential;
use crate::dialog::registration::Registration;
use crate::sip::{prelude::*, SipMessage, StatusCode, Transport, Uri};
use crate::transaction::endpoint::TargetLocator;
use crate::transport::stream::{SipCodec, SipCodecType};
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{timeout, Duration};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;

struct RegistrationLocator(SipAddr);

#[async_trait]
impl TargetLocator for RegistrationLocator {
    async fn locate(&self, _uri: &Uri) -> crate::Result<SipAddr> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn test_register_via_matches_tcp_connection() {
    for mode in ["direct", "proxy", "locator"] {
        let token = CancellationToken::new();
        let tl = TransportLayer::new(token.clone());
        let udp = UdpConnection::create_connection(
            "127.0.0.1:0".parse().unwrap(),
            None,
            Some(token.clone()),
        )
        .await
        .unwrap();
        tl.add_transport(udp.into());
        let mut builder = EndpointBuilder::new();
        builder
            .with_cancel_token(token.clone())
            .with_transport_layer(tl);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // Keep a separate registrar listening to detect any unwanted direct dial.
        let registrar = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if mode == "locator" {
            let mut dest = SipAddr::from(listener.local_addr().unwrap());
            dest.r#type = Some(Transport::Tcp);
            builder.with_target_locator(Box::new(RegistrationLocator(dest)));
        }
        let endpoint = builder.build();
        let target = if mode != "direct" {
            registrar.local_addr().unwrap()
        } else {
            listener.local_addr().unwrap()
        };
        let uri: Uri = format!("sip:{};transport=tcp", target).try_into().unwrap();
        let mut registration = Registration::new(
            endpoint.inner.clone(),
            Some(Credential {
                username: "alice".into(),
                password: "secret".into(),
                realm: Some("test".into()),
            }),
        );
        if mode == "proxy" {
            registration.outbound_proxy = Some(listener.local_addr().unwrap());
        }
        let server = async {
            let (stream, peer) = listener.accept().await.unwrap();
            let mut framed = Framed::new(stream, SipCodec::new());
            for status in [StatusCode::Unauthorized, StatusCode::OK] {
                let request = match framed.next().await.unwrap().unwrap() {
                    SipCodecType::Message(SipMessage::Request(request)) => request,
                    other => panic!("unexpected message: {}", other),
                };
                assert_eq!(request.uri, uri);
                let via = request.via_header().unwrap().typed().unwrap();
                assert_eq!(via.transport, Transport::Tcp);
                assert_eq!(via.uri.host_with_port, peer.into());
                if status == StatusCode::OK {
                    assert!(request.authorization_header().is_some());
                }
                let mut response = endpoint.inner.make_response(&request, status.clone(), None);
                if status == StatusCode::Unauthorized {
                    response.headers.push(
                        crate::sip::headers::WwwAuthenticate::new(
                            "Digest realm=\"test\", nonce=\"test-nonce\", algorithm=MD5, qop=\"auth\"",
                        )
                        .into(),
                    );
                }
                framed.send(SipMessage::Response(response)).await.unwrap();
            }
        };
        let client = async {
            let response = registration.register(uri.clone(), Some(300)).await.unwrap();
            assert_eq!(response.status_code, StatusCode::OK);
        };
        let exchange = async {
            tokio::join!(server, client);
        };
        tokio::select! {
            _ = endpoint.serve() => panic!("endpoint stopped"),
            result = timeout(Duration::from_secs(5), exchange) => result.unwrap(),
        }
        assert!(timeout(Duration::from_millis(50), registrar.accept())
            .await
            .is_err());
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
        token.cancel();
    }
}

#[tokio::test]
async fn test_register_udp_unchanged() {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.clone());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.clone()),
    )
    .await
    .unwrap();
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_cancel_token(token.clone())
        .with_transport_layer(tl)
        .build();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uri: Uri = format!("sip:{}", socket.local_addr().unwrap())
        .try_into()
        .unwrap();
    let mut registration = Registration::new(endpoint.inner.clone(), None);
    let server = async {
        let mut buf = [0u8; 4096];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request: crate::sip::Request = std::str::from_utf8(&buf[..len])
            .unwrap()
            .try_into()
            .unwrap();
        let via = request.via_header().unwrap().typed().unwrap();
        assert_eq!(via.transport, Transport::Udp);
        assert_eq!(via.uri.host_with_port, peer.into());
        let response = endpoint.inner.make_response(&request, StatusCode::OK, None);
        socket.send_to(&response.to_bytes(), peer).await.unwrap();
    };
    let client = async {
        assert_eq!(
            registration.register(uri, Some(300)).await.unwrap().status_code,
            StatusCode::OK,
        );
    };
    let exchange = async {
        tokio::join!(server, client);
    };
    tokio::select! {
        _ = endpoint.serve() => panic!("endpoint stopped"),
        result = timeout(Duration::from_secs(5), exchange) => result.unwrap(),
    }
    token.cancel();
}
