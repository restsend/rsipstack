//! A stream (TCP) connection that the peer closed must not be reused for
//! later requests: the next request has to open a fresh connection instead
//! of being written to the dead one and waiting out Timer B/F.
use crate::sip::{headers::*, Method, SipMessage, StatusCode};
use crate::transaction::endpoint::EndpointOption;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::EndpointBuilder;
use crate::transport::tcp::TcpConnection;
use crate::transport::{udp::UdpConnection, SipAddr, SipConnection, TransportLayer};
use crate::Result;
use std::convert::TryFrom;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Read one SIP request (no body) from a raw stream.
async fn read_request(stream: &mut TcpStream) -> crate::sip::Request {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.expect("read request");
        assert!(n > 0, "peer closed before a full request");
        buf.extend_from_slice(&chunk[..n]);
    }
    let raw = String::from_utf8_lossy(&buf).to_string();
    match SipMessage::try_from(raw.as_str()).expect("parse request") {
        SipMessage::Request(req) => req,
        _ => panic!("expected a request"),
    }
}

/// Answer `req` with a 200 OK on a raw stream.
async fn answer(stream: &mut TcpStream, req: &crate::sip::Request) {
    let mut resp = String::from("SIP/2.0 200 OK\r\n");
    for header in req.headers.iter() {
        match header {
            crate::sip::Header::Via(_)
            | crate::sip::Header::From(_)
            | crate::sip::Header::To(_)
            | crate::sip::Header::CallId(_)
            | crate::sip::Header::CSeq(_) => {
                resp.push_str(&header.to_string());
                resp.push_str("\r\n");
            }
            _ => {}
        }
    }
    resp.push_str("Content-Length: 0\r\n\r\n");
    stream
        .write_all(resp.as_bytes())
        .await
        .expect("write response");
}

async fn answer_one(stream: &mut TcpStream) {
    let req = read_request(stream).await;
    answer(stream, &req).await;
}

fn make_options(peer: std::net::SocketAddr, cseq: u32) -> Result<crate::sip::Request> {
    make_request(Method::Options, peer, cseq)
}

fn make_request(
    method: Method,
    peer: std::net::SocketAddr,
    cseq: u32,
) -> Result<crate::sip::Request> {
    let uri = crate::sip::Uri::try_from(format!("sip:{};transport=tcp", peer).as_str())?;
    Ok(crate::sip::Request {
        method,
        uri,
        headers: vec![
            Via::new(format!(
                "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-reconnect-{cseq}"
            ))
            .into(),
            CSeq::new(format!("{cseq} {method}")).into(),
            From::new("<sip:alice@127.0.0.1>;tag=reconnect").into(),
            To::new("<sip:bob@127.0.0.1>").into(),
            CallId::new("stream-reconnect@127.0.0.1").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    })
}

async fn final_status(tx: &mut Transaction) -> Option<StatusCode> {
    while let Some(msg) = tx.receive().await {
        if let SipMessage::Response(resp) = msg {
            if resp.status_code.kind() != crate::sip::StatusCodeKind::Provisional {
                return Some(resp.status_code);
            }
        }
    }
    None
}

async fn build_endpoint(t1: Duration) -> Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    tl.add_transport(udp.into());
    let option = EndpointOption {
        t1,
        t1x64: Duration::from_secs(8),
        ..Default::default()
    };
    Ok(EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .with_option(option)
        .build())
}

/// The peer idle-closes the connection the first request opened. A later
/// request to the same peer must be sent over a new connection.
#[tokio::test]
async fn test_request_after_peer_closed_stream_uses_new_connection() -> Result<()> {
    // T1 is long so a Timer A redial cannot hide a stale cached connection:
    // the request has to go out on a new connection straight away.
    let endpoint = build_endpoint(Duration::from_secs(3)).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer = listener.local_addr()?;

    let peer_task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("accept first");
        answer_one(&mut first).await;
        drop(first); // the peer closes the flow after the first transaction
        let (mut second, _) = listener.accept().await.expect("accept second");
        answer_one(&mut second).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });

    let inner = endpoint.inner.clone();
    let client = async move {
        let req = make_options(peer, 1)?;
        let key = TransactionKey::from_request(&req, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, req, inner.clone(), None);
        tx.send().await?;
        assert_eq!(final_status(&mut tx).await, Some(StatusCode::OK));
        let first_connection = tx.connection.clone().expect("first connection");
        drop(tx);

        // The transport layer sees the peer's FIN and marks the flow
        // terminated, so flow affinity (RFC 5626) no longer picks it.
        let token = first_connection.cancel_token().expect("stream token");
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("a flow the peer closed must be marked terminated");

        let req = make_options(peer, 2)?;
        let key = TransactionKey::from_request(&req, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, req, inner.clone(), None);
        tx.send().await?;
        let status = tokio::time::timeout(Duration::from_millis(1500), final_status(&mut tx))
            .await
            .unwrap_or(None);
        Ok::<_, crate::Error>(status)
    };

    let status = tokio::select! {
        r = client => r?,
        _ = endpoint.serve() => panic!("endpoint stopped"),
    };
    peer_task.abort();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "the request after the peer closed the TCP connection must be sent on a new \
         connection and answered, not written to the closed one"
    );
    Ok(())
}

/// A client transaction bound to a stream connection whose write fails must
/// report the failure to the TU at once (a local 503, RFC 3261 §17.1.4 /
/// §8.1.3.1) instead of waiting for Timer B/F: nothing retransmits a request
/// on a reliable transport.
#[tokio::test]
async fn test_send_failure_on_stream_is_reported_at_once() -> Result<()> {
    for method in [Method::Options, Method::Invite] {
        let endpoint = build_endpoint(Duration::from_millis(500)).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let peer = listener.local_addr()?;
        let peer_task = tokio::spawn(async move {
            let (_first, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let target = SipAddr::try_from(&crate::sip::Uri::try_from(
            format!("sip:{};transport=tcp", peer).as_str(),
        )?)?;
        let dead_token = CancellationToken::new();
        let dead =
            SipConnection::Tcp(TcpConnection::connect(&target, Some(dead_token.clone())).await?);
        // A flow whose local side is already shut down: every write fails.
        dead.close().await.ok();

        let inner = endpoint.inner.clone();
        let request = make_request(method, peer, 1)?;
        let client = async move {
            let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
            let mut tx = Transaction::new_client(key, request, inner.clone(), Some(dead));
            tx.send().await?;
            let status = tokio::time::timeout(Duration::from_secs(2), final_status(&mut tx))
                .await
                .unwrap_or(None);
            Ok::<_, crate::Error>(status)
        };

        let status = tokio::select! {
            r = client => r?,
            _ = endpoint.serve() => panic!("endpoint stopped"),
        };
        peer_task.abort();
        assert_eq!(
            status,
            Some(StatusCode::ServiceUnavailable),
            "a failed {method} write on a stream connection must be reported to the TU, \
             not left to time out"
        );
        assert!(
            dead_token.is_cancelled(),
            "the connection whose {method} write failed must be retired"
        );
    }
    Ok(())
}

/// Retiring a dead connection must not drop a newer connection cached for the
/// same peer.
#[tokio::test]
async fn test_retire_keeps_newer_connection_to_same_peer() -> Result<()> {
    let endpoint = build_endpoint(Duration::from_millis(500)).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer = listener.local_addr()?;
    let peer_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let target = SipAddr::try_from(&crate::sip::Uri::try_from(
        format!("sip:{};transport=tcp", peer).as_str(),
    )?)?;
    let old = SipConnection::Tcp(TcpConnection::connect(&target, None).await?);
    let newer = SipConnection::Tcp(TcpConnection::connect(&target, None).await?);
    let transport_layer = &endpoint.inner.transport_layer;
    transport_layer.add_connection(newer.clone());

    transport_layer.retire_connection(&old);
    let (cached, _) = transport_layer.lookup(&target, None).await?;
    assert!(
        cached.is_same_stream(&newer),
        "retiring an old connection must keep the newer one"
    );

    transport_layer.retire_connection(&newer);
    let (fresh, _) = transport_layer.lookup(&target, None).await?;
    assert!(
        !fresh.is_same_stream(&newer),
        "a retired connection must not be returned by lookup"
    );
    peer_task.abort();
    Ok(())
}
