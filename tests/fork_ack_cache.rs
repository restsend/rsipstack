//! Retransmissions from an earlier answered fork must reuse that fork's ACK.
use rsipstack::{
    sip::{Header, HeadersExt, Method, Request, Response, SipMessage, StatusCode},
    transaction::{
        endpoint::EndpointOption,
        key::{TransactionKey, TransactionRole},
        transaction::Transaction,
        EndpointBuilder,
    },
    transport::{udp::UdpConnection, TransportLayer},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(2);

async fn receive(socket: &UdpSocket, method: Method) -> Result<(Request, SocketAddr)> {
    tokio::time::timeout(WAIT, async {
        let mut buf = [0; 8192];
        loop {
            let (n, source) = socket.recv_from(&mut buf).await?;
            if let SipMessage::Request(r) = SipMessage::try_from(&buf[..n])? {
                if r.method == method {
                    return Ok((r, source));
                }
            }
        }
    })
    .await?
}

struct Stop(CancellationToken);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn alternating_forks(drop_before_retransmit: bool) -> Result<()> {
    let stop = Stop(CancellationToken::new());
    let transport = TransportLayer::new(stop.0.clone());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, Some(stop.0.clone()))
        .await?;
    transport.add_transport(udp.into());
    let endpoint = Arc::new(
        EndpointBuilder::new()
            .with_transport_layer(transport)
            .with_cancel_token(stop.0.clone())
            .with_option(EndpointOption {
                t1x64: Duration::from_millis(1000),
                ..Default::default()
            })
            .build(),
    );
    let serving = endpoint.clone();
    tokio::spawn(async move { serving.serve().await });
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let invite: Request = format!("INVITE sip:callee@{} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-cache\r\nFrom: <sip:caller@example.com>;tag=local\r\nTo: <sip:callee@example.com>\r\nCall-ID: forks\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", a.local_addr()?).as_str().try_into()?;
    let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key.clone(), invite, endpoint.inner.clone(), None);
    tx.send().await?;
    let (invite, source) = receive(&a, Method::Invite).await?;
    let response = |tag: &str, address: SocketAddr| -> Response {
        let mut response = endpoint.inner.make_response(&invite, StatusCode::OK, None);
        response.headers.unique_push(Header::To(
            format!("<sip:callee@example.com>;tag={tag}").into(),
        ));
        response
            .headers
            .push(Header::Contact(format!("<sip:{tag}@{address}>").into()));
        response.headers.push(Header::RecordRoute(
            format!("<sip:proxy-{tag}@{address};lr>").into(),
        ));
        response
    };
    let responses = [
        response("a", a.local_addr()?),
        response("b", b.local_addr()?),
    ];
    let sockets = [&a, &b];
    let mut original_acks = Vec::new();
    let mut deadline = None;
    for i in 0..2 {
        if i == 0 {
            // Preserve an application-supplied SDP answer, not only headers.
            let mut ack = endpoint.inner.make_ack(&invite, &responses[i])?;
            ack.body = b"v=0\r\ns=answer-a\r\n".to_vec();
            ack.headers
                .unique_push(Header::ContentType("application/sdp".into()));
            ack.headers
                .unique_push(Header::ContentLength((ack.body.len() as u32).into()));
            tx.last_ack = Some(ack);
        }
        a.send_to(responses[i].to_string().as_bytes(), source)
            .await?;
        tokio::time::timeout(WAIT, tx.receive())
            .await?
            .ok_or("transaction ended")?;
        let (ack, _) = receive(sockets[i], Method::Ack).await?;
        assert_eq!(
            ack.to_header()?.tag()?.unwrap().value(),
            if i == 0 { "a" } else { "b" }
        );
        assert_eq!(
            ack.uri.to_string(),
            format!(
                "sip:{}@{}",
                if i == 0 { "a" } else { "b" },
                sockets[i].local_addr()?
            )
        );
        original_acks.push(ack);
        if i == 0 {
            deadline = tx.timer_m;
        }
        assert_eq!(tx.timer_m, deadline, "fork must not restart Timer M");
    }
    let mut tx = Some(tx);
    if drop_before_retransmit {
        drop(tx.take());
    }
    for i in [0, 1, 0, 1] {
        a.send_to(responses[i].to_string().as_bytes(), source)
            .await?;
        if let Some(tx) = &mut tx {
            tokio::time::timeout(WAIT, tx.receive())
                .await?
                .ok_or("transaction ended")?;
            assert_eq!(
                tx.timer_m, deadline,
                "retransmission must not restart Timer M"
            );
        }
        let (ack, _) = receive(sockets[i], Method::Ack).await?;
        assert_eq!(
            ack.to_string(),
            original_acks[i].to_string(),
            "fork {i} must reuse its exact ACK, including Via and Route"
        );
    }
    if drop_before_retransmit {
        // Once its owner drops the transaction, an unknown fork must never
        // receive another fork's cached ACK with only the To tag rewritten.
        let unknown = response("unknown", a.local_addr()?);
        a.send_to(unknown.to_string().as_bytes(), source).await?;
        let mut bytes = [0; 8192];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), a.recv_from(&mut bytes))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!endpoint.inner.finished_transactions.contains_key(&key));
        a.send_to(responses[0].to_string().as_bytes(), source)
            .await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), a.recv_from(&mut bytes))
                .await
                .is_err(),
            "expired ACK cache still answered"
        );
    }
    Ok(())
}

#[tokio::test]
async fn alternating_forks_keep_exact_acks_while_accepted() -> Result<()> {
    alternating_forks(false).await
}
#[tokio::test]
async fn alternating_forks_keep_exact_acks_after_owner_drops_transaction() -> Result<()> {
    alternating_forks(true).await
}
