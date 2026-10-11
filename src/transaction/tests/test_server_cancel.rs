//! A CANCEL matching a server INVITE (RFC 3261 §9.2, issue #198): the UAS
//! answers the CANCEL itself, with `CSeq: n CANCEL` and the To tag of the
//! INVITE's response, 200 while the INVITE transaction exists and 481 when
//! nothing matches. Once the INVITE has a final response the CANCEL has no
//! effect on it.

use crate::sip::StatusCode;
use crate::transaction::{transaction::Transaction, TransactionState};
use crate::transport::{tcp_listener::TcpListenerConnection, udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// The far end: a raw UDP socket or TCP stream writing SIP text by hand.
enum Peer {
    Udp(tokio::net::UdpSocket, SocketAddr),
    Tcp(tokio::net::TcpStream),
}

/// A response seen by the peer: "<code> <CSeq>" and its To tag.
type Seen = (String, Option<String>);

impl Peer {
    /// A `method` request with Via branch `branch` (the case name, or
    /// `<case>-ack` for a 2xx ACK) on the case's Call-ID.
    fn request(&self, method: &str, branch: &str, to_tag: Option<&str>) -> String {
        let (me, proto) = match self {
            Peer::Udp(sock, _) => (sock.local_addr().unwrap(), "UDP"),
            Peer::Tcp(stream) => (stream.local_addr().unwrap(), "TCP"),
        };
        let call_id = branch.trim_end_matches("-ack");
        let to_tag = to_tag.map(|t| format!(";tag={t}")).unwrap_or_default();
        format!(
            "{method} sip:bob@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/{proto} {me};branch=z9hG4bK-{branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@127.0.0.1>;tag=a1\r\n\
             To: <sip:bob@127.0.0.1>{to_tag}\r\n\
             Call-ID: cancel-{call_id}\r\n\
             CSeq: 1 {method}\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    async fn send(&mut self, text: &str) {
        match self {
            Peer::Udp(sock, server) => {
                sock.send_to(text.as_bytes(), *server).await.unwrap();
            }
            Peer::Tcp(stream) => stream.write_all(text.as_bytes()).await.unwrap(),
        }
    }

    /// The responses received within `wait`.
    async fn responses(&mut self, wait: Duration) -> Vec<Seen> {
        let mut text = String::new();
        let mut buf = vec![0u8; 65536];
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let read = match self {
                Peer::Udp(sock, _) => timeout_at(deadline, sock.recv_from(&mut buf))
                    .await
                    .map(|(n, _)| n),
                Peer::Tcp(stream) => timeout_at(deadline, stream.read(&mut buf)).await,
            };
            match read {
                Some(n) if n > 0 => text.push_str(&String::from_utf8_lossy(&buf[..n])),
                _ => break,
            }
        }
        // Every message here has an empty body.
        text.split("\r\n\r\n")
            .filter(|m| !m.is_empty())
            .map(|m| {
                let header = |name: &str| m.lines().find_map(|l| l.strip_prefix(name));
                let code = m.split(' ').nth(1).unwrap_or_default();
                let cseq = header("CSeq: ").unwrap_or_default();
                let tag = header("To: ").and_then(|to| to.split_once(";tag=").map(|t| t.1));
                (format!("{code} {cseq}"), tag.map(str::to_string))
            })
            .collect()
    }
}

async fn timeout_at<T>(
    deadline: tokio::time::Instant,
    f: impl std::future::Future<Output = std::io::Result<T>>,
) -> Option<T> {
    tokio::time::timeout_at(deadline, f).await.ok()?.ok()
}

/// Runs `case` against a server endpoint, sending the same CANCEL twice (a
/// retransmission). Returns the responses the peer received from the first
/// CANCEL on, and the To tag of the INVITE's final response, if any, sent
/// before it.
async fn cancel_answers(case: &str, tcp: bool) -> (Vec<Seen>, Option<String>) {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let mut peer = if tcp {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        tl.add_transport(TcpListenerConnection::new(addr, None).await.unwrap().into());
        tl.serve_listens().await.unwrap();
        Peer::Tcp(tokio::net::TcpStream::connect(addr).await.unwrap())
    } else {
        let conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        let addr = conn.get_addr().get_socketaddr().unwrap();
        tl.add_transport(conn.into());
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Peer::Udp(sock, addr)
    };
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(tl)
        .with_cancel_token(token.child_token())
        .build();
    let mut incoming = endpoint.incoming_transactions().unwrap();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { inner.serve().await });

    let mut tx: Option<Transaction> = None;
    let mut final_tag = None;
    if case != "no_invite" {
        peer.send(&peer.request("INVITE", case, None)).await;
        let mut t = incoming.recv().await.unwrap();
        let status = match case {
            "proceeding" | "dropped_proceeding" => StatusCode::Ringing,
            "accepted" | "acked" => StatusCode::OK,
            _ => StatusCode::TemporarilyUnavailable,
        };
        // A final reply adds a To tag (`reply_with`).
        t.reply(status).await.unwrap();
        let first = peer.responses(Duration::from_millis(100)).await;
        if !matches!(case, "proceeding" | "dropped_proceeding") {
            final_tag = first[0].1.clone();
            assert!(final_tag.is_some(), "{case}: a final response has a To tag");
        }
        if matches!(case, "acked" | "confirmed") {
            let branch = if case == "acked" {
                format!("{case}-ack")
            } else {
                case.into()
            };
            let ack = peer.request("ACK", &branch, final_tag.as_deref());
            peer.send(&ack).await;
            let ack = timeout(Duration::from_secs(1), t.receive()).await.unwrap();
            assert!(ack.is_some(), "{case}: the ACK must reach the TU");
        }
        if case == "acked" {
            // The ACK ended the transaction; only its cached 2xx remains.
            assert_eq!(t.state, TransactionState::Terminated);
        } else if !case.starts_with("dropped") {
            tx = Some(t);
        }
    }
    let state = tx.as_ref().map(|t| t.state.clone());

    // The CANCEL has the INVITE's (untagged) To (RFC 3261 §9.1).
    let cancel = peer.request("CANCEL", case, None);
    peer.send(&cancel).await;
    if case == "proceeding" {
        let t = tx.as_mut().unwrap();
        let msg = timeout(Duration::from_secs(1), t.receive()).await.unwrap();
        let msg = msg.unwrap().to_string();
        assert!(
            msg.starts_with("CANCEL "),
            "proceeding: CANCEL must reach the TU"
        );
        t.reply(StatusCode::RequestTerminated).await.unwrap();
    }
    peer.send(&cancel).await;
    if let Some(t) = tx.as_mut() {
        // Drive the transaction for the CANCEL (and Timer G over UDP).
        let delivered = timeout(Duration::from_millis(700), t.receive()).await;
        assert!(
            delivered.is_err(),
            "{case}: a CANCEL after a final response must not reach the TU"
        );
        if case != "proceeding" {
            let now = Some(t.state.clone());
            assert_eq!(now, state, "{case}: the CANCEL must not change the INVITE");
        }
    }
    let got = peer.responses(Duration::from_millis(300)).await;
    if case == "accepted" {
        // The 2xx still awaits its ACK, which still ends the transaction.
        let t = tx.as_mut().unwrap();
        let ack = peer.request("ACK", "accepted-ack", final_tag.as_deref());
        peer.send(&ack).await;
        let ack = timeout(Duration::from_secs(1), t.receive()).await.unwrap();
        assert!(
            ack.is_some(),
            "accepted: the ACK must reach the TU after the CANCEL"
        );
        assert_eq!(t.state, TransactionState::Terminated);
    }
    token.cancel();
    (got, final_tag)
}

#[tokio::test]
async fn test_cancel_answers_by_invite_state() {
    for tcp in [false, true] {
        for (case, cancel_answer) in [
            ("accepted", "200"),
            ("acked", "200"),
            ("proceeding", "200"),
            ("completed", "200"),
            ("confirmed", "200"),
            ("dropped_completed", "200"),
            ("dropped_proceeding", "481"),
            ("no_invite", "481"),
        ] {
            let (got, final_tag) = cancel_answers(case, tcp).await;
            let row = format!("{case} (tcp: {tcp}): {got:?}");
            let (cancels, invites): (Vec<_>, Vec<_>) =
                got.iter().partition(|r| r.0.ends_with(" CANCEL"));
            let codes: Vec<_> = cancels.iter().map(|r| r.0.as_str()).collect();
            let expected = format!("{cancel_answer} 1 CANCEL");
            assert_eq!(codes, [expected.as_str(); 2], "{row}");
            // Responses to the INVITE: the 487 to a cancelled INVITE, the
            // non-2xx final retransmitted over UDP (Timer G) and the 2xx
            // retransmitted until its ACK. Never one answering a CANCEL.
            let expected_invite = match case {
                "proceeding" => Some("487 1 INVITE"),
                "completed" if !tcp => Some("480 1 INVITE"),
                "accepted" => Some("200 1 INVITE"),
                _ => None,
            };
            let first_invite = invites.first().map(|r| r.0.as_str());
            assert_eq!(first_invite, expected_invite, "{row}");
            assert!(invites
                .iter()
                .all(|r| Some(r.0.as_str()) == expected_invite));
            // The 200 to the CANCEL has the To tag of the INVITE's last
            // response (§9.2): in Proceeding the 180's (none here) for the
            // first CANCEL and the 487's for its retransmission.
            if case == "proceeding" {
                assert_eq!(cancels[0].1, None, "{row}");
                assert_eq!(cancels[1].1, invites[0].1, "{row}");
            } else if final_tag.is_some() {
                assert!(cancels.iter().all(|r| r.1 == final_tag), "{row}");
            }
        }
    }
}
