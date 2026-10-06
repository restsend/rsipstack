//! RFC 3261 §13.3.1.4: a UAS retransmits its 2xx to an INVITE (T1, doubling)
//! until the ACK arrives. If no ACK arrives within 64*T1, the session SHOULD
//! be ended with a BYE. The dialog must not stay in `WaitAck` forever.
use crate::dialog::{
    dialog::{Dialog, DialogState, DialogStateReceiver, TerminatedReason},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, SipMessage};
use crate::transaction::endpoint::EndpointOption;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "uas-ack-timeout-test";
const FROM_TAG: &str = "uac-tag";
const T1: Duration = Duration::from_millis(20);
// Same T4/T1 ratio as the RFC defaults (5 s / 500 ms).
const T4: Duration = Duration::from_millis(200);
const T1X64: Duration = Duration::from_millis(64 * 20);

/// A raw UAC peer.
struct Peer {
    socket: UdpSocket,
    uas: SocketAddr,
}

impl Peer {
    async fn send(&self, msg: String) {
        self.socket.send_to(msg.as_bytes(), self.uas).await.unwrap();
    }

    async fn send_request(&self, method: Method, cseq: u32, to_tag: Option<&str>) {
        let addr = self.socket.local_addr().unwrap();
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@{}>;tag={tag}", self.uas),
            None => format!("<sip:bob@{}>", self.uas),
        };
        let branch = match method {
            Method::Ack => "z9hG4bK-ack".to_string(),
            _ => format!("z9hG4bK-{method}-{cseq}"),
        };
        self.send(format!(
            "{method} sip:bob@{uas} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@{addr}>;tag={FROM_TAG}\r\n\
             To: {to}\r\n\
             Call-ID: {CALL_ID}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@{addr}>\r\n\
             Content-Length: 0\r\n\r\n",
            uas = self.uas,
        ))
        .await;
    }

    /// Everything the UAS sends until `deadline`, with arrival times. A BYE
    /// is answered with 200 OK.
    async fn collect(&self, deadline: Instant) -> Vec<(Instant, SipMessage)> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return out;
            }
            let Ok(Ok((len, _))) =
                tokio::time::timeout(deadline - now, self.socket.recv_from(&mut buf)).await
            else {
                return out;
            };
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            let Ok(msg) = SipMessage::try_from(text) else {
                continue;
            };
            if let SipMessage::Request(req) = &msg {
                if req.method == Method::Bye {
                    let resp = format!(
                        "SIP/2.0 200 OK\r\n\
                         Via: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\n\
                         Content-Length: 0\r\n\r\n",
                        req.via_header().unwrap().value(),
                        req.from_header().unwrap().value(),
                        req.to_header().unwrap().value(),
                        req.call_id_header().unwrap().value(),
                        req.cseq_header().unwrap().value(),
                    );
                    self.send(resp).await;
                }
            }
            out.push((Instant::now(), msg));
        }
    }
}

/// A UAS endpoint with short timers, running the usual incoming-transaction
/// loop.
fn short_timers() -> EndpointOption {
    EndpointOption {
        t1: T1,
        t4: T4,
        t1x64: T1X64,
        ..Default::default()
    }
}

async fn setup(
    token: &CancellationToken,
    option: EndpointOption,
) -> crate::Result<(DialogStateReceiver, UnboundedReceiver<InviteDialog>, Peer)> {
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uas: SocketAddr = udp.get_addr().get_socketaddr()?;
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .with_option(option)
        .build();
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let mut incoming = endpoint.incoming_transactions()?;
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let (state_sender, states) = unbounded_channel();
    let (dialog_sender, dialogs) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            let has_to_tag = tx.original.to_header().unwrap().tag().unwrap().is_some();
            let dialog = if has_to_tag {
                dialog_layer.match_dialog(&tx)
            } else if tx.original.method == Method::Invite {
                let dialog = dialog_layer
                    .get_or_create_server_invite(&tx, state_sender.clone(), None, None)
                    .expect("server dialog");
                dialog_sender.send(dialog.clone()).unwrap();
                Some(Dialog::Invite(dialog))
            } else {
                None
            };
            if let Some(mut dialog) = dialog {
                tokio::spawn(async move {
                    let _ = dialog.handle(&mut tx).await;
                });
            }
        }
    });

    let peer = Peer {
        socket: UdpSocket::bind("127.0.0.1:0").await?,
        uas,
    };
    Ok((states, dialogs, peer))
}

fn is_invite_2xx(msg: &SipMessage) -> bool {
    match msg {
        SipMessage::Response(resp) => {
            resp.status_code.code() == 200
                && resp.cseq_header().unwrap().method().unwrap() == Method::Invite
        }
        _ => false,
    }
}

fn is_2xx_to(msg: &SipMessage, cseq: u32) -> bool {
    is_invite_2xx(msg)
        && matches!(msg, SipMessage::Response(resp) if resp.cseq_header().unwrap().seq().unwrap() == cseq)
}

/// The BYE among `messages`: its arrival time, after checking it belongs to
/// this dialog (Call-ID and both tags).
fn bye_of_dialog(messages: &[(Instant, SipMessage)], local_tag: &str) -> Instant {
    let (at, bye) = messages
        .iter()
        .find_map(|(at, m)| match m {
            SipMessage::Request(req) if req.method == Method::Bye => Some((*at, req)),
            _ => None,
        })
        .expect("the UAS must send a BYE when the ACK never arrives");
    assert_eq!(bye.call_id_header().unwrap().value(), CALL_ID);
    assert_eq!(
        bye.from_header().unwrap().tag().unwrap().unwrap().value(),
        local_tag,
        "the BYE must come from the dialog's local tag"
    );
    assert_eq!(
        bye.to_header().unwrap().tag().unwrap().unwrap().value(),
        FROM_TAG
    );
    at
}

fn terminated_reason(states: &mut DialogStateReceiver) -> Option<TerminatedReason> {
    let mut terminated = None;
    while let Ok(state) = states.try_recv() {
        if let DialogState::Terminated(_, reason) = state {
            terminated = Some(reason);
        }
    }
    terminated
}

#[tokio::test]
async fn test_unacked_2xx_is_retransmitted_then_the_session_is_ended() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    let accepted = Instant::now();
    dialog.accept(None, None)?;

    // The peer never ACKs.
    let messages = peer.collect(accepted + T1X64 * 2).await;

    let oks: Vec<Instant> = messages
        .iter()
        .filter(|(_, m)| is_invite_2xx(m))
        .map(|(at, _)| *at)
        .collect();
    assert!(
        oks.len() >= 6,
        "the 2xx must be retransmitted until 64*T1, got {} transmissions",
        oks.len()
    );
    let last = *oks.last().unwrap();
    assert!(
        last - accepted > T4 * 2 && last - accepted >= T1X64 / 2,
        "2xx retransmissions must go on until 64*T1, not stop at T4, last one after {:?}",
        last - accepted
    );
    let gaps: Vec<Duration> = oks.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.windows(2).all(|g| g[1] + T1 / 2 >= g[0]),
        "retransmission intervals must not shrink: {gaps:?}"
    );

    // The dialog ends, with a reason the application can tell apart.
    let mut terminated = None;
    while let Ok(state) = states.try_recv() {
        if let DialogState::Terminated(_, reason) = state {
            terminated = Some(reason);
        }
    }
    assert!(
        matches!(terminated, Some(TerminatedReason::Timeout)),
        "a 2xx without ACK for 64*T1 must terminate the dialog with Timeout, got {terminated:?}, state {}",
        dialog.state()
    );

    // The session is ended with a BYE for this dialog, sent no earlier than
    // 64*T1 after the 2xx.
    let ok_to_tag = messages
        .iter()
        .find_map(|(_, m)| match m {
            SipMessage::Response(resp) if is_invite_2xx(m) => Some(
                resp.to_header()
                    .unwrap()
                    .tag()
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_string(),
            ),
            _ => None,
        })
        .unwrap();
    let (bye_at, bye) = messages
        .iter()
        .find_map(|(at, m)| match m {
            SipMessage::Request(req) if req.method == Method::Bye => Some((*at, req)),
            _ => None,
        })
        .expect("the UAS must send a BYE when the ACK never arrives");
    assert_eq!(bye.call_id_header()?.value(), CALL_ID);
    assert_eq!(
        bye.from_header()?.tag()?.unwrap().value(),
        ok_to_tag,
        "the BYE must come from the dialog's local tag"
    );
    assert_eq!(bye.to_header()?.tag()?.unwrap().value(), FROM_TAG);
    assert!(
        bye_at - accepted >= T1X64 - T1,
        "the BYE must not be sent before 64*T1, sent after {:?}",
        bye_at - accepted
    );
    assert!(
        !oks.iter().any(|at| *at > bye_at),
        "no 2xx may be retransmitted after the BYE"
    );

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_acked_2xx_stops_retransmitting_and_confirms() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    let first = peer.collect(Instant::now() + T1 * 2).await;
    let to_tag = first
        .iter()
        .find_map(|(_, m)| match m {
            SipMessage::Response(resp) if is_invite_2xx(m) => Some(
                resp.to_header()
                    .unwrap()
                    .tag()
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_string(),
            ),
            _ => None,
        })
        .expect("the 2xx");
    peer.send_request(Method::Ack, 1, Some(&to_tag)).await;
    let acked = Instant::now();

    let after = peer.collect(acked + T1X64 * 2).await;
    assert!(
        !after
            .iter()
            .any(|(at, m)| is_invite_2xx(m) && *at > acked + T1 * 4),
        "no 2xx may be retransmitted once the ACK arrived"
    );
    assert!(
        !after.iter().any(|(_, m)| matches!(
            m,
            SipMessage::Request(req) if req.method == Method::Bye
        )),
        "an ACKed call must not be ended"
    );
    let mut seen = Vec::new();
    while let Ok(state) = states.try_recv() {
        seen.push(state.to_string());
    }
    assert!(
        seen.iter().any(|s| s.ends_with("(Confirmed)"))
            && !seen.iter().any(|s| s.ends_with("(Terminated)")),
        "the dialog must be confirmed and stay up, got {seen:?}"
    );
    assert!(dialog.state().is_confirmed());

    token.cancel();
    Ok(())
}

/// The interval between 2xx retransmissions doubles up to T2, then stays
/// there until 64*T1 (RFC 3261 §13.3.1.4, §17.2.1). Checked on the Timer G
/// the server INVITE transaction schedules, not on wall-clock arrival times
/// (which a loaded machine stretches).
#[tokio::test]
async fn test_2xx_retransmission_interval_doubles_up_to_t2() -> crate::Result<()> {
    use crate::transaction::{
        key::{TransactionKey, TransactionRole},
        transaction::{Transaction, TransactionEvent},
        TransactionState, TransactionTimer,
    };
    let t1 = Duration::from_millis(20);
    let t2 = t1 * 4;
    let token = CancellationToken::new();
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(TransportLayer::new(token.child_token()))
        .with_option(EndpointOption {
            t1,
            t2,
            ..short_timers()
        })
        .build();
    // The endpoint is not served: no timer fires on its own.
    let invite = crate::sip::Request::try_from(
        "INVITE sip:bob@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK-timer-g\r\n\
         From: <sip:alice@127.0.0.1>;tag=uac-tag\r\n\
         To: <sip:bob@127.0.0.1>\r\n\
         Call-ID: timer-g\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n",
    )?;
    let key = TransactionKey::from_request(&invite, TransactionRole::Server)?;
    let mut tx = Transaction::new_server(key.clone(), invite, endpoint.inner.clone(), None);
    tx.state = TransactionState::Completed;

    let mut scheduled = Vec::new();
    let mut duration = t1;
    for _ in 0..6 {
        tx.tu_sender
            .send(TransactionEvent::Timer(TransactionTimer::TimerG(
                key.clone(),
                duration,
            )))
            .unwrap();
        // `receive` handles the timer, then waits for a message that never
        // comes.
        let _ = tokio::time::timeout(Duration::from_millis(20), tx.receive()).await;
        let next = tx.timer_g.take().expect("Timer G is restarted");
        let Some(TransactionTimer::TimerG(_, next)) = endpoint.inner.timers.cancel(next) else {
            panic!("the restarted timer is Timer G");
        };
        scheduled.push(next);
        duration = next;
    }
    assert_eq!(scheduled, vec![t1 * 2, t2, t2, t2, t2, t2]);
    token.cancel();
    Ok(())
}

/// The same applies to a re-INVITE: an established call whose re-INVITE 2xx
/// is never ACKed is ended with a BYE (RFC 3261 §14.2 defers to §13.3.1.4).
#[tokio::test]
async fn test_unacked_reinvite_2xx_ends_the_session() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;
    let first = peer.collect(Instant::now() + T1 * 2).await;
    let local_tag = first
        .iter()
        .find_map(|(_, m)| match m {
            SipMessage::Response(resp) if is_2xx_to(m, 1) => Some(
                resp.to_header()
                    .unwrap()
                    .tag()
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_string(),
            ),
            _ => None,
        })
        .expect("the 2xx");
    peer.send_request(Method::Ack, 1, Some(&local_tag)).await;
    loop {
        let state = tokio::time::timeout(Duration::from_secs(2), states.recv())
            .await
            .expect("timeout waiting for the call to be confirmed")
            .expect("state channel closed");
        if matches!(state, DialogState::Confirmed(..)) {
            break;
        }
    }

    // The call is up; the peer sends a re-INVITE and the application
    // answers it.
    peer.send_request(Method::Invite, 2, Some(&local_tag)).await;
    let handle = loop {
        let state = tokio::time::timeout(Duration::from_secs(2), states.recv())
            .await
            .expect("timeout waiting for the re-INVITE")
            .expect("state channel closed");
        if let DialogState::Updated(_, _, handle) = state {
            break handle;
        }
    };
    let answered = Instant::now();
    handle.reply(crate::sip::StatusCode::OK).await.ok();

    // The peer never ACKs the re-INVITE's 2xx.
    let messages = peer.collect(answered + T1X64 * 2).await;
    let oks: Vec<Instant> = messages
        .iter()
        .filter(|(_, m)| is_2xx_to(m, 2))
        .map(|(at, _)| *at)
        .collect();
    assert!(
        oks.len() >= 6 && *oks.last().unwrap() - answered >= T1X64 / 2,
        "the re-INVITE 2xx must be retransmitted until 64*T1, got {} transmissions",
        oks.len()
    );
    assert!(
        matches!(
            terminated_reason(&mut states),
            Some(TerminatedReason::Timeout)
        ),
        "a re-INVITE 2xx without ACK must terminate the dialog with Timeout, state {}",
        dialog.state()
    );
    let bye_at = bye_of_dialog(&messages, &local_tag);
    assert!(bye_at - answered >= T1X64 - T1);

    token.cancel();
    Ok(())
}

async fn wait_confirmed(states: &mut DialogStateReceiver) {
    loop {
        let state = tokio::time::timeout(Duration::from_secs(2), states.recv())
            .await
            .expect("timeout waiting for the call to be confirmed")
            .expect("state channel closed");
        if matches!(state, DialogState::Confirmed(..)) {
            return;
        }
    }
}

/// Read SIP messages (no bodies) from `stream` until `deadline`.
async fn read_tcp_messages(
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Vec<(Instant, SipMessage)> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&buf[..end + 4]).to_string();
            buf.drain(..end + 4);
            if let Ok(msg) = SipMessage::try_from(text.as_str()) {
                out.push((Instant::now(), msg));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return out;
        }
        match tokio::time::timeout(deadline - now, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return out,
        }
    }
}

/// RFC 3261 §13.3.1.4: the UAS core retransmits a 2xx on every transport,
/// reliable ones included (the 2xx can be lost at a later UDP hop), until
/// the ACK arrives.
#[tokio::test]
async fn test_2xx_over_tcp_is_retransmitted_until_the_ack() -> crate::Result<()> {
    use crate::transport::tcp_listener::TcpListenerConnection;
    use tokio::io::AsyncWriteExt;
    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.child_token());
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let uas: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let tcp = TcpListenerConnection::new(uas, None).await?;
    transport_layer.add_transport(tcp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .with_option(short_timers())
        .build();
    endpoint.inner.transport_layer.serve_listens().await?;
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let mut incoming = endpoint.incoming_transactions()?;
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let (state_sender, mut states) = unbounded_channel();
    let (dialog_sender, mut dialogs) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            let has_to_tag = tx.original.to_header().unwrap().tag().unwrap().is_some();
            let dialog = if has_to_tag {
                dialog_layer.match_dialog(&tx)
            } else if tx.original.method == Method::Invite {
                let dialog = dialog_layer
                    .get_or_create_server_invite(&tx, state_sender.clone(), None, None)
                    .expect("server dialog");
                dialog_sender.send(dialog.clone()).unwrap();
                Some(Dialog::Invite(dialog))
            } else {
                None
            };
            if let Some(mut dialog) = dialog {
                tokio::spawn(async move {
                    let _ = dialog.handle(&mut tx).await;
                });
            }
        }
    });

    let mut stream = tokio::net::TcpStream::connect(uas).await?;
    let local = stream.local_addr()?;
    let request = |method: Method, cseq: u32, to_tag: Option<&str>| {
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@{uas}>;tag={tag}"),
            None => format!("<sip:bob@{uas}>"),
        };
        format!(
            "{method} sip:bob@{uas};transport=tcp SIP/2.0\r\n\
             Via: SIP/2.0/TCP {local};branch=z9hG4bK-tcp-{method}-{cseq}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@{local}>;tag={FROM_TAG}\r\n\
             To: {to}\r\n\
             Call-ID: {CALL_ID}-tcp\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@{local};transport=tcp>\r\n\
             Content-Length: 0\r\n\r\n"
        )
    };
    stream
        .write_all(request(Method::Invite, 1, None).as_bytes())
        .await?;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    // No ACK yet: the 2xx is retransmitted (T1, 2*T1, 4*T1, ...).
    let mut buf = Vec::new();
    let before_ack = read_tcp_messages(&mut stream, &mut buf, Instant::now() + T1 * 12).await;
    let oks: Vec<_> = before_ack.iter().filter(|(_, m)| is_2xx_to(m, 1)).collect();
    assert!(
        oks.len() >= 3,
        "a 2xx over TCP must be retransmitted until the ACK, got {} transmissions",
        oks.len()
    );
    let SipMessage::Response(ok) = &oks[0].1 else {
        unreachable!()
    };
    let to_tag = ok.to_header()?.tag()?.unwrap().value().to_string();

    stream
        .write_all(request(Method::Ack, 1, Some(&to_tag)).as_bytes())
        .await?;
    let acked = Instant::now();
    wait_confirmed(&mut states).await;
    let after_ack = read_tcp_messages(&mut stream, &mut buf, acked + T1 * 30).await;
    assert!(
        !after_ack
            .iter()
            .any(|(at, m)| is_invite_2xx(m) && *at > acked + T1 * 2),
        "the ACK must stop the 2xx retransmissions"
    );
    assert!(
        !after_ack.iter().any(|(_, m)| matches!(
            m,
            SipMessage::Request(req) if req.method == Method::Bye
        )),
        "an ACKed call must not be ended"
    );
    assert!(dialog.state().is_confirmed());
    token.cancel();
    Ok(())
}

/// An ACK whose CSeq does not match the INVITE (RFC 3261 §13.2.2.4: e.g. a
/// delayed ACK of an earlier re-INVITE) must not confirm the server INVITE
/// transaction: the 2xx keeps being retransmitted, and a later ACK with the
/// matching CSeq still confirms the dialog — without any BYE.
#[tokio::test]
async fn test_stale_ack_is_ignored_and_a_valid_ack_still_confirms() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    // The first 200 OK; remember its To tag for the ACKs.
    let mut buf = vec![0u8; 4096];
    let to_tag = loop {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_secs(2), peer.socket.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the first 200");
        };
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
            if resp.status_code.code() == 200 {
                break resp
                    .to_header()?
                    .tag()?
                    .expect("the 200 must carry the local tag")
                    .value()
                    .to_string();
            }
        }
    };

    // An ACK with a stale CSeq must be ignored: the 2xx keeps being
    // retransmitted (Timer G must not stop).
    peer.send_request(Method::Ack, 99, Some(&to_tag)).await;
    let stale_at = Instant::now();
    let retransmitted_after_stale = loop {
        let now = Instant::now();
        if now >= stale_at + T1X64 / 2 {
            break None;
        }
        let Ok(Ok((len, _))) =
            tokio::time::timeout(stale_at + T1X64 / 2 - now, peer.socket.recv_from(&mut buf)).await
        else {
            break None;
        };
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
            if resp.status_code.code() == 200 {
                break Some(Instant::now());
            }
        }
    };
    let retransmitted_after_stale = retransmitted_after_stale.expect(
        "a stale ACK must not confirm the transaction: the 2xx must keep being retransmitted",
    );
    assert!(
        retransmitted_after_stale >= stale_at,
        "the 2xx retransmission must come after the stale ACK"
    );
    assert!(
        !matches!(dialog.state(), DialogState::Confirmed(_, _)),
        "a stale ACK must not confirm the dialog, got {}",
        dialog.state()
    );

    // The ACK with the matching CSeq confirms; no BYE may follow.
    peer.send_request(Method::Ack, 1, Some(&to_tag)).await;
    let messages = peer
        .collect(Instant::now() + T1X64 + Duration::from_millis(200))
        .await;
    assert!(
        !messages.iter().any(|(_, m)| matches!(
            m,
            SipMessage::Request(req) if req.method == Method::Bye
        )),
        "a confirmed dialog must not be ended with a BYE"
    );
    assert!(
        dialog.state().is_confirmed(),
        "the valid ACK must confirm the dialog, got {}",
        dialog.state()
    );
    assert!(
        !states
            .try_recv()
            .is_ok_and(|s| matches!(s, DialogState::Terminated(_, _))),
        "the dialog must not have been terminated"
    );
    token.cancel();
    Ok(())
}

/// RFC 3261 §13.2.2.4: the ACK of a 2xx carries the CSeq number of its
/// INVITE. Over UDP the ACK of a re-INVITE can arrive after the next
/// re-INVITE on the dialog: it must still stop its own 2xx, and the newer
/// re-INVITE must still wait for its own ACK.
#[tokio::test]
async fn test_late_ack_of_an_earlier_reinvite_reaches_its_own_transaction() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;
    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;
    let first = peer.collect(Instant::now() + T1 * 2).await;
    let Some((_, SipMessage::Response(ok))) = first.iter().find(|(_, m)| is_2xx_to(m, 1)) else {
        panic!("the 2xx");
    };
    let local_tag = ok.to_header()?.tag()?.unwrap().value().to_string();
    peer.send_request(Method::Ack, 1, Some(&local_tag)).await;
    wait_confirmed(&mut states).await;

    // re-INVITE 2 and 3 are answered; the ACK of 2 arrives after re-INVITE 3.
    let mut answered = None;
    for cseq in [2, 3] {
        peer.send_request(Method::Invite, cseq, Some(&local_tag))
            .await;
        let handle = loop {
            let state = tokio::time::timeout(Duration::from_secs(2), states.recv())
                .await
                .expect("timeout waiting for the re-INVITE")
                .expect("state channel closed");
            if let DialogState::Updated(_, _, handle) = state {
                break handle;
            }
        };
        answered.get_or_insert(Instant::now());
        handle.reply(crate::sip::StatusCode::OK).await.ok();
        // The next request follows this 2xx on the wire.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !peer
            .collect(Instant::now() + T1)
            .await
            .iter()
            .any(|(_, m)| is_2xx_to(m, cseq))
        {
            assert!(
                Instant::now() < deadline,
                "timeout waiting for the 2xx to {cseq}"
            );
        }
    }
    peer.send_request(Method::Ack, 2, Some(&local_tag)).await;
    let acked_2 = Instant::now();
    let messages = peer.collect(acked_2 + T1 * 16).await;
    assert!(
        !messages
            .iter()
            .any(|(at, m)| is_2xx_to(m, 2) && *at > acked_2 + T1 * 4),
        "the late ACK of CSeq 2 must stop the retransmissions of its 2xx"
    );
    assert!(
        messages
            .iter()
            .any(|(at, m)| is_2xx_to(m, 3) && *at > acked_2),
        "the ACK of CSeq 2 must not stop the 2xx to CSeq 3"
    );

    peer.send_request(Method::Ack, 3, Some(&local_tag)).await;
    let acked_3 = Instant::now();
    let messages = peer.collect(answered.unwrap() + T1X64 + T1 * 10).await;
    assert!(
        !messages
            .iter()
            .any(|(at, m)| is_invite_2xx(m) && *at > acked_3 + T1 * 4),
        "no 2xx may be retransmitted once both are ACKed"
    );
    assert!(
        !messages.iter().any(|(_, m)| matches!(
            m,
            SipMessage::Request(req) if req.method == Method::Bye
        )),
        "an ACKed call must not be ended"
    );
    assert!(terminated_reason(&mut states).is_none());
    assert!(dialog.state().is_confirmed());
    token.cancel();
    Ok(())
}

/// Regression guard for the Accepted-state ACK handling: a re-INVITE whose
/// 2xx IS acknowledged must never trip the no-ACK timeout path — the dialog
/// stays confirmed and no BYE goes out.
#[tokio::test]
async fn test_acked_reinvite_sends_no_bye() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token, short_timers()).await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    // First 200 OK and its ACK.
    let mut buf = vec![0u8; 4096];
    let to_tag = loop {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_secs(2), peer.socket.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the first 200");
        };
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
            if resp.status_code.code() == 200 {
                break resp
                    .to_header()?
                    .tag()?
                    .expect("the 200 must carry the local tag")
                    .value()
                    .to_string();
            }
        }
    };
    peer.send_request(Method::Ack, 1, Some(&to_tag)).await;

    // A re-INVITE answered and ACKed: the session must go on.
    peer.send_request(Method::Invite, 2, Some(&to_tag)).await;
    let handle = loop {
        let state = tokio::time::timeout(Duration::from_secs(2), states.recv())
            .await
            .expect("timeout waiting for the re-INVITE")
            .expect("state channel closed");
        if let DialogState::Updated(_, _, handle) = state {
            break handle;
        }
    };
    let reinvite_answered = Instant::now();
    handle.reply(crate::sip::StatusCode::OK).await.ok();
    let mut got_reinvite_2xx = false;
    while !got_reinvite_2xx {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_secs(2), peer.socket.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the re-INVITE's 200");
        };
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
            if resp.status_code.code() == 200 {
                got_reinvite_2xx = true;
            }
        }
    }
    peer.send_request(Method::Ack, 2, Some(&to_tag)).await;

    // No BYE within 64*T1 after the re-INVITE's ACK.
    let messages = peer
        .collect(reinvite_answered + T1X64 + Duration::from_millis(200))
        .await;
    assert!(
        !messages.iter().any(|(_, m)| matches!(
            m,
            SipMessage::Request(req) if req.method == Method::Bye
        )),
        "a confirmed re-INVITE must not end the session with a BYE"
    );
    assert!(
        dialog.state().is_confirmed(),
        "the dialog must stay confirmed after the re-INVITE's ACK, got {}",
        dialog.state()
    );
    while let Ok(state) = states.try_recv() {
        assert!(
            !matches!(state, DialogState::Terminated(_, _)),
            "the dialog must not have been terminated"
        );
    }
    token.cancel();
    Ok(())
}
