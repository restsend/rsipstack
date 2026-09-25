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

/// The interval between 2xx retransmissions doubles up to T2, then stays there
/// until 64*T1 (RFC 3261 §13.3.1.4).
#[tokio::test]
async fn test_unacked_2xx_retransmission_interval_is_capped_at_t2() -> crate::Result<()> {
    let t2 = T1 * 4;
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(
        &token,
        EndpointOption {
            t2,
            ..short_timers()
        },
    )
    .await?;

    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    let accepted = Instant::now();
    dialog.accept(None, None)?;
    let messages = peer.collect(accepted + T1X64 * 2).await;

    let oks: Vec<Instant> = messages
        .iter()
        .filter(|(_, m)| is_invite_2xx(m))
        .map(|(at, _)| *at)
        .collect();
    let gaps: Vec<Duration> = oks.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.len() >= 8 && gaps.iter().all(|g| *g <= t2 + T1 * 2),
        "retransmission intervals must stay at or below T2, got {gaps:?}"
    );
    let last = *oks.last().unwrap();
    assert!(
        last - accepted >= T1X64 - t2 - T1 * 2,
        "2xx retransmissions must go on until 64*T1, last one after {:?}",
        last - accepted
    );
    assert!(matches!(
        terminated_reason(&mut states),
        Some(TerminatedReason::Timeout)
    ));

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
