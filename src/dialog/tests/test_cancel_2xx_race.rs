//! A 2xx that answers the INVITE after we sent CANCEL (the callee picked up
//! while the CANCEL was in flight) establishes a dialog at the far end. The
//! CANCEL has no effect on it, so the UAC must ACK the 2xx and then end the
//! session with a BYE (RFC 3261 §9.1, §15; RFC 5407 §3.1.2).
//!
//! These tests drop the `do_invite` future after a 180 — the documented way to
//! abandon an outgoing call, which cancels it — and answer the INVITE with a
//! 200 from a raw UDP peer in each wire ordering. The `removed` variants call
//! `DialogLayer::remove_dialog` before dropping the future: the INVITE still
//! has to end (CANCEL, and ACK + BYE for a 2xx) even though the layer entry is
//! already gone.
use crate::dialog::{
    dialog::{DialogState, DialogStateReceiver, TerminatedReason},
    dialog_layer::DialogLayer,
    invitation::InviteOption,
    DialogId,
};
use crate::sip::{prelude::HeadersExt, Method, Request, SipMessage, Uri};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

/// Receive the next request with `method` on the raw peer socket within
/// `wait`, skipping anything else.
async fn recv_request(socket: &UdpSocket, method: Method, wait: Duration) -> (Request, SocketAddr) {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            if req.method == method {
                return (req, from);
            }
        }
    }
}

/// Fail if the peer receives a BYE within `wait`.
async fn assert_no_bye(socket: &UdpSocket, wait: Duration, what: &str) {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((len, _))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
    {
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            assert_ne!(req.method, Method::Bye, "{what}");
        }
    }
}

/// Build a response to `req` as the peer UA, adding the peer's To tag.
fn response(req: &Request, code: u16, reason: &str, contact: &str) -> String {
    let to = req.to_header().unwrap().value().to_string();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={PEER_TAG}")
    };
    format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {to}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <{contact}>\r\n\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
    )
}

async fn reply(socket: &UdpSocket, to: SocketAddr, req: &Request, code: u16, reason: &str) {
    let contact = format!("sip:bob@{}", socket.local_addr().unwrap());
    socket
        .send_to(response(req, code, reason, &contact).as_bytes(), to)
        .await
        .expect("send_to failed");
}

struct Uac {
    dialog_layer: Arc<DialogLayer>,
    option: InviteOption,
    peer: UdpSocket,
}

async fn setup(token: &CancellationToken) -> crate::Result<Uac> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_port = peer.local_addr()?.port();

    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uac_addr = udp.get_addr().addr.clone();
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{peer_port};transport=udp").as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        ..Default::default()
    };
    Ok(Uac {
        dialog_layer,
        option,
        peer,
    })
}

async fn wait_for_state(
    rx: &mut DialogStateReceiver,
    what: &str,
    wait: Duration,
    pred: impl Fn(&DialogState) -> bool,
) -> DialogState {
    tokio::time::timeout(wait, async {
        loop {
            let state = rx.recv().await.expect("state channel closed");
            if pred(&state) {
                return state;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {what}"))
}

/// The ACK and the BYE must belong to the dialog the 2xx established:
/// same Call-ID, our From tag, and the peer's To tag.
fn assert_in_dialog(msg: &Request, invite: &Request, what: &str) {
    assert_eq!(
        msg.call_id_header().unwrap().value(),
        invite.call_id_header().unwrap().value(),
        "{what} must carry the INVITE's Call-ID"
    );
    assert_eq!(
        msg.from_header().unwrap().tag().unwrap(),
        invite.from_header().unwrap().tag().unwrap(),
        "{what} must carry our From tag"
    );
    assert_eq!(
        msg.to_header()
            .unwrap()
            .tag()
            .unwrap()
            .map(|t| t.value().to_string()),
        Some(PEER_TAG.to_string()),
        "{what} must carry the 2xx's To tag"
    );
}

#[derive(Clone, Copy, Debug)]
enum Order {
    /// 200 to the INVITE, then 200 to the CANCEL.
    InviteOkFirst,
    /// 200 to the CANCEL, then 200 to the INVITE right away.
    CancelOkFirst,
    /// 200 to the CANCEL, then 200 to the INVITE after the 2 s settle window.
    InviteOkLate,
}

/// The id the `Calling` state reports, the one the dialog is registered under.
async fn calling_id(states: &mut DialogStateReceiver) -> DialogId {
    match wait_for_state(states, "Calling", Duration::from_secs(2), |s| {
        matches!(s, DialogState::Calling(_))
    })
    .await
    {
        DialogState::Calling(id) => id,
        _ => unreachable!(),
    }
}

async fn run_crossing_2xx(order: Order, provisional: u16, remove: bool) -> crate::Result<()> {
    let token = CancellationToken::new();
    let Uac {
        dialog_layer,
        option,
        peer,
    } = setup(&token).await?;
    let wait = Duration::from_secs(2);

    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move { layer.do_invite(option, state_sender).await });

    let (inv, uac) = recv_request(&peer, Method::Invite, wait).await;
    let id = calling_id(&mut states).await;
    let reason = if provisional == 100 {
        "Trying"
    } else {
        "Ringing"
    };
    reply(&peer, uac, &inv, provisional, reason).await;
    wait_for_state(&mut states, "Trying or Early", wait, |s| {
        matches!(s, DialogState::Trying(_) | DialogState::Early(_, _))
    })
    .await;

    if remove {
        // The application removes the dialog from the layer first.
        dialog_layer.remove_dialog(&id);
        assert!(dialog_layer.is_empty());
    }
    // The application abandons the call: dropping the `do_invite` future
    // cancels the INVITE.
    invite.abort();
    let _ = invite.await;
    let (cancel, _) = recv_request(&peer, Method::Cancel, wait).await;

    let mut terminated = None;
    match order {
        Order::InviteOkFirst => {
            reply(&peer, uac, &inv, 200, "OK").await;
            reply(&peer, uac, &cancel, 200, "OK").await;
        }
        Order::CancelOkFirst => {
            reply(&peer, uac, &cancel, 200, "OK").await;
            reply(&peer, uac, &inv, 200, "OK").await;
        }
        Order::InviteOkLate => {
            reply(&peer, uac, &cancel, 200, "OK").await;
            // The dialog reports Terminated(UacCancel) once the 2 s settle
            // window passes without a final response.
            terminated = Some(
                wait_for_state(&mut states, "Terminated", Duration::from_secs(4), |s| {
                    matches!(s, DialogState::Terminated(_, _))
                })
                .await,
            );
            tokio::time::sleep(Duration::from_millis(2500)).await;
            reply(&peer, uac, &inv, 200, "OK").await;
        }
    }

    let (ack, _) = recv_request(&peer, Method::Ack, wait).await;
    assert_in_dialog(&ack, &inv, "ACK");
    assert_eq!(
        ack.cseq_header().unwrap().seq().unwrap(),
        inv.cseq_header().unwrap().seq().unwrap(),
        "the ACK must acknowledge the INVITE"
    );

    let (bye, _) = recv_request(&peer, Method::Bye, wait).await;
    assert_in_dialog(&bye, &inv, "BYE");
    reply(&peer, uac, &bye, 200, "OK").await;

    // A retransmitted 2xx is ACKed again but starts no second BYE.
    reply(&peer, uac, &inv, 200, "OK").await;
    let (ack, _) = recv_request(&peer, Method::Ack, wait).await;
    assert_in_dialog(&ack, &inv, "ACK of the retransmitted 2xx");
    assert_no_bye(
        &peer,
        Duration::from_millis(500),
        "one BYE per abandoned call",
    )
    .await;

    // The abandoned call reports Terminated(UacCancel) once and is never
    // reported as Confirmed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut seen = Vec::new();
    while let Ok(state) = states.try_recv() {
        seen.push(state);
    }
    if let Some(t) = terminated {
        seen.insert(0, t);
    }
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, DialogState::Confirmed(_, _))),
        "an abandoned call must not report Confirmed, got {seen:?}"
    );
    let terminations: Vec<_> = seen
        .iter()
        .filter(|s| matches!(s, DialogState::Terminated(_, _)))
        .collect();
    assert!(
        matches!(
            terminations.as_slice(),
            [DialogState::Terminated(_, TerminatedReason::UacCancel)]
        ),
        "expected exactly one Terminated(UacCancel), got {seen:?}"
    );
    assert!(
        bye.cseq_header().unwrap().seq().unwrap() > inv.cseq_header().unwrap().seq().unwrap(),
        "the BYE must use a new CSeq"
    );
    assert_eq!(
        bye.uri.to_string(),
        format!("sip:bob@{}", peer.local_addr()?),
        "the BYE must target the 2xx's Contact"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_2xx_before_cancel_response_is_acked_and_byed() -> crate::Result<()> {
    run_crossing_2xx(Order::InviteOkFirst, 180, false).await
}

#[tokio::test]
async fn test_2xx_after_cancel_response_is_acked_and_byed() -> crate::Result<()> {
    run_crossing_2xx(Order::CancelOkFirst, 180, false).await
}

#[tokio::test]
async fn test_2xx_after_cancel_settle_window_is_acked_and_byed() -> crate::Result<()> {
    run_crossing_2xx(Order::InviteOkLate, 180, false).await
}

/// The same when the application removed the dialog from the layer before
/// dropping the `do_invite` future, in Early (180) and in Trying (100).
#[tokio::test]
async fn test_removed_dialog_2xx_crossing_the_cancel_is_acked_and_byed() -> crate::Result<()> {
    run_crossing_2xx(Order::InviteOkFirst, 180, true).await?;
    run_crossing_2xx(Order::InviteOkFirst, 100, true).await
}

/// The same in the other wire ordering (the 200 to the CANCEL arrives before
/// the 2xx) with the dialog already removed from the layer.
#[tokio::test]
async fn test_removed_dialog_2xx_after_the_cancel_response_is_acked_and_byed() -> crate::Result<()>
{
    run_crossing_2xx(Order::CancelOkFirst, 180, true).await
}

/// A CANCEL that wins the race (487 to the INVITE) ends the call as before:
/// the 487 is ACKed and no BYE is sent — also when the application removed
/// the dialog from the layer before dropping the `do_invite` future.
async fn run_cancel_answered_487(provisional: u16, remove: bool) -> crate::Result<()> {
    let token = CancellationToken::new();
    let Uac {
        dialog_layer,
        option,
        peer,
    } = setup(&token).await?;
    let wait = Duration::from_secs(2);

    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move { layer.do_invite(option, state_sender).await });
    let (inv, uac) = recv_request(&peer, Method::Invite, wait).await;
    let id = calling_id(&mut states).await;
    let reason = if provisional == 100 {
        "Trying"
    } else {
        "Ringing"
    };
    reply(&peer, uac, &inv, provisional, reason).await;
    wait_for_state(&mut states, "Trying or Early", wait, |s| {
        matches!(s, DialogState::Trying(_) | DialogState::Early(_, _))
    })
    .await;

    if remove {
        // The application removes the dialog from the layer first.
        dialog_layer.remove_dialog(&id);
        assert!(dialog_layer.is_empty());
    }
    invite.abort();
    let _ = invite.await;
    let (cancel, _) = recv_request(&peer, Method::Cancel, wait).await;
    reply(&peer, uac, &cancel, 200, "OK").await;
    reply(&peer, uac, &inv, 487, "Request Terminated").await;
    let (ack, _) = recv_request(&peer, Method::Ack, wait).await;
    assert_in_dialog(&ack, &inv, "ACK");
    assert_eq!(
        ack.cseq_header().unwrap().seq().unwrap(),
        inv.cseq_header().unwrap().seq().unwrap(),
        "the ACK must acknowledge the INVITE"
    );

    assert_no_bye(
        &peer,
        Duration::from_millis(1500),
        "a cancelled call must not be BYE'd",
    )
    .await;

    // Exactly one Terminated(UacCancel), never Confirmed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen: Vec<_> = std::iter::from_fn(|| states.try_recv().ok()).collect();
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, DialogState::Confirmed(_, _))),
        "a cancelled call must not report Confirmed, got {seen:?}"
    );
    let terminations: Vec<_> = seen
        .iter()
        .filter(|s| matches!(s, DialogState::Terminated(_, _)))
        .collect();
    assert!(
        matches!(
            terminations.as_slice(),
            [DialogState::Terminated(_, TerminatedReason::UacCancel)]
        ),
        "expected exactly one Terminated(UacCancel), got {seen:?}"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_cancel_answered_487_sends_no_bye() -> crate::Result<()> {
    run_cancel_answered_487(180, false).await
}

/// The same when the application removed the dialog from the layer before
/// dropping the `do_invite` future, in Early (180) and in Trying (100).
#[tokio::test]
async fn test_removed_cancel_answered_487_sends_no_bye() -> crate::Result<()> {
    run_cancel_answered_487(180, true).await?;
    run_cancel_answered_487(100, true).await
}

/// Dropped before any response: Terminated(UacCancel) is reported at once and
/// nothing is sent while no provisional has arrived (RFC 3261 §9.1). The first
/// response then gets a CANCEL (180), or an ACK and a BYE (200).
async fn run_dropped_before_provisional(first: u16, remove: bool) -> crate::Result<()> {
    let token = CancellationToken::new();
    let Uac {
        dialog_layer,
        option,
        peer,
    } = setup(&token).await?;
    let wait = Duration::from_secs(2);

    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move { layer.do_invite(option, state_sender).await });
    let (inv, uac) = recv_request(&peer, Method::Invite, wait).await;
    let id = calling_id(&mut states).await;
    if remove {
        // The application removes the dialog from the layer first.
        dialog_layer.remove_dialog(&id);
        assert!(dialog_layer.is_empty());
    }
    invite.abort();
    let _ = invite.await;
    let terminated = wait_for_state(&mut states, "Terminated", Duration::from_millis(200), |s| {
        matches!(s, DialogState::Terminated(_, _))
    })
    .await;
    assert!(matches!(
        terminated,
        DialogState::Terminated(_, TerminatedReason::UacCancel)
    ));
    // Over twice T1: not even an INVITE retransmission.
    let mut buf = vec![0u8; 4096];
    let silent = tokio::time::timeout(Duration::from_millis(1100), peer.recv_from(&mut buf)).await;
    assert!(silent.is_err(), "nothing may be sent before a provisional");

    match first {
        180 => {
            reply(&peer, uac, &inv, 180, "Ringing").await;
            let (cancel, _) = recv_request(&peer, Method::Cancel, wait).await;
            assert_eq!(cancel.cseq_header()?.seq()?, inv.cseq_header()?.seq()?);
            reply(&peer, uac, &cancel, 200, "OK").await;
            reply(&peer, uac, &inv, 487, "Request Terminated").await;
        }
        200 => reply(&peer, uac, &inv, 200, "OK").await,
        _ => reply(&peer, uac, &inv, first, "Busy Here").await,
    }
    let (ack, _) = recv_request(&peer, Method::Ack, wait).await;
    assert_in_dialog(&ack, &inv, "ACK");
    if first == 200 {
        let (bye, _) = recv_request(&peer, Method::Bye, wait).await;
        assert_in_dialog(&bye, &inv, "BYE");
        reply(&peer, uac, &bye, 200, "OK").await;
    } else {
        assert_no_bye(
            &peer,
            Duration::from_millis(500),
            "a call that was not answered",
        )
        .await;
    }
    assert!(
        !std::iter::from_fn(|| states.try_recv().ok())
            .any(|s| matches!(s, DialogState::Terminated(..) | DialogState::Confirmed(..))),
        "no second Terminated and no Confirmed"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_dropped_before_provisional_is_cancelled_after_the_180() -> crate::Result<()> {
    run_dropped_before_provisional(180, false).await
}

#[tokio::test]
async fn test_dropped_before_provisional_2xx_is_acked_and_byed() -> crate::Result<()> {
    run_dropped_before_provisional(200, false).await
}

#[tokio::test]
async fn test_removed_before_provisional_is_cancelled_after_the_180() -> crate::Result<()> {
    run_dropped_before_provisional(180, true).await
}

#[tokio::test]
async fn test_removed_before_provisional_2xx_is_acked_and_byed() -> crate::Result<()> {
    run_dropped_before_provisional(200, true).await
}

#[tokio::test]
async fn test_dropped_before_provisional_final_failure_is_acked_only() -> crate::Result<()> {
    run_dropped_before_provisional(486, false).await
}

#[tokio::test]
async fn test_removed_before_provisional_final_failure_is_acked_only() -> crate::Result<()> {
    run_dropped_before_provisional(486, true).await
}
