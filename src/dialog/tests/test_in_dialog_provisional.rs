//! A provisional response to an in-dialog request must not move a confirmed
//! dialog back to the early state (RFC 3261 §12: a dialog goes early →
//! confirmed and never back; a 1xx to a mid-dialog request does not create
//! early state). Otherwise `bye()` refuses to run on the dialog and
//! `hangup()` falls through to a CANCEL of the long-completed INVITE.
use crate::dialog::{
    dialog::{DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invitation::InviteOption,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, Request, SipMessage, Uri};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

/// Receive the next request with `method` on the raw peer socket, skipping
/// anything else (retransmissions, ACKs we are not waiting for).
pub(super) async fn recv_request(socket: &UdpSocket, method: Method) -> (Request, SocketAddr) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
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

/// Build a response to `req` as the peer UA, adding the peer's To tag when
/// the request does not carry one yet.
pub(super) fn response(req: &Request, code: u16, reason: &str, contact: &str) -> String {
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

pub(super) async fn reply(
    socket: &UdpSocket,
    to: SocketAddr,
    req: &Request,
    code: u16,
    reason: &str,
) {
    let contact = format!("sip:bob@{}", socket.local_addr().unwrap());
    socket
        .send_to(response(req, code, reason, &contact).as_bytes(), to)
        .await
        .expect("send_to failed");
}

fn drain_states(rx: &mut DialogStateReceiver) -> Vec<DialogState> {
    let mut states = Vec::new();
    while let Ok(state) = rx.try_recv() {
        states.push(state);
    }
    states
}

/// Set up a UAC endpoint and a raw UDP peer, and establish a dialog whose
/// initial INVITE is answered 100 → 183 → 200. Returns the confirmed dialog.
pub(super) async fn establish(
    token: &CancellationToken,
) -> crate::Result<(InviteDialog, DialogStateReceiver, UdpSocket)> {
    establish_with_credential(token, None).await
}

pub(super) async fn establish_with_credential(
    token: &CancellationToken,
    credential: Option<crate::dialog::authenticate::Credential>,
) -> crate::Result<(InviteDialog, DialogStateReceiver, UdpSocket)> {
    establish_with_options(token, credential, Default::default()).await
}

pub(super) async fn establish_with_options(
    token: &CancellationToken,
    credential: Option<crate::dialog::authenticate::Credential>,
    options: crate::transaction::endpoint::EndpointOption,
) -> crate::Result<(InviteDialog, DialogStateReceiver, UdpSocket)> {
    establish_with_dispatch(token, credential, options, None).await
}

async fn establish_with_dispatch(
    token: &CancellationToken,
    credential: Option<crate::dialog::authenticate::Credential>,
    options: crate::transaction::endpoint::EndpointOption,
    dispatch: Option<crate::transaction::TransactionSender>,
) -> crate::Result<(InviteDialog, DialogStateReceiver, UdpSocket)> {
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
        .with_option(options)
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    // Pump inbound in-dialog requests (e.g. the peer's BYE) into the layer.
    let mut incoming = endpoint.incoming_transactions()?;
    let pump_layer = DialogLayer {
        endpoint: dialog_layer.endpoint.clone(),
        inner: dialog_layer.inner.clone(),
    };
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            if let Some(dispatch) = &dispatch {
                if dispatch.send(tx).is_err() {
                    break;
                }
                continue;
            }
            if let Some(mut dialog) = pump_layer.match_dialog(&tx) {
                tokio::spawn(async move {
                    let _ = dialog.handle(&mut tx).await;
                });
            }
        }
    });

    let (state_sender, mut state_receiver) = unbounded_channel();
    let invite_option = InviteOption {
        credential,
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{peer_port};transport=udp").as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        ..Default::default()
    };
    let invite = tokio::spawn(async move {
        dialog_layer
            .do_invite(invite_option, state_sender)
            .await
            .map(|(dialog, _)| dialog)
    });

    let (req, uac) = recv_request(&peer, Method::Invite).await;
    reply(&peer, uac, &req, 100, "Trying").await;
    reply(&peer, uac, &req, 183, "Session Progress").await;
    reply(&peer, uac, &req, 200, "OK").await;
    recv_request(&peer, Method::Ack).await;

    let dialog = invite.await.expect("do_invite task panicked")?;
    assert!(dialog.state().is_confirmed(), "initial INVITE must confirm");

    // The initial INVITE's 183 still produces early state, as before.
    let states = drain_states(&mut state_receiver);
    assert!(
        states.iter().any(|s| matches!(s, DialogState::Early(_, _))),
        "a 183 to the initial INVITE must report Early, got {states:?}"
    );
    assert!(
        matches!(states.last(), Some(DialogState::Confirmed(_, _))),
        "initial INVITE must end Confirmed, got {states:?}"
    );
    Ok((dialog, state_receiver, peer))
}

/// Send `method` in-dialog, answer it 100 → 183 → 200 from the peer, and
/// check the dialog stays Confirmed throughout and can still send BYE.
async fn assert_provisional_keeps_confirmed(method: Method) -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog, mut states, peer) = establish(&token).await?;

    let requester = dialog.clone();
    let req_method = method.clone();
    let pending = tokio::spawn(async move {
        match req_method {
            Method::Invite => requester.reinvite(None, None).await,
            Method::Update => requester.update(None, None).await,
            _ => unreachable!(),
        }
    });

    let (req, uac) = recv_request(&peer, method.clone()).await;
    reply(&peer, uac, &req, 100, "Trying").await;
    reply(&peer, uac, &req, 183, "Session Progress").await;
    // Let the dialog process the provisionals while the request is pending.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        dialog.state().is_confirmed(),
        "a 183 to an in-dialog {method} must not leave Confirmed, state: {}",
        dialog.state()
    );

    reply(&peer, uac, &req, 200, "OK").await;
    let resp = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .expect("in-dialog request did not complete")
        .expect("request task panicked")?
        .expect("no final response");
    assert_eq!(resp.status_code, crate::sip::StatusCode::OK);
    assert!(
        dialog.state().is_confirmed(),
        "dialog must be Confirmed after the in-dialog {method} completes, state: {}",
        dialog.state()
    );
    // The 183 is still delivered to the caller, it just does not change the
    // dialog's state.
    let states = drain_states(&mut states);
    assert!(
        states.iter().any(|s| matches!(
            s,
            DialogState::Early(_, r) if r.status_code == crate::sip::StatusCode::SessionProgress
        )),
        "the 183 to an in-dialog {method} must still be notified, got {states:?}"
    );

    // The call can still be hung up with a BYE.
    let hanger = dialog.clone();
    let bye = tokio::spawn(async move { hanger.bye().await });
    let (bye_req, uac) = recv_request(&peer, Method::Bye).await;
    reply(&peer, uac, &bye_req, 200, "OK").await;
    tokio::time::timeout(Duration::from_secs(2), bye)
        .await
        .expect("bye did not complete")
        .expect("bye task panicked")?;
    assert!(dialog.state().is_terminated());

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_reinvite_provisional_keeps_dialog_confirmed() -> crate::Result<()> {
    assert_provisional_keeps_confirmed(Method::Invite).await
}

#[tokio::test]
async fn test_update_provisional_keeps_dialog_confirmed() -> crate::Result<()> {
    assert_provisional_keeps_confirmed(Method::Update).await
}

/// A provisional response to an in-dialog request is never notified after
/// the dialog terminated: the peer hangs up while a re-INVITE is pending,
/// and only then answers it with a 183.
#[tokio::test]
async fn test_provisional_after_terminated_is_not_notified() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog, mut states, peer) = establish(&token).await?;
    while states.try_recv().is_ok() {}

    // A re-INVITE goes out and stays pending.
    let requester = dialog.clone();
    let pending = tokio::spawn(async move { requester.reinvite(None, None).await });
    let (req, uac) = recv_request(&peer, Method::Invite).await;

    // The peer hangs up while the re-INVITE is pending.
    let id = dialog.id();
    let uac_uri = format!("sip:alice@{uac}");
    let bye = format!(
        "BYE {uac_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-bye\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@{peer_addr}>;tag={PEER_TAG}\r\n\
         To: <{uac_uri}>;tag={local}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 2 BYE\r\n\
         Content-Length: 0\r\n\r\n",
        peer_addr = peer.local_addr()?,
        local = id.local_tag,
        call_id = id.call_id,
    );
    peer.send_to(bye.as_bytes(), uac).await?;
    // The dialog terminates and answers the BYE with a 200.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(states.recv().await, Some(DialogState::Terminated(..))) {
                break;
            }
        }
    })
    .await
    .expect("timeout waiting for Terminated");
    assert!(dialog.state().is_terminated());

    // Only now does the peer answer the re-INVITE — with a provisional.
    reply(&peer, uac, &req, 183, "Session Progress").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after: Vec<String> = drain_states(&mut states)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    assert!(
        after.is_empty(),
        "nothing may be notified after Terminated, got {after:?}"
    );

    // Finish the pending re-INVITE so the transaction does not linger.
    reply(&peer, uac, &req, 200, "OK").await;
    tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .expect("re-INVITE did not complete")
        .expect("re-INVITE task panicked")?;

    assert!(dialog.state().is_terminated());
    token.cancel();
    Ok(())
}

/// Endpoint arrival order must survive a consumer scheduling INFO before BYE.
#[tokio::test]
async fn test_incoming_cseq_admission_precedes_consumer_dispatch() -> crate::Result<()> {
    for stale_bye in [false, true] {
        let token = CancellationToken::new();
        let _guard = token.clone().drop_guard();
        let (dispatch, mut incoming) = unbounded_channel();
        let (dialog, mut states, peer) =
            establish_with_dispatch(&token, None, Default::default(), Some(dispatch)).await?;
        let id = dialog.id();
        let local = dialog.inner.endpoint_inner.get_addrs()[0].get_socketaddr()?;
        let addr = peer.local_addr()?;
        let request = |method: Method, seq: u32| {
            format!(
                "{method} sip:alice@{local} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch=z9hG4bK-receive-{seq}-{method}\r\n\
             From: <sip:bob@{addr}>;tag={remote}\r\n\
             To: <sip:alice@{local}>;tag={local_tag}\r\n\
             Call-ID: {call_id}\r\nCSeq: {seq} {method}\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
                remote = id.remote_tag,
                local_tag = id.local_tag,
                call_id = id.call_id,
            )
        };
        let receive = async |incoming: &mut tokio::sync::mpsc::UnboundedReceiver<
            crate::transaction::transaction::Transaction,
        >| {
            tokio::time::timeout(Duration::from_secs(2), incoming.recv())
                .await
                .unwrap()
                .unwrap()
        };
        // Receiving each Transaction is the barrier proving Endpoint arrival order.
        let (mut bye, mut info) = if stale_bye {
            peer.send_to(request(Method::Info, 1606).as_bytes(), local)
                .await?;
            let info = receive(&mut incoming).await;
            peer.send_to(request(Method::Bye, 1605).as_bytes(), local)
                .await?;
            (receive(&mut incoming).await, info)
        } else {
            peer.send_to(request(Method::Bye, 1605).as_bytes(), local)
                .await?;
            let bye = receive(&mut incoming).await;
            peer.send_to(request(Method::Info, 1606).as_bytes(), local)
                .await?;
            (bye, receive(&mut incoming).await)
        };
        let mut info_dialog = dialog.clone();
        let mut info_task = Box::pin(info_dialog.handle(&mut info));
        assert!(futures::poll!(info_task.as_mut()).is_pending());
        assert!(matches!(states.recv().await, Some(DialogState::Info(..))));
        let mut bye_dialog = dialog.clone();
        bye_dialog.handle(&mut bye).await?;
        let mut buf = [0u8; 4096];
        let response = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (len, _) = peer.recv_from(&mut buf).await.unwrap();
                if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(&buf[..len]) {
                    if resp.cseq_header().unwrap().seq().unwrap() == 1605 {
                        break resp;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            response.status_code,
            if stale_bye {
                crate::sip::StatusCode::ServerInternalError
            } else {
                crate::sip::StatusCode::OK
            },
            "earlier BYE must not become stale due to consumer scheduling"
        );
        assert_eq!(dialog.state().is_terminated(), !stale_bye);
    }
    Ok(())
}
