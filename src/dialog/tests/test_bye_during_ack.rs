//! A received 2xx establishes the UAC dialog before its ACK finishes sending.
use crate::dialog::{
    dialog::{DialogState, DialogStateReceiver, TerminatedReason},
    dialog_layer::DialogLayer,
    invitation::InviteOption,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, Request, SipMessage, StatusCode, Uri};
use crate::transaction::endpoint::TargetLocator;
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

struct DelayedAck {
    peer: SipAddr,
    entered: CancellationToken,
    release: CancellationToken,
    delayed: AtomicBool,
}

#[async_trait]
impl TargetLocator for DelayedAck {
    async fn locate(&self, uri: &Uri) -> crate::Result<SipAddr> {
        if uri.auth.as_ref().is_some_and(|a| a.user == "answered")
            && !self.delayed.swap(true, Ordering::SeqCst)
        {
            self.entered.cancel();
            self.release.cancelled().await;
        }
        Ok(self.peer.clone())
    }
}

struct Call {
    peer: UdpSocket,
    layer: Arc<DialogLayer>,
    dialog: InviteDialog,
    states: DialogStateReceiver,
    facts: super::super::lifecycle::DialogLifecycleReceiver,
    invite: Request,
    uac: std::net::SocketAddr,
    release: CancellationToken,
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<crate::Result<()>>,
}

impl Drop for Call {
    fn drop(&mut self) {
        self.release.cancel();
        self.shutdown.cancel();
        self.join.abort();
    }
}

async fn receive(peer: &UdpSocket) -> SipMessage {
    let mut buf = [0; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("SIP message timed out")
        .unwrap();
    SipMessage::try_from(&buf[..len]).unwrap()
}

async fn request(peer: &UdpSocket, method: Method) -> Request {
    match receive(peer).await {
        SipMessage::Request(req) => {
            assert_eq!(req.method, method);
            req
        }
        other => panic!("expected {method}, got {other}"),
    }
}

fn response(req: &Request, to: &str, contact: &str) -> String {
    format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <{contact}>\r\nContent-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(), req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(), req.cseq_header().unwrap().value(),
    )
}

async fn start(async_api: bool, provisional: bool) -> crate::Result<Call> {
    start_observed(async_api, provisional, false).await
}

async fn start_observed(async_api: bool, provisional: bool, observe: bool) -> crate::Result<Call> {
    let shutdown = CancellationToken::new();
    let entered = CancellationToken::new();
    let release = CancellationToken::new();
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let tl = TransportLayer::new(shutdown.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let uac = udp.get_addr().get_socketaddr()?;
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(tl)
        .with_cancel_token(shutdown.child_token())
        .with_target_locator(Box::new(DelayedAck {
            peer: SipAddr::try_from(&Uri::try_from(
                format!("sip:bob@{}", peer.local_addr()?).as_str(),
            )?)?,
            entered: entered.clone(),
            release: release.clone(),
            delayed: AtomicBool::new(false),
        }))
        .build();
    let mut incoming = endpoint.incoming_transactions()?;
    let ep = endpoint.inner.clone();
    tokio::spawn(async move { ep.serve().await });
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (sender, facts) = super::super::lifecycle::dialog_lifecycle_channel();
    if observe {
        layer.set_lifecycle_events(Some(sender));
    }
    let router = layer.clone();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                Some(mut tx) = incoming.recv() => {
                    if let Some(mut dialog) = router.match_dialog(&tx) {
                        dialog.handle(&mut tx).await.unwrap();
                    } else {
                        tx.reply(StatusCode::CallTransactionDoesNotExist).await.unwrap();
                    }
                }
            }
        }
    });
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{}", peer.local_addr()?).as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac}").as_str())?,
        ..Default::default()
    };
    let (sender, states) = unbounded_channel();
    let (dialog, join) = if async_api {
        let (dialog, task) = layer.do_invite_async(option, sender)?;
        (
            Some(dialog),
            tokio::spawn(async move { task.await.unwrap().map(|_| ()) }),
        )
    } else {
        let l = layer.clone();
        (
            None,
            tokio::spawn(async move { l.do_invite(option, sender).await.map(|_| ()) }),
        )
    };
    let invite = request(&peer, Method::Invite).await;
    let dialog = dialog.unwrap_or_else(|| {
        layer
            .get_client_dialog_by_call_id(invite.call_id_header().unwrap().value())
            .pop()
            .unwrap()
    });
    let contact = format!("sip:answered@{}", peer.local_addr()?);
    let ok = response(
        &invite,
        &format!("{};tag=peer", invite.to_header()?.value()),
        &contact,
    );
    if provisional {
        peer.send_to(ok.replace("200 OK", "180 Ringing").as_bytes(), uac)
            .await?;
    }
    peer.send_to(ok.as_bytes(), uac).await?;
    tokio::time::timeout(Duration::from_secs(2), entered.cancelled())
        .await
        .expect("ACK was not delayed");
    Ok(Call {
        peer,
        layer,
        dialog,
        states,
        facts,
        invite,
        uac,
        release,
        shutdown,
        join,
    })
}

async fn remote_bye(call: &Call, remote_tag: &str, local_tag: &str, seq: u32) -> StatusCode {
    let bye = format!(
        "BYE sip:alice@{} SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bKbye{seq};rport\r\nFrom: <sip:bob@example.com>;tag={remote_tag}\r\nTo: <sip:alice@example.com>;tag={local_tag}\r\nCall-ID: {}\r\nCSeq: {seq} BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        call.uac, call.peer.local_addr().unwrap(), call.invite.call_id_header().unwrap().value(),
    );
    call.peer.send_to(bye.as_bytes(), call.uac).await.unwrap();
    match receive(&call.peer).await {
        SipMessage::Response(resp) => resp.status_code,
        other => panic!("expected BYE response, got {other}"),
    }
}

async fn remote_bye_during_ack(async_api: bool, provisional: bool) -> crate::Result<()> {
    let mut call = start(async_api, provisional).await?;
    let local = call
        .invite
        .from_header()?
        .tag()?
        .unwrap()
        .value()
        .to_string();
    assert_eq!(
        remote_bye(&call, "wrong", &local, 100).await,
        StatusCode::CallTransactionDoesNotExist
    );
    assert_eq!(
        remote_bye(&call, "peer", "wrong", 101).await,
        StatusCode::CallTransactionDoesNotExist
    );
    assert_eq!(
        remote_bye(&call, "peer", &local, 2).await,
        StatusCode::OK,
        "a valid BYE must succeed while the initial ACK is blocked"
    );
    assert!(matches!(
        call.dialog.state(),
        DialogState::Terminated(_, TerminatedReason::UasBye)
    ));
    let events: Vec<_> = std::iter::from_fn(|| call.states.try_recv().ok()).collect();
    let confirmed = events
        .iter()
        .position(|s| matches!(s, DialogState::Confirmed(_, _)))
        .expect("answered event");
    let ended = events
        .iter()
        .position(|s| matches!(s, DialogState::Terminated(_, _)))
        .expect("ended event");
    assert!(
        confirmed < ended,
        "billing must see answer before termination"
    );
    assert_eq!(
        events
            .iter()
            .filter(|s| matches!(s, DialogState::Confirmed(_, _)))
            .count(),
        1
    );
    call.layer.remove_dialog(&call.dialog.id());
    assert!(call.layer.is_empty());
    call.release.cancel();
    request(&call.peer, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap()?;
    assert!(
        call.layer.is_empty(),
        "ACK completion must not resurrect a terminated dialog"
    );
    assert!(
        call.states.try_recv().is_err(),
        "no state changes after termination"
    );
    Ok(())
}

#[tokio::test]
async fn test_remote_bye_during_ack_async() -> crate::Result<()> {
    remote_bye_during_ack(true, false).await
}

#[tokio::test]
async fn test_remote_bye_during_ack_after_ringing() -> crate::Result<()> {
    remote_bye_during_ack(false, true).await
}

#[tokio::test]
async fn test_local_bye_waits_for_initial_ack() -> crate::Result<()> {
    let mut call = start(true, false).await?;
    assert!(
        call.dialog.state().is_confirmed(),
        "200 establishes the dialog before ACK completes"
    );
    let dialog = call.dialog.clone();
    let mut bye = Box::pin(dialog.bye());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut bye)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receive(&call.peer))
            .await
            .is_err()
    );
    call.release.cancel();
    let peer = async {
        request(&call.peer, Method::Ack).await;
        let req = request(&call.peer, Method::Bye).await;
        let ok = response(
            &req,
            req.to_header()?.value(),
            &format!("sip:bob@{}", call.peer.local_addr()?),
        );
        call.peer.send_to(ok.as_bytes(), call.uac).await?;
        crate::Result::Ok(())
    };
    let (bye_result, peer_result) = tokio::join!(bye, peer);
    bye_result?;
    peer_result?;
    tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap()?;
    assert!(matches!(
        call.dialog.state(),
        DialogState::Terminated(_, TerminatedReason::UacBye)
    ));
    Ok(())
}

#[tokio::test]
async fn test_remote_bye_wins_while_local_bye_waits_for_ack() -> crate::Result<()> {
    let mut call = start(true, false).await?;
    let dialog = call.dialog.clone();
    let mut bye = Box::pin(dialog.bye());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut bye)
        .await
        .is_err());
    let local = call
        .invite
        .from_header()?
        .tag()?
        .unwrap()
        .value()
        .to_string();
    assert_eq!(remote_bye(&call, "peer", &local, 2).await, StatusCode::OK);
    call.layer.remove_dialog(&dialog.id());
    call.release.cancel();
    request(&call.peer, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), bye)
        .await
        .unwrap()?;
    tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap()?;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receive(&call.peer))
            .await
            .is_err(),
        "no local BYE after the remote BYE ended the dialog"
    );
    assert!(matches!(
        dialog.state(),
        DialogState::Terminated(_, TerminatedReason::UasBye)
    ));
    assert!(call.layer.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_interrupted_ack_releases_waiting_bye_with_error() -> crate::Result<()> {
    let mut call = start(false, false).await?;
    let dialog = call.dialog.clone();
    let mut bye = Box::pin(dialog.bye());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut bye)
        .await
        .is_err());
    call.join.abort();
    assert!(tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
    let err = tokio::time::timeout(Duration::from_secs(2), bye)
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("ACK was interrupted"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receive(&call.peer))
            .await
            .is_err(),
        "interrupted ACK must not let BYE overtake it"
    );
    Ok(())
}

#[tokio::test]
async fn lifecycle_answer_and_valid_bye_precede_blocked_ack() -> crate::Result<()> {
    use super::super::lifecycle::DialogLifecycleKind as K;
    let mut call = start_observed(true, false, true).await?;
    let accepted = call.facts.try_recv().expect("answer before ACK finishes");
    assert!(matches!(accepted.kind, K::InviteAccepted { .. }));
    assert_eq!(accepted.sequence, 1);
    assert_eq!(accepted.dialog_id, call.dialog.id());
    let local = call
        .invite
        .from_header()?
        .tag()?
        .unwrap()
        .value()
        .to_string();
    assert_eq!(
        remote_bye(&call, "wrong", &local, 100).await,
        StatusCode::CallTransactionDoesNotExist
    );
    assert!(call.facts.try_recv().is_err());
    assert_eq!(remote_bye(&call, "peer", &local, 2).await, StatusCode::OK);
    let bye = call.facts.try_recv().unwrap();
    let ended = call.facts.try_recv().unwrap();
    assert!(matches!(bye.kind, K::RemoteByeReceived));
    assert!(matches!(ended.kind, K::DialogTerminated { .. }));
    assert_eq!((bye.sequence, ended.sequence), (2, 3));
    assert!(bye.occurred_at.monotonic >= accepted.occurred_at.monotonic);
    assert!(ended.occurred_at.monotonic >= bye.occurred_at.monotonic);
    assert!(call.facts.try_recv().is_err());
    call.release.cancel();
    request(&call.peer, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap()?;
    assert!(call.facts.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn lifecycle_local_end_precedes_ack_and_bye_response() -> crate::Result<()> {
    use super::super::lifecycle::DialogLifecycleKind as K;
    let mut call = start_observed(true, false, true).await?;
    let accepted = call.facts.try_recv().unwrap();
    let dialog = call.dialog.clone();
    let mut bye = Box::pin(dialog.bye());
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut bye)
        .await
        .is_err());
    let requested = call
        .facts
        .try_recv()
        .expect("local end while ACK is blocked");
    assert!(matches!(requested.kind, K::LocalTerminationRequested));
    assert_eq!(requested.sequence, accepted.sequence + 1);
    assert!(call.facts.try_recv().is_err());
    call.release.cancel();
    let peer = async {
        request(&call.peer, Method::Ack).await;
        let req = request(&call.peer, Method::Bye).await;
        call.peer
            .send_to(
                response(&req, req.to_header()?.value(), "sip:bob@example.com").as_bytes(),
                call.uac,
            )
            .await?;
        crate::Result::Ok(())
    };
    let (a, b) = tokio::join!(bye, peer);
    a?;
    b?;
    let ended = call.facts.try_recv().unwrap();
    assert!(matches!(ended.kind, K::DialogTerminated { .. }));
    assert!(ended.occurred_at.monotonic > requested.occurred_at.monotonic);
    assert_eq!(ended.sequence, 3);
    Ok(())
}

#[tokio::test]
async fn lifecycle_duplicate_2xx_and_info_do_not_repeat_answer() -> crate::Result<()> {
    let mut call = start_observed(true, false, true).await?;
    assert_eq!(call.facts.try_recv().unwrap().sequence, 1);
    call.release.cancel();
    request(&call.peer, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), &mut call.join)
        .await
        .unwrap()
        .unwrap()?;
    let ok = response(
        &call.invite,
        &format!("{};tag=peer", call.invite.to_header()?.value()),
        &format!("sip:answered@{}", call.peer.local_addr()?),
    );
    call.peer.send_to(ok.as_bytes(), call.uac).await?;
    request(&call.peer, Method::Ack).await;
    // The legacy state channel can re-announce Confirmed after INFO. Facts
    // must not infer a new answer from that state notification.
    call.dialog.inner.transition(DialogState::Confirmed(
        call.dialog.id(),
        crate::sip::Response::default(),
    ));
    assert!(call.facts.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn lifecycle_closed_receiver_does_not_prevent_remote_bye() -> crate::Result<()> {
    let mut call = start_observed(true, false, true).await?;
    call.facts.close();
    let local = call
        .invite
        .from_header()?
        .tag()?
        .unwrap()
        .value()
        .to_string();
    assert_eq!(remote_bye(&call, "peer", &local, 2).await, StatusCode::OK);
    assert!(call.dialog.state().is_terminated());
    Ok(())
}
