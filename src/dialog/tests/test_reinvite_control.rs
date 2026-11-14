//! Wire regressions for application-controlled re-INVITEs on confirmed dialogs.
use super::test_in_dialog_provisional::{
    establish, establish_with_credential, establish_with_options, recv_request, reply, response,
};
use crate::dialog::{
    dialog::DialogState,
    reinvite::{AckBody, InviteAnswerHandler, ReinviteOptions},
};
use crate::sip::{Header, HeadersExt, Method, Response};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n";
const REJECTED: &[u8] = b"v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n";
struct Answer {
    offers: mpsc::Sender<Response>,
    answers: Mutex<mpsc::Receiver<Vec<u8>>>,
}
#[async_trait::async_trait]
impl InviteAnswerHandler for Answer {
    fn fallback_answer(&self, _: &Response) -> AckBody {
        AckBody::sdp(REJECTED.to_vec())
    }
    async fn answer(&self, response: Response) -> crate::Result<AckBody> {
        self.offers.send(response).await.unwrap();
        Ok(AckBody::sdp(
            self.answers.lock().await.recv().await.unwrap(),
        ))
    }
}

#[tokio::test]
async fn deferred_ack_waits_for_answer_and_retransmits_identically() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish_with_credential(&token, Some(credential())).await?;
    let before = dialog.snapshot().local_cseq;
    let request = dialog.prepare_reinvite(None, None)?;
    assert_eq!(dialog.snapshot().local_cseq, before + 1);

    let (offers, mut received_offer) = mpsc::channel(1);
    let (answers, receive_answer) = mpsc::channel(1);
    let handler = Arc::new(Answer {
        offers,
        answers: Mutex::new(receive_answer),
    });
    let sender = dialog.clone();
    let pending = tokio::spawn(async move {
        sender
            .send_reinvite(
                request,
                ReinviteOptions {
                    answer_handler: Some(handler),
                    ..Default::default()
                },
            )
            .await
    });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    challenge(&peer, address, &request).await?;
    recv_request(&peer, Method::Ack).await;
    let (request, address) = recv_request(&peer, Method::Invite).await;
    let sequence = request.cseq_header()?.seq()?;
    assert!(request.authorization_header().is_some());
    assert!(request.body.is_empty());
    let contact = format!("sip:peer@{}", peer.local_addr()?);
    let mut success = Response::try_from(response(&request, 200, "OK", &contact).as_str())?;
    success.body = OFFER.into();
    success
        .headers
        .unique_push(Header::ContentType("application/sdp".into()));
    success
        .headers
        .unique_push(Header::ContentLength((OFFER.len() as u32).into()));
    peer.send_to(success.to_string().as_bytes(), address)
        .await?;
    assert_eq!(received_offer.recv().await.unwrap().body, OFFER);
    let during_answer = dialog.snapshot();
    assert_eq!(during_answer.runtime.pending.negotiations, 1);
    assert!(during_answer.runtime.pending.local_invite);
    assert!(!during_answer.is_quiescent());
    peer.send_to(success.to_string().as_bytes(), address)
        .await?;
    let overlapping = dialog.prepare_reinvite(None, Some(OFFER.to_vec()))?;
    assert!(dialog
        .send_reinvite(overlapping, ReinviteOptions::default())
        .await
        .is_err());
    let mut packet = [0; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut packet))
            .await
            .is_err(),
        "no automatic empty ACK while waiting for the answer"
    );
    assert!(
        received_offer.try_recv().is_err(),
        "a retransmission must not start another answer handler"
    );
    answers.send(ANSWER.into()).await.unwrap();
    let (ack, _) = recv_request(&peer, Method::Ack).await;
    assert_eq!(ack.body, ANSWER);
    assert_eq!(ack.cseq_header()?.seq()?, sequence);
    assert_eq!(pending.await.unwrap()?.unwrap().status_code.code(), 200);
    assert!(dialog.snapshot().is_quiescent());
    peer.send_to(success.to_string().as_bytes(), address)
        .await?;
    let (repeated, _) = recv_request(&peer, Method::Ack).await;
    assert_eq!(repeated, ack);
    let mut wrong = success.clone();
    wrong.to_header_mut()?.mut_tag("another-dialog".into())?;
    peer.send_to(wrong.to_string().as_bytes(), address).await?;
    wrong = success.clone();
    wrong.cseq_header_mut()?.mut_seq(sequence + 1)?;
    peer.send_to(wrong.to_string().as_bytes(), address).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut packet))
            .await
            .is_err(),
        "another dialog or CSeq must not reuse the ACK answer"
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_reinvite_waits_for_provisional_and_preserves_session() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish_with_credential(&token, Some(credential())).await?;
    let request = dialog.prepare_reinvite(None, Some(OFFER.into()))?;
    let cancel = CancellationToken::new();
    let cancellation = cancel.clone();
    let sender = dialog.clone();
    let pending = tokio::spawn(async move {
        sender
            .send_reinvite(
                request,
                ReinviteOptions {
                    cancellation,
                    ..Default::default()
                },
            )
            .await
    });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    challenge(&peer, address, &request).await?;
    recv_request(&peer, Method::Ack).await;
    let (request, address) = recv_request(&peer, Method::Invite).await;
    assert!(request.authorization_header().is_some());
    cancel.cancel();
    let mut packet = [0; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut packet))
            .await
            .is_err(),
        "CANCEL must wait for a provisional"
    );
    reply(&peer, address, &request, 100, "Trying").await;
    let (cancel, _) = recv_request(&peer, Method::Cancel).await;
    assert_eq!(cancel.via_header()?, request.via_header()?);
    assert_eq!(cancel.cseq_header()?.seq()?, request.cseq_header()?.seq()?);
    reply(&peer, address, &cancel, 200, "OK").await;
    reply(&peer, address, &request, 487, "Request Terminated").await;
    recv_request(&peer, Method::Ack).await;
    assert_eq!(pending.await.unwrap()?.unwrap().status_code.code(), 487);
    assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
    assert!(dialog.snapshot().is_quiescent());
    Ok(())
}

fn credential() -> crate::dialog::authenticate::Credential {
    crate::dialog::authenticate::Credential {
        username: "alice".into(),
        password: "secret".into(),
        ..Default::default()
    }
}

async fn challenge(
    peer: &tokio::net::UdpSocket,
    address: std::net::SocketAddr,
    req: &crate::sip::Request,
) -> crate::Result<()> {
    let mut resp = Response::try_from(
        response(
            req,
            401,
            "Unauthorized",
            &format!("sip:peer@{}", peer.local_addr()?),
        )
        .as_str(),
    )?;
    resp.headers.push(Header::WwwAuthenticate(
        r#"Digest realm="test", nonce="nonce", algorithm=MD5, qop="auth""#.into(),
    ));
    peer.send_to(resp.to_string().as_bytes(), address).await?;
    Ok(())
}

#[tokio::test]
async fn challenge_without_credentials_preserves_confirmed_dialog() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish(&token).await?;
    let sender = dialog.clone();
    let request = dialog.prepare_reinvite(None, Some(OFFER.into()))?;
    let pending = tokio::spawn(async move {
        sender
            .send_reinvite(request, ReinviteOptions::default())
            .await
    });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    challenge(&peer, address, &request).await?;
    recv_request(&peer, Method::Ack).await;
    assert_eq!(pending.await.unwrap()?.unwrap().status_code.code(), 401);
    assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
    Ok(())
}

async fn receive_response(
    peer: &tokio::net::UdpSocket,
    method: Method,
    code: u16,
) -> crate::Result<(Response, std::net::SocketAddr)> {
    let mut bytes = [0; 8192];
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (len, address) = peer.recv_from(&mut bytes).await?;
            if let crate::sip::SipMessage::Response(response) =
                crate::sip::SipMessage::try_from(&bytes[..len])?
            {
                if response.cseq_header()?.method()? == method
                    && response.status_code.code() == code
                {
                    return Ok((response, address));
                }
            }
        }
    })
    .await
    .expect("response deadline")
}

#[tokio::test]
async fn server_leg_reinvite_requires_initial_ack_and_preserves_call_on_488() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, mut tx, mut states, peer) =
        super::test_accept_before_handle::incoming_invite(&token).await?;
    let original = tx.original.clone();
    assert!(dialog.prepare_reinvite(None, Some(OFFER.into())).is_err());
    dialog.accept(None, None)?;
    let mut driver = dialog.clone();
    tokio::spawn(async move { driver.handle(&mut tx).await });
    let (success, address) = receive_response(&peer, Method::Invite, 200).await?;
    assert!(matches!(dialog.state(), DialogState::WaitAck(..)));
    assert!(dialog.prepare_reinvite(None, Some(OFFER.into())).is_err());
    let mut ack = original;
    ack.method = Method::Ack;
    ack.headers.unique_push(Header::CSeq("1 ACK".into()));
    ack.headers
        .unique_push(Header::To(success.to_header()?.clone()));
    peer.send_to(ack.to_string().as_bytes(), address).await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Confirmed(..)) {
                return;
            }
        }
        panic!("dialog closed before ACK");
    })
    .await
    .unwrap();
    let request = dialog.prepare_reinvite(
        Some(vec![Header::ContentType("application/sdp".into())]),
        Some(OFFER.into()),
    )?;
    let sender = dialog.clone();
    let pending = tokio::spawn(async move {
        sender
            .send_reinvite(request, ReinviteOptions::default())
            .await
    });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    reply(&peer, address, &request, 488, "Not Acceptable Here").await;
    recv_request(&peer, Method::Ack).await;
    assert_eq!(pending.await.unwrap()?.unwrap().status_code.code(), 488);
    assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
    Ok(())
}

#[tokio::test]
async fn incoming_reinvite_cancel_can_be_relayed_or_answered_by_default() -> crate::Result<()> {
    for observed in [false, true] {
        let token = CancellationToken::new();
        let _guard = token.clone().drop_guard();
        let (dialog, mut states, peer) = establish(&token).await?;
        let local = dialog
            .inner
            .endpoint_inner
            .transport_layer
            .get_listen_addrs()[0]
            .get_socketaddr()?;
        let remote = peer.local_addr()?;
        let id = dialog.id();
        let request = crate::sip::Request::try_from(format!(
            "INVITE sip:alice@{local} SIP/2.0\r\nVia: SIP/2.0/UDP {remote};branch=z9hG4bK-controlled-reinvite\r\nMax-Forwards: 70\r\nFrom: <sip:peer@{remote}>;tag={}\r\nTo: <sip:alice@{local}>;tag={}\r\nCall-ID: {}\r\nCSeq: 10 INVITE\r\nContact: <sip:peer@{remote}>\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
            id.remote_tag, id.local_tag, id.call_id, OFFER.len(), std::str::from_utf8(OFFER).unwrap()
        ).as_str())?;
        peer.send_to(request.to_string().as_bytes(), local).await?;
        let handle = tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(event) = states.recv().await {
                if let DialogState::Updated(_, _, handle) = event {
                    return handle;
                }
            }
            panic!("missing re-INVITE event");
        })
        .await
        .unwrap();
        let cancellation = observed.then(|| handle.cancellation());
        let finished = handle.finished();
        handle.reply(180.into()).await.unwrap();
        receive_response(&peer, Method::Invite, 180).await?;
        let mut cancel = request.clone();
        cancel.method = Method::Cancel;
        cancel.headers.unique_push(Header::CSeq("10 CANCEL".into()));
        cancel.body.clear();
        cancel
            .headers
            .retain(|h| !matches!(h, Header::ContentType(_)));
        cancel.headers.unique_push(Header::ContentLength(0.into()));
        peer.send_to(cancel.to_string().as_bytes(), local).await?;
        receive_response(&peer, Method::Cancel, 200).await?;
        if let Some(cancellation) = cancellation {
            tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
                .await
                .unwrap();
            let mut bytes = [0; 8192];
            assert!(
                tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut bytes))
                    .await
                    .is_err(),
                "observed CANCEL waits for the application final response"
            );
            handle.reply(487.into()).await.unwrap();
        }
        let (final_response, _) = receive_response(&peer, Method::Invite, 487).await?;
        assert!(!finished.is_cancelled(), "handler must still wait for ACK");
        let mut ack = request;
        ack.method = Method::Ack;
        ack.headers.unique_push(Header::CSeq("10 ACK".into()));
        ack.headers
            .unique_push(Header::To(final_response.to_header()?.clone()));
        ack.headers.retain(|h| !matches!(h, Header::ContentType(_)));
        ack.headers.unique_push(Header::ContentLength(0.into()));
        ack.body.clear();
        peer.send_to(ack.to_string().as_bytes(), local).await?;
        tokio::time::timeout(Duration::from_secs(1), finished.cancelled())
            .await
            .unwrap();
        assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
    }
    Ok(())
}

fn success_with_offer(request: &crate::sip::Request, contact: &str) -> crate::Result<Response> {
    let mut success = Response::try_from(response(request, 200, "OK", contact).as_str())?;
    success.body = OFFER.to_vec();
    success
        .headers
        .unique_push(Header::ContentType("application/sdp".into()));
    success
        .headers
        .unique_push(Header::ContentLength((OFFER.len() as u32).into()));
    Ok(success)
}

#[tokio::test]
async fn dropping_awaiter_keeps_transaction_alive_and_cancellable() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish(&token).await?;
    let request = dialog.prepare_reinvite(None, Some(OFFER.to_vec()))?;
    let cancellation = CancellationToken::new();
    let options = ReinviteOptions {
        cancellation: cancellation.clone(),
        ..Default::default()
    };
    let sender = dialog.clone();
    let task = tokio::spawn(async move { sender.send_reinvite(request, options).await });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    cancellation.cancel();
    reply(&peer, address, &request, 100, "Trying").await;
    let (cancel, _) = recv_request(&peer, Method::Cancel).await;
    assert_eq!(cancel.via_header()?, request.via_header()?);
    reply(&peer, address, &cancel, 200, "OK").await;
    reply(&peer, address, &request, 487, "Request Terminated").await;
    recv_request(&peer, Method::Ack).await;
    assert!(dialog.state().is_confirmed());
    Ok(())
}

#[tokio::test]
async fn local_bye_waits_for_deferred_ack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish(&token).await?;
    let (offers, mut received_offer) = mpsc::channel(1);
    let (answers, receive_answer) = mpsc::channel(1);
    let handler = Arc::new(Answer {
        offers,
        answers: Mutex::new(receive_answer),
    });
    let request = dialog.prepare_reinvite(None, None)?;
    let sender = dialog.clone();
    let task = tokio::spawn(async move {
        sender
            .send_reinvite(
                request,
                ReinviteOptions {
                    answer_handler: Some(handler),
                    ..Default::default()
                },
            )
            .await
    });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    let success = success_with_offer(&request, &format!("sip:peer@{}", peer.local_addr()?))?;
    peer.send_to(success.to_string().as_bytes(), address)
        .await?;
    tokio::time::timeout(Duration::from_secs(1), received_offer.recv())
        .await
        .unwrap()
        .unwrap();
    let sender = dialog.clone();
    let bye = tokio::spawn(async move { sender.bye().await });
    let mut packet = [0; 8192];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut packet))
            .await
            .is_err()
    );
    answers.send(ANSWER.to_vec()).await.unwrap();
    // Do not skip packets: the first outgoing request must be ACK, then BYE.
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut packet))
        .await
        .unwrap()?;
    let ack = crate::sip::Request::try_from(std::str::from_utf8(&packet[..len]).unwrap())?;
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(ack.body, ANSWER);
    let (request, address) = recv_request(&peer, Method::Bye).await;
    reply(&peer, address, &request, 200, "OK").await;
    bye.await.unwrap()?;
    assert_eq!(task.await.unwrap()?.unwrap().status_code.code(), 200);
    assert!(dialog.state().is_terminated());
    Ok(())
}

struct FailedAnswer {
    wait: bool,
}
#[async_trait::async_trait]
impl InviteAnswerHandler for FailedAnswer {
    async fn answer(&self, _: Response) -> crate::Result<AckBody> {
        if self.wait {
            futures::future::pending::<()>().await;
        }
        Err(crate::Error::Error("other leg could not answer".into()))
    }
    fn fallback_answer(&self, _: &Response) -> AckBody {
        AckBody::sdp(REJECTED.to_vec())
    }
}

#[tokio::test]
async fn failed_or_expired_answer_sends_rejecting_ack_then_bye() -> crate::Result<()> {
    for wait in [false, true] {
        let token = CancellationToken::new();
        let _guard = token.clone().drop_guard();
        let (dialog, _states, peer) = establish_with_options(
            &token,
            None,
            crate::transaction::endpoint::EndpointOption {
                t1: Duration::from_millis(5),
                t1x64: Duration::from_millis(320),
                ..Default::default()
            },
        )
        .await?;
        let request = dialog.prepare_reinvite(None, None)?;
        let sender = dialog.clone();
        let task = tokio::spawn(async move {
            sender
                .send_reinvite(
                    request,
                    ReinviteOptions {
                        answer_handler: Some(Arc::new(FailedAnswer { wait })),
                        ..Default::default()
                    },
                )
                .await
        });
        let (request, address) = recv_request(&peer, Method::Invite).await;
        let success = success_with_offer(&request, &format!("sip:peer@{}", peer.local_addr()?))?;
        peer.send_to(success.to_string().as_bytes(), address)
            .await?;
        // Race a local teardown with the timed-out answer. It must join the
        // cleanup, not fail or issue a second BYE before the rejecting ACK.
        let local_bye = if wait {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let sender = dialog.clone();
            Some(tokio::spawn(async move { sender.bye().await }))
        } else {
            None
        };
        let (ack, _) = recv_request(&peer, Method::Ack).await;
        assert_eq!(ack.body, REJECTED);
        let (bye, _) = recv_request(&peer, Method::Bye).await;
        reply(&peer, address, &bye, 200, "OK").await;
        if let Some(local_bye) = local_bye {
            local_bye.await.unwrap()?;
        }
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(dialog.state().is_terminated());
        if !wait {
            peer.send_to(success.to_string().as_bytes(), address)
                .await?;
            let (repeated, _) = recv_request(&peer, Method::Ack).await;
            assert_eq!(repeated, ack);
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_does_not_restart_invite_on_challenge() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, _states, peer) = establish_with_credential(&token, Some(credential())).await?;
    let request = dialog.prepare_reinvite(None, Some(OFFER.to_vec()))?;
    let cancellation = CancellationToken::new();
    let options = ReinviteOptions {
        cancellation: cancellation.clone(),
        ..Default::default()
    };
    let sender = dialog.clone();
    let task = tokio::spawn(async move { sender.send_reinvite(request, options).await });
    let (request, address) = recv_request(&peer, Method::Invite).await;
    reply(&peer, address, &request, 100, "Trying").await;
    cancellation.cancel();
    let (cancel, _) = recv_request(&peer, Method::Cancel).await;
    reply(&peer, address, &cancel, 200, "OK").await;
    challenge(&peer, address, &request).await?;
    recv_request(&peer, Method::Ack).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()?
            .unwrap()
            .status_code
            .code(),
        401
    );
    assert!(dialog.state().is_confirmed());
    let mut packet = [0; 8192];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut packet))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn incoming_offerless_reinvite_exposes_only_matching_ack_answer() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (dialog, mut states, peer) = establish(&token).await?;
    let local = dialog
        .inner
        .endpoint_inner
        .transport_layer
        .get_listen_addrs()[0]
        .get_socketaddr()?;
    let remote = peer.local_addr()?;
    let id = dialog.id();
    let request = crate::sip::Request::try_from(format!(
        "INVITE sip:alice@{local} SIP/2.0\r\nVia: SIP/2.0/UDP {remote};branch=z9hG4bK-offerless\r\nMax-Forwards: 70\r\nFrom: <sip:peer@{remote}>;tag={}\r\nTo: <sip:alice@{local}>;tag={}\r\nCall-ID: {}\r\nCSeq: 10 INVITE\r\nContact: <sip:peer@{remote}>\r\nContent-Length: 0\r\n\r\n",
        id.remote_tag, id.local_tag, id.call_id
    ).as_str())?;
    peer.send_to(request.to_string().as_bytes(), local).await?;
    let handle = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(event) = states.recv().await {
            if let DialogState::Updated(_, _, handle) = event {
                return handle;
            }
        }
        panic!("missing re-INVITE event");
    })
    .await
    .unwrap();
    handle
        .respond(
            200.into(),
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(OFFER.to_vec()),
        )
        .await
        .unwrap();
    receive_response(&peer, Method::Invite, 200).await?;
    let awaiting_ack = dialog.snapshot();
    assert_eq!(awaiting_ack.runtime.pending.negotiations, 1);
    assert!(awaiting_ack.runtime.pending.remote_invite_awaiting_ack);
    assert!(!awaiting_ack.is_quiescent());
    let mut ack = request;
    ack.method = Method::Ack;
    ack.headers.unique_push(Header::CSeq("9 ACK".into()));
    ack.headers
        .unique_push(Header::ContentType("application/sdp".into()));
    ack.body = ANSWER.to_vec();
    ack.headers
        .unique_push(Header::ContentLength((ANSWER.len() as u32).into()));
    peer.send_to(ack.to_string().as_bytes(), local).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), handle.wait_ack())
            .await
            .is_err()
    );
    ack.headers.unique_push(Header::CSeq("10 ACK".into()));
    peer.send_to(ack.to_string().as_bytes(), local).await?;
    let received = tokio::time::timeout(Duration::from_secs(1), handle.wait_ack())
        .await
        .unwrap()?;
    assert_eq!(received.body, ANSWER);
    assert_eq!(received.cseq_header()?.seq()?, 10);
    assert!(dialog.state().is_confirmed());
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dialog.snapshot().is_quiescent() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("matching ACK must finish the snapshot negotiation");
    Ok(())
}
