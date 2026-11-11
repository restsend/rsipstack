use super::test_dialog_states::create_invite_request;
use crate::dialog::{
    dialog::{DialogInner, DialogState, TransactionHandle},
    invite_dialog::InviteDialog,
    DialogId,
};
use crate::sip::{Header, HeadersExt, Method, Request, SipMessage, StatusCode};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
    TransactionState, TransactionTimer,
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use crate::EndpointBuilder;
use futures::FutureExt;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

struct Fixture {
    dialog: InviteDialog,
    states: UnboundedReceiver<DialogState>,
    conn: SipConnection,
    wire: UnboundedReceiver<TransportEvent>,
}

impl Fixture {
    async fn new(role: TransactionRole) -> Self {
        let endpoint = EndpointBuilder::new().build();
        let (_, incoming) = unbounded_channel();
        let (outgoing, wire) = unbounded_channel();
        let addr: SipAddr = "127.0.0.1:5060"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        let conn: SipConnection =
            ChannelConnection::create_connection(incoming, outgoing, addr, None)
                .await
                .unwrap()
                .into();
        endpoint.inner.transport_layer.add_transport(conn.clone());
        let (sender, states) = unbounded_channel();
        let (tu, _) = unbounded_channel();
        let id = DialogId {
            call_id: "overlap".into(),
            local_tag: if role == TransactionRole::Server {
                "bob"
            } else {
                "alice"
            }
            .into(),
            remote_tag: if role == TransactionRole::Server {
                "alice"
            } else {
                "bob"
            }
            .into(),
        };
        let inner = Arc::new(
            DialogInner::new(
                role,
                id.clone(),
                request(Method::Invite, 1),
                endpoint.inner,
                sender,
                None,
                Some("sip:bob@127.0.0.1:5060".try_into().unwrap()),
                tu,
            )
            .unwrap(),
        );
        inner.set_remote_target("sip:peer@127.0.0.1:5060".try_into().unwrap(), None);
        inner.set_server_connection(Some(conn.clone()));
        *inner.state.lock() = DialogState::Confirmed(id, Default::default());
        Self {
            dialog: InviteDialog::from_inner(inner),
            states,
            conn,
            wire,
        }
    }

    fn transaction(&self, method: Method, cseq: u32) -> Transaction {
        let mut req = request(method, cseq);
        if self.dialog.role() == TransactionRole::Client {
            req.headers
                .unique_push(Header::From("<sip:bob@example.com>;tag=bob".into()));
            req.headers
                .unique_push(Header::To("<sip:alice@example.com>;tag=alice".into()));
        }
        Transaction::new_server(
            TransactionKey::from_request(&req, TransactionRole::Server).unwrap(),
            req,
            self.dialog.inner.endpoint_inner.clone(),
            Some(self.conn.clone()),
        )
    }

    fn update_handle(&mut self) -> TransactionHandle {
        loop {
            match self.states.try_recv().unwrap() {
                DialogState::Updated(_, _, handle) => return handle,
                DialogState::Confirmed(_, _) => (),
                state => panic!("unexpected state: {state}"),
            }
        }
    }

    fn next_request(&mut self, method: Method) -> Request {
        while let Ok(event) = self.wire.try_recv() {
            if let TransportEvent::Incoming(SipMessage::Request(req), _, _) = event {
                if req.method == method {
                    return req;
                }
            }
        }
        panic!("no outgoing {method}");
    }

    fn respond(&self, req: &Request, status: StatusCode, headers: Vec<Header>) {
        let mut response = self
            .dialog
            .inner
            .endpoint_inner
            .make_response(req, status, None);
        for header in headers {
            response.headers.unique_push(header);
        }
        let key = TransactionKey::from_request(req, TransactionRole::Client).unwrap();
        self.dialog
            .inner
            .endpoint_inner
            .transactions
            .get(&key)
            .unwrap()
            .send(TransactionEvent::Received(
                response.into(),
                Some(self.conn.clone()),
            ))
            .unwrap();
    }

    fn assert_local_blocked(&self) {
        assert!(matches!(
            self.dialog.reinvite(None, None).now_or_never(),
            Some(Err(crate::Error::DialogError(
                _,
                _,
                StatusCode::RequestPending
            )))
        ));
    }

    fn assert_local_can_start(&mut self) {
        // Polling sends the INVITE; dropping this owned request future also
        // drops its transaction. This helper must leave no active reservation.
        assert!(self.dialog.reinvite(None, None).now_or_never().is_none());
        self.next_request(Method::Invite);
    }
}

fn request(method: Method, cseq: u32) -> Request {
    let mut req = create_invite_request("alice", "bob", "overlap");
    req.uri = "sip:bob@127.0.0.1:5060".try_into().unwrap();
    req.headers
        .unique_push(Header::Contact("<sip:peer@127.0.0.1:5060>".into()));
    req.headers.unique_push(Header::Via(
        format!("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-{cseq}-{method}").into(),
    ));
    req.headers
        .unique_push(Header::CSeq(format!("{cseq} {method}").into()));
    req.method = method;
    req
}

#[tokio::test]
async fn second_incoming_invite_is_rejected_before_application_dispatch() {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        let mut f = Fixture::new(role).await;
        let mut first = f.transaction(Method::Invite, 10);
        let mut dialog = f.dialog.clone();
        let mut handling = Box::pin(dialog.handle(&mut first));
        assert!(handling.as_mut().now_or_never().is_none());
        let _handle = f.update_handle();
        let mut second = f.transaction(Method::Invite, 11);
        let outcome = f.dialog.clone().handle(&mut second).now_or_never();
        assert!(
            matches!(outcome, Some(Ok(()))),
            "overlap reached application instead of being rejected"
        );
        let response = second.last_response.as_ref().unwrap();
        assert_eq!(response.status_code, StatusCode::ServerInternalError);
        let retry = response
            .headers
            .iter()
            .find_map(|header| match header {
                Header::RetryAfter(value) => Some(value.value().parse::<u32>().unwrap()),
                _ => None,
            })
            .expect("500 must carry Retry-After");
        assert!(retry <= 10);
        assert!(f.states.try_recv().is_err());
    }
}

#[tokio::test]
async fn outgoing_invite_blocks_both_outgoing_entry_points_and_incoming_glare() {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        let mut f = Fixture::new(role).await;
        let dialog = f.dialog.clone();
        let mut first = Box::pin(dialog.reinvite(None, None));
        assert!(first.as_mut().now_or_never().is_none());
        assert!(f.wire.try_recv().is_ok(), "first INVITE was not sent");
        for generic in [false, true] {
            let result = if generic {
                f.dialog.request(Method::Invite, None, None).now_or_never()
            } else {
                f.dialog.reinvite(None, None).now_or_never()
            };
            assert!(matches!(
                result,
                Some(Err(crate::Error::DialogError(
                    _,
                    _,
                    StatusCode::RequestPending
                )))
            ));
        }
        let mut incoming = f.transaction(Method::Invite, 10);
        f.dialog
            .clone()
            .handle(&mut incoming)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(
            incoming.last_response.as_ref().unwrap().status_code,
            StatusCode::RequestPending
        );
        assert!(f.states.try_recv().is_err());
    }
}

#[tokio::test]
async fn cancelling_handler_future_keeps_reservation_until_transaction_drop() {
    let mut f = Fixture::new(TransactionRole::Server).await;
    let mut tx = f.transaction(Method::Invite, 10);
    // now_or_never drops only the borrowing future, not tx.
    assert!(f.dialog.clone().handle(&mut tx).now_or_never().is_none());
    let _handle = f.update_handle();
    f.assert_local_blocked();
    drop(tx);
    f.assert_local_can_start();
    f.assert_local_can_start(); // old cleanup cannot clear a later reservation
}

#[tokio::test]
async fn cancelling_owned_outgoing_future_releases_its_transaction() {
    let mut f = Fixture::new(TransactionRole::Client).await;
    let dialog = f.dialog.clone();
    let mut sending = Box::pin(dialog.reinvite(None, None));
    assert!(sending.as_mut().now_or_never().is_none());
    f.next_request(Method::Invite);
    f.assert_local_blocked();
    drop(sending);
    f.assert_local_can_start();
}

#[tokio::test]
async fn server_final_response_allows_remote_retry_but_local_waits_for_ack() {
    for status in [StatusCode::OK, StatusCode::NotAcceptableHere] {
        let mut f = Fixture::new(TransactionRole::Server).await;
        let mut first = f.transaction(Method::Invite, 10);
        let first_events = first.tu_sender.clone();
        let mut dialog = f.dialog.clone();
        let mut handling = Box::pin(dialog.handle(&mut first));
        assert!(handling.as_mut().now_or_never().is_none());
        let handle = f.update_handle();
        handle.reply(status.clone()).await.unwrap();
        assert!(handling.as_mut().now_or_never().is_none());
        f.assert_local_blocked();

        // §14.2 only forbids a second incoming INVITE before the final
        // response. A previous final awaiting its ACK must not reject it.
        let mut second = f.transaction(Method::Invite, 11);
        assert!(f
            .dialog
            .clone()
            .handle(&mut second)
            .now_or_never()
            .is_none());
        let _second_handle = f.update_handle();
        drop(second);
        f.assert_local_blocked();

        first_events
            .send(TransactionEvent::Received(
                request(Method::Ack, 9).into(),
                None,
            ))
            .unwrap();
        assert!(handling.as_mut().now_or_never().is_none());
        f.assert_local_blocked(); // delayed ACK for another CSeq does not release
        first_events
            .send(TransactionEvent::Received(
                request(Method::Ack, 10).into(),
                None,
            ))
            .unwrap();
        assert!(matches!(handling.as_mut().now_or_never(), Some(Ok(()))));
        drop(handling);
        assert!(matches!(
            first.state,
            TransactionState::Confirmed | TransactionState::Terminated
        ));
        f.assert_local_can_start();
        drop(first); // cleanup after the reservation was already released
        f.assert_local_can_start();
    }
}

#[tokio::test]
async fn server_ack_timeout_releases_reservation() {
    for status in [StatusCode::OK, StatusCode::NotAcceptableHere] {
        let mut f = Fixture::new(TransactionRole::Server).await;
        let mut tx = f.transaction(Method::Invite, 10);
        assert!(f.dialog.clone().handle(&mut tx).now_or_never().is_none());
        let _handle = f.update_handle();
        tx.reply(status.clone()).await.unwrap();
        f.assert_local_blocked();
        let timer = if status == StatusCode::OK {
            TransactionTimer::TimerL(tx.key.clone())
        } else {
            TransactionTimer::TimerD(tx.key.clone())
        };
        tx.tu_sender.send(TransactionEvent::Timer(timer)).unwrap();
        assert!(matches!(tx.receive().now_or_never(), Some(None)));
        assert_eq!(tx.state, TransactionState::Terminated);
        f.assert_local_can_start();
    }
}

#[tokio::test]
async fn client_final_response_or_timeout_allows_next_invite() {
    for status in [
        StatusCode::OK,
        StatusCode::NotAcceptableHere,
        StatusCode::RequestPending,
        StatusCode::RequestTimeout,
    ] {
        let mut f = Fixture::new(TransactionRole::Client).await;
        let dialog = f.dialog.clone();
        let mut sending = Box::pin(dialog.reinvite(None, None));
        assert!(sending.as_mut().now_or_never().is_none());
        let req = f.next_request(Method::Invite);
        f.assert_local_blocked();
        if status == StatusCode::RequestTimeout {
            let key = TransactionKey::from_request(&req, TransactionRole::Client).unwrap();
            f.dialog
                .inner
                .endpoint_inner
                .transactions
                .get(&key)
                .unwrap()
                .send(TransactionEvent::Timer(TransactionTimer::TimerB(key)))
                .unwrap();
        } else {
            f.respond(
                &req,
                status.clone(),
                vec![Header::Contact("<sip:peer@127.0.0.1:5060>".into())],
            );
        }
        let response = sending.as_mut().now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(response.status_code, status);
        f.assert_local_can_start();
    }
}

#[tokio::test]
async fn auth_retry_reserves_its_new_invite_transaction() {
    use crate::dialog::authenticate::Credential;
    for status in [
        StatusCode::Unauthorized,
        StatusCode::ProxyAuthenticationRequired,
    ] {
        let mut f = Fixture::new(TransactionRole::Client).await;
        Arc::get_mut(&mut f.dialog.inner).unwrap().credential = Some(Credential {
            username: "alice".into(),
            password: "secret".into(),
            ..Default::default()
        });
        let dialog = f.dialog.clone();
        let mut sending = Box::pin(dialog.reinvite(None, None));
        assert!(sending.as_mut().now_or_never().is_none());
        let req = f.next_request(Method::Invite);
        let value = "Digest realm=\"test\", nonce=\"challenge\", algorithm=MD5";
        let challenge = if status == StatusCode::Unauthorized {
            Header::WwwAuthenticate(value.into())
        } else {
            Header::ProxyAuthenticate(value.into())
        };
        f.respond(&req, status, vec![challenge]);
        assert!(sending.as_mut().now_or_never().is_none());
        let retry = f.next_request(Method::Invite);
        assert!(
            retry.cseq_header().unwrap().seq().unwrap() > req.cseq_header().unwrap().seq().unwrap()
        );
        f.assert_local_blocked();
        f.respond(
            &retry,
            StatusCode::OK,
            vec![Header::Contact("<sip:peer@127.0.0.1:5060>".into())],
        );
        assert!(matches!(sending.as_mut().now_or_never(), Some(Ok(Some(_)))));
        f.assert_local_can_start();
    }
}

#[tokio::test]
async fn non_invite_requests_and_bye_remain_available_while_invite_pending() {
    let mut f = Fixture::new(TransactionRole::Client).await;
    let dialog = f.dialog.clone();
    let mut sending = Box::pin(dialog.reinvite(None, None));
    assert!(sending.as_mut().now_or_never().is_none());
    let invite = f.next_request(Method::Invite);
    for method in [Method::Info, Method::Update, Method::Options] {
        let mut request = Box::pin(dialog.request(method.clone(), None, None));
        assert!(request.as_mut().now_or_never().is_none());
        let wire_request = f.next_request(method);
        f.respond(&wire_request, StatusCode::OK, vec![]);
        assert!(matches!(request.as_mut().now_or_never(), Some(Ok(Some(_)))));
        f.assert_local_blocked();
    }
    let mut bye = Box::pin(dialog.bye());
    assert!(bye.as_mut().now_or_never().is_none());
    let wire_bye = f.next_request(Method::Bye);
    f.respond(&wire_bye, StatusCode::OK, vec![]);
    assert!(matches!(bye.as_mut().now_or_never(), Some(Ok(()))));
    assert!(dialog.inner.is_terminated());
    f.respond(&invite, StatusCode::NotAcceptableHere, vec![]);
    assert!(matches!(sending.as_mut().now_or_never(), Some(Ok(Some(_)))));
    assert!(dialog.inner.is_terminated());
    assert!(matches!(
        dialog.reinvite(None, None).now_or_never(),
        Some(Ok(None))
    ));
}

#[tokio::test]
async fn simultaneous_clones_start_only_one_outgoing_invite() {
    let mut f = Fixture::new(TransactionRole::Client).await;
    let barrier = std::sync::Barrier::new(8);
    let runtime = tokio::runtime::Handle::current();
    let winners = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let dialog = &f.dialog;
                let barrier = &barrier;
                let runtime = &runtime;
                scope.spawn(move || {
                    let _entered = runtime.enter();
                    let mut sending = Box::pin(dialog.reinvite(None, None));
                    barrier.wait();
                    let outcome = sending.as_mut().now_or_never();
                    barrier.wait(); // retain the winning transaction until all attempted
                    match outcome {
                        None => 1,
                        Some(Err(crate::Error::DialogError(_, _, StatusCode::RequestPending))) => 0,
                        other => panic!("unexpected result: {other:?}"),
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .sum::<usize>()
    });
    assert_eq!(winners, 1);
    f.next_request(Method::Invite);
    assert!(
        f.wire.try_recv().is_err(),
        "more than one INVITE reached the wire"
    );
    f.assert_local_can_start();
}

#[tokio::test]
async fn client_accepted_retransmission_window_does_not_block_next_invite() {
    let mut f = Fixture::new(TransactionRole::Client).await;
    let req = request(Method::Invite, 10);
    let mut tx = Transaction::new_client(
        TransactionKey::from_request(&req, TransactionRole::Client).unwrap(),
        req.clone(),
        f.dialog.inner.endpoint_inner.clone(),
        Some(f.conn.clone()),
    );
    f.dialog.inner.reserve_invite(&tx).unwrap();
    tx.send().await.unwrap();
    f.next_request(Method::Invite);
    f.assert_local_blocked();
    f.respond(
        &req,
        StatusCode::OK,
        vec![Header::Contact("<sip:peer@127.0.0.1:5060>".into())],
    );
    assert!(matches!(
        tx.receive().now_or_never(),
        Some(Some(SipMessage::Response(_)))
    ));
    assert_eq!(tx.state, TransactionState::Accepted);
    f.assert_local_can_start();
    // Retransmitted 2xx and eventual cleanup of the old transaction must not
    // clear the next transaction's independently acquired reservation.
    let dialog = f.dialog.clone();
    let mut next = Box::pin(dialog.reinvite(None, None));
    assert!(next.as_mut().now_or_never().is_none());
    f.respond(
        &req,
        StatusCode::OK,
        vec![Header::Contact("<sip:peer@127.0.0.1:5060>".into())],
    );
    assert!(matches!(tx.receive().now_or_never(), Some(Some(_))));
    drop(tx);
    f.assert_local_blocked();
}

/// Sending a state event wakes its receiver inside transition_locked. Probe the
/// id there so a lock inversion fails synchronously, without hanging a worker.
struct CheckReinviteId(Arc<DialogInner>);

impl std::task::Wake for CheckReinviteId {
    fn wake(self: Arc<Self>) {
        assert!(
            self.0.id.try_lock().is_some(),
            "re-INVITE took the state lock while holding the dialog id"
        );
    }
}

#[tokio::test]
async fn reinvite_releases_id_for_updated_and_confirmed() {
    let mut f = Fixture::new(TransactionRole::Server).await;
    let mut tx = f.transaction(Method::Invite, 10);
    let events = tx.tu_sender.clone();
    let mut dialog = f.dialog.clone();
    let mut handling = Box::pin(dialog.handle(&mut tx));
    let waker = std::task::Waker::from(Arc::new(CheckReinviteId(f.dialog.inner.clone())));
    let mut cx = std::task::Context::from_waker(&waker);

    assert!(f.states.poll_recv(&mut cx).is_pending());
    assert!(handling.as_mut().now_or_never().is_none());
    let handle = f.update_handle();
    handle.reply(StatusCode::OK).await.unwrap();
    assert!(handling.as_mut().now_or_never().is_none());

    assert!(f.states.poll_recv(&mut cx).is_pending());
    events
        .send(TransactionEvent::Received(
            request(Method::Ack, 10).into(),
            None,
        ))
        .unwrap();
    handling.await.unwrap();
    assert!(matches!(
        f.states.try_recv(),
        Ok(DialogState::Confirmed(..))
    ));
}

/// Keep the test's timer runnable even if both blocking mutexes deadlock.
fn dialog_worker(
    operation: impl std::future::Future<Output = crate::Result<()>> + Send + 'static,
) -> tokio::sync::oneshot::Receiver<crate::Result<()>> {
    let runtime = tokio::runtime::Handle::current();
    let (done, result) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = done.send(runtime.block_on(operation));
    });
    result
}

async fn race_reinvite_with_bye(local: bool) {
    use crate::dialog::dialog::TerminatedReason;
    use std::time::{Duration, Instant};

    let mut f = Fixture::new(TransactionRole::Server).await;
    let mut invite = f.transaction(Method::Invite, 10);
    let events = invite.tu_sender.clone();
    let mut dialog = f.dialog.clone();
    let mut reinvite = Box::pin(async move { dialog.handle(&mut invite).await });
    assert!(reinvite.as_mut().now_or_never().is_none());
    let handle = f.update_handle();
    handle.reply(StatusCode::OK).await.unwrap();
    assert!(reinvite.as_mut().now_or_never().is_none());
    let Ok(TransportEvent::Incoming(SipMessage::Response(ok), _, _)) = f.wire.try_recv() else {
        panic!("expected re-INVITE response");
    };
    assert_eq!(ok.status_code, StatusCode::OK);

    let reinvite = dialog_worker(reinvite);
    let mut dialog = f.dialog.clone();
    let mut incoming = f.transaction(Method::Bye, 11);
    let bye = {
        // Pause BYE at lifecycle recording while it owns state. The matching
        // ACK now drives the re-INVITE's transition back to Confirmed.
        let _gate = f.dialog.inner.lifecycle.lock();
        let bye = dialog_worker(async move {
            if local {
                dialog.bye().await
            } else {
                dialog.handle(&mut incoming).await?;
                assert_eq!(
                    incoming.last_response.as_ref().unwrap().status_code,
                    StatusCode::OK
                );
                Ok(())
            }
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !f.dialog.inner.state.is_locked() {
            assert!(
                Instant::now() < deadline,
                "BYE did not reach the state lock"
            );
            std::thread::yield_now();
        }
        events
            .send(TransactionEvent::Received(
                request(Method::Ack, 10).into(),
                None,
            ))
            .unwrap();
        while f.dialog.inner.remote_ack.lock().is_none() {
            assert!(
                Instant::now() < deadline,
                "re-INVITE did not receive its ACK"
            );
            std::thread::yield_now();
        }
        bye
    };
    if local {
        let Some(TransportEvent::Incoming(SipMessage::Request(bye), _, _)) = f.wire.recv().await
        else {
            panic!("expected outgoing BYE");
        };
        assert_eq!(bye.method, Method::Bye);
        f.respond(&bye, StatusCode::OK, Vec::new());
    }
    bye.await.unwrap().unwrap();
    reinvite.await.unwrap().unwrap();
    assert!(matches!(
        (local, f.dialog.state()),
        (true, DialogState::Terminated(_, TerminatedReason::UasBye))
            | (false, DialogState::Terminated(_, TerminatedReason::UacBye))
    ));
}

#[tokio::test]
async fn reinvite_completes_with_received_bye() {
    tokio::time::timeout(
        std::time::Duration::from_secs(4),
        race_reinvite_with_bye(false),
    )
    .await
    .expect("re-INVITE and received BYE deadlocked");
}

#[tokio::test]
async fn reinvite_completes_with_local_bye() {
    tokio::time::timeout(
        std::time::Duration::from_secs(4),
        race_reinvite_with_bye(true),
    )
    .await
    .expect("re-INVITE and local BYE deadlocked");
}

#[tokio::test]
async fn early_update_preserves_invite_lifecycle_and_refreshes_target() {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        for with_sdp in [false, true] {
            for final_status in [StatusCode::OK, StatusCode::NotAcceptableHere] {
                let mut fixture = Fixture::new(role).await;
                let id = fixture.dialog.id();
                *fixture.dialog.inner.state.lock() =
                    DialogState::Early(id.clone(), Default::default());
                let mut tx = fixture.transaction(Method::Update, 2);
                tx.original
                    .headers
                    .unique_push(Header::Contact("<sip:new@127.0.0.1:5090>".into()));
                tx.original.body = if with_sdp {
                    b"v=0\r\ns=changed media\r\n".to_vec()
                } else {
                    vec![]
                };
                let mut dialog = fixture.dialog.clone();
                let handler = async {
                    dialog.handle(&mut tx).await.unwrap();
                };
                let application = async {
                    let DialogState::Updated(event_id, request, handle) =
                        fixture.states.recv().await.unwrap()
                    else {
                        panic!("expected UPDATE before INVITE acceptance");
                    };
                    assert_eq!(event_id, id);
                    assert_eq!(!request.body.is_empty(), with_sdp);
                    assert!(matches!(fixture.dialog.state(), DialogState::Early(..)));
                    handle
                        .respond(
                            final_status.clone(),
                            None,
                            with_sdp.then(|| b"answer".to_vec()),
                        )
                        .await
                        .unwrap();
                };
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    tokio::join!(handler, application);
                })
                .await
                .expect("early UPDATE must receive a response");
                assert!(matches!(fixture.dialog.state(), DialogState::Early(..)));
                assert!(
                    fixture.states.try_recv().is_err(),
                    "UPDATE must not emit Confirmed"
                );
                let TransportEvent::Incoming(SipMessage::Response(response), _, _) =
                    fixture.wire.try_recv().unwrap()
                else {
                    panic!("expected UPDATE response");
                };
                assert_eq!(response.status_code, final_status);
                assert_eq!(
                    response.cseq_header().unwrap().method().unwrap(),
                    Method::Update
                );
                if final_status == StatusCode::OK {
                    assert_eq!(
                        fixture.dialog.snapshot().remote_uri.to_string(),
                        "sip:new@127.0.0.1:5090"
                    );
                } else {
                    assert_eq!(
                        fixture.dialog.snapshot().remote_uri.to_string(),
                        "sip:peer@127.0.0.1:5060"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn early_update_response_does_not_overwrite_racing_invite_state() {
    for confirmed in [false, true] {
        let mut fixture = Fixture::new(TransactionRole::Client).await;
        let id = fixture.dialog.id();
        *fixture.dialog.inner.state.lock() = DialogState::Early(id.clone(), Default::default());
        let mut tx = fixture.transaction(Method::Update, 2);
        let mut dialog = fixture.dialog.clone();
        let application = async {
            let DialogState::Updated(_, _, handle) = fixture.states.recv().await.unwrap() else {
                panic!("expected UPDATE");
            };
            let next = if confirmed {
                DialogState::Confirmed(id, Default::default())
            } else {
                DialogState::Terminated(id, crate::dialog::dialog::TerminatedReason::UacCancel)
            };
            fixture.dialog.inner.transition(next);
            handle.reply(StatusCode::OK).await.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (result, ()) = tokio::join!(dialog.handle(&mut tx), application);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(fixture.dialog.state().is_confirmed(), confirmed);
        assert_eq!(fixture.dialog.state().is_terminated(), !confirmed);
        fixture.states.try_recv().unwrap();
        assert!(fixture.states.try_recv().is_err());
    }
}

#[tokio::test]
async fn early_update_can_be_sent_without_confirming_dialog() {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        let mut fixture = Fixture::new(role).await;
        *fixture.dialog.inner.state.lock() =
            DialogState::Early(fixture.dialog.id(), Default::default());
        let dialog = fixture.dialog.clone();
        let mut update = Box::pin(dialog.update(None, Some(b"offer".to_vec())));
        assert!(update.as_mut().now_or_never().is_none());
        let request = fixture.next_request(Method::Update);
        assert_eq!(request.body, b"offer");
        fixture.respond(&request, StatusCode::OK, vec![]);
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), update)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status_code, StatusCode::OK);
        assert!(matches!(dialog.state(), DialogState::Early(..)));
        assert!(fixture.states.try_recv().is_err());
    }
}

#[tokio::test]
async fn early_update_registry_lookup_requires_the_learned_remote_tag() {
    let fixture = Fixture::new(TransactionRole::Client).await;
    let id = fixture.dialog.id();
    *fixture.dialog.inner.state.lock() = DialogState::Early(id.clone(), Default::default());
    let layer =
        crate::dialog::dialog_layer::DialogLayer::new(fixture.dialog.inner.endpoint_inner.clone());
    let mut pending_id = id.clone();
    pending_id.remote_tag.clear();
    layer.inner.dialogs.insert(
        pending_id.clone(),
        crate::dialog::dialog::Dialog::Invite(fixture.dialog.clone()),
    );
    let tx = fixture.transaction(Method::Update, 2);
    assert_eq!(layer.match_dialog(&tx).unwrap().id(), id);
    for wrong in [
        DialogId {
            remote_tag: "unrelated".into(),
            ..id.clone()
        },
        DialogId {
            local_tag: "unrelated".into(),
            ..id.clone()
        },
        DialogId {
            call_id: "unrelated".into(),
            ..id.clone()
        },
    ] {
        assert!(layer.get_dialog(&wrong).is_none());
        layer.remove_dialog(&wrong);
        assert_eq!(layer.len(), 1);
    }
    layer.remove_dialog(&id);
    assert!(layer.is_empty());
    assert!(layer.get_dialog(&pending_id).is_none());
}
