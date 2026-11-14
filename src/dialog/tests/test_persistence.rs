//! Wire-level checks for storage barriers, failures, and teardown races.
use crate::dialog::{
    dialog::DialogStateReceiver,
    dialog_layer::DialogLayer,
    invitation::{InviteAsyncResult, InviteOption},
    invite_dialog::InviteDialog,
    lifecycle::{dialog_lifecycle_channel, DialogLifecycleKind, DialogLifecycleReceiver},
    persistence::{
        DialogCheckpoint, DialogCheckpointReason as Reason, DialogPersistence,
        DialogPersistenceConfig,
    },
};
use crate::sip::{prelude::HeadersExt, Method, Request, SipMessage, StatusCode, Uri};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc::unbounded_channel, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    Never,
    InitialRequest,
    Answer,
    ReinviteAnswer,
    ByeResponse,
    UasResponse,
    Info,
}

struct Storage {
    gate: Gate,
    entered: CancellationToken,
    release: CancellationToken,
    fail: AtomicBool,
    committed: Mutex<Vec<DialogCheckpoint>>,
    attempts: Mutex<Vec<DialogCheckpoint>>,
    inspecting: Mutex<Option<std::sync::Weak<crate::dialog::dialog::DialogInner>>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl Storage {
    fn new(gate: Gate) -> Arc<Self> {
        Arc::new(Self {
            gate,
            entered: CancellationToken::new(),
            release: CancellationToken::new(),
            fail: AtomicBool::new(false),
            committed: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
            inspecting: Mutex::new(None),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        })
    }
    fn matches(&self, c: &DialogCheckpoint) -> bool {
        match self.gate {
            Gate::Never => false,
            Gate::InitialRequest => {
                c.reason == Reason::OutgoingRequest
                    && matches!(&c.message, Some(SipMessage::Request(r)) if r.method == Method::Invite)
            }
            Gate::Answer => c.reason == Reason::BeforeAck,
            Gate::ReinviteAnswer => {
                c.reason == Reason::BeforeAck && c.snapshot.runtime.pending.negotiations != 0
            }
            Gate::ByeResponse => {
                c.reason == Reason::BeforeResponse
                    && matches!(&c.message, Some(SipMessage::Response(r)) if r.cseq_header().unwrap().method().unwrap() == Method::Bye)
            }
            Gate::UasResponse => {
                c.reason == Reason::BeforeResponse
                    && matches!(&c.message, Some(SipMessage::Response(r)) if r.status_code == StatusCode::OK && r.cseq_header().unwrap().method().unwrap() == Method::Invite)
            }
            Gate::Info => {
                c.reason == Reason::OutgoingRequest
                    && matches!(&c.message, Some(SipMessage::Request(r)) if r.method == Method::Info)
            }
        }
    }
    fn config(self: &Arc<Self>, timeout: Duration) -> DialogPersistenceConfig {
        DialogPersistenceConfig {
            handler: self.clone(),
            timeout,
        }
    }
}

struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl DialogPersistence for Storage {
    async fn save(&self, c: DialogCheckpoint) -> crate::Result<()> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _active = Active(&self.active);
        self.max_active.fetch_max(active, Ordering::SeqCst);
        let inspect = self
            .inspecting
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        if let Some(dialog) = inspect {
            // A callback must be able to inspect the dialog: no state lock is held.
            assert!(dialog.snapshot().runtime.revision >= c.snapshot.runtime.revision);
        }
        self.attempts.lock().unwrap().push(c.clone());
        if self.matches(&c) {
            self.entered.cancel();
            self.release.cancelled().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(crate::Error::Error("test storage failure".into()));
        }
        self.committed.lock().unwrap().push(c);
        Ok(())
    }
}

struct Call {
    peer: UdpSocket,
    local: std::net::SocketAddr,
    dialog: InviteDialog,
    facts: DialogLifecycleReceiver,
    _states: DialogStateReceiver,
    task: JoinHandle<InviteAsyncResult>,
    router: JoinHandle<()>,
    endpoint: JoinHandle<crate::Result<()>>,
    stop: CancellationToken,
}

impl Drop for Call {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
        self.router.abort();
        self.endpoint.abort();
    }
}

async fn start(storage: Arc<Storage>, timeout: Duration) -> crate::Result<Call> {
    let stop = CancellationToken::new();
    let transport = TransportLayer::new(stop.child_token());
    let udp =
        UdpConnection::create_connection("127.0.0.1:0".parse()?, None, Some(stop.child_token()))
            .await?;
    let local = udp.get_addr().get_socketaddr()?;
    transport.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(transport)
        .with_cancel_token(stop.child_token())
        .build();
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (sender, facts) = dialog_lifecycle_channel();
    layer.set_lifecycle_events(Some(sender));
    layer.set_persistence(Some(storage.config(timeout)))?;
    let mut incoming = endpoint.incoming_transactions()?;
    let endpoint_ref = endpoint.inner.clone();
    let endpoint = tokio::spawn(async move { endpoint_ref.serve().await });
    let routing = layer.clone();
    let router = tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            if let Some(mut dialog) = routing.match_dialog(&tx) {
                let _ = dialog.handle(&mut tx).await;
            } else {
                let _ = tx.reply(StatusCode::CallTransactionDoesNotExist).await;
            }
        }
    });
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{}", peer.local_addr()?).as_str())?,
        contact: Uri::try_from(format!("sip:alice@{local}").as_str())?,
        ..Default::default()
    };
    let (sender, states) = unbounded_channel();
    let (dialog, task) = layer.do_invite_async(option, sender)?;
    *storage.inspecting.lock().unwrap() = Some(Arc::downgrade(&dialog.inner));
    Ok(Call {
        peer,
        local,
        dialog,
        facts,
        _states: states,
        task,
        router,
        endpoint,
        stop,
    })
}

async fn receive(peer: &UdpSocket) -> SipMessage {
    let mut bytes = [0u8; 8192];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("SIP receive timeout")
        .unwrap();
    SipMessage::try_from(&bytes[..len]).unwrap()
}

async fn request(peer: &UdpSocket, method: Method) -> Request {
    let SipMessage::Request(r) = receive(peer).await else {
        panic!("expected request")
    };
    assert_eq!(r.method, method);
    r
}

fn response(request: &Request, contact: &str) -> String {
    let to = request.to_header().unwrap();
    let to = if to.tag().unwrap().is_some() {
        to.value().to_string()
    } else {
        format!("{};tag=peer", to.value())
    };
    format!("SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <{contact}>\r\nContent-Length: 0\r\n\r\n",
        request.via_header().unwrap().value(), request.from_header().unwrap().value(), request.call_id_header().unwrap().value(), request.cseq_header().unwrap().value())
}

async fn answer(call: &Call, invite: &Request) {
    call.peer
        .send_to(
            response(
                invite,
                &format!("sip:bob@{}", call.peer.local_addr().unwrap()),
            )
            .as_bytes(),
            call.local,
        )
        .await
        .unwrap();
}

async fn established(call: &mut Call) -> Request {
    let invite = request(&call.peer, Method::Invite).await;
    answer(call, &invite).await;
    request(&call.peer, Method::Ack).await;
    tokio::time::timeout(Duration::from_secs(2), &mut call.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    invite
}

async fn send_bye(call: &Call, invite: &Request, seq: u32) -> Vec<u8> {
    let bytes = format!("BYE sip:alice@{} SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bK-peer-bye{seq}\r\nFrom: <sip:bob@example.com>;tag=peer\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {seq} BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        call.local, call.peer.local_addr().unwrap(), invite.from_header().unwrap().value(), invite.call_id_header().unwrap().value()).into_bytes();
    call.peer.send_to(&bytes, call.local).await.unwrap();
    bytes
}

async fn silent(peer: &UdpSocket) {
    let mut bytes = [0u8; 8192];
    assert!(
        tokio::time::timeout(Duration::from_millis(40), peer.recv_from(&mut bytes))
            .await
            .is_err(),
        "SIP escaped the persistence barrier"
    );
}

async fn entered(store: &Storage) {
    tokio::time::timeout(Duration::from_secs(2), store.entered.cancelled())
        .await
        .unwrap();
}

#[tokio::test]
async fn persistence_initial_invite_waits_for_durable_write() -> crate::Result<()> {
    let store = Storage::new(Gate::InitialRequest);
    let call = start(store.clone(), Duration::from_secs(2)).await?;
    entered(&store).await;
    silent(&call.peer).await;
    store.release.cancel();
    let invite = request(&call.peer, Method::Invite).await;
    let saved = store.committed.lock().unwrap();
    assert_eq!(saved[0].snapshot.local_cseq, invite.cseq_header()?.seq()?);
    assert_eq!(store.max_active.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn persistence_failed_initial_write_sends_nothing() -> crate::Result<()> {
    let store = Storage::new(Gate::Never);
    store.fail.store(true, Ordering::SeqCst);
    let mut call = start(store, Duration::from_secs(1)).await?;
    assert!(tokio::time::timeout(Duration::from_secs(2), &mut call.task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    silent(&call.peer).await;
    assert!(call.dialog.persistence_status().unwrap().failure.is_some());
    Ok(())
}

#[tokio::test]
async fn persistence_timeout_poisoning_is_bounded() -> crate::Result<()> {
    let store = Storage::new(Gate::InitialRequest);
    let mut call = start(store.clone(), Duration::from_millis(30)).await?;
    assert!(tokio::time::timeout(Duration::from_secs(1), &mut call.task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    silent(&call.peer).await;
    store.release.cancel();
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    assert!(call
        .dialog
        .persistence_status()
        .unwrap()
        .failure
        .unwrap()
        .contains("timed out"));
    Ok(())
}

#[tokio::test]
async fn persistence_answer_waits_before_ack_and_fact_delivery() -> crate::Result<()> {
    let store = Storage::new(Gate::Answer);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let invite = request(&call.peer, Method::Invite).await;
    answer(&call, &invite).await;
    entered(&store).await;
    assert!(call.dialog.state().is_confirmed());
    assert!(call.dialog.snapshot().runtime.pending.initial_ack);
    assert!(call.facts.try_recv().is_err());
    silent(&call.peer).await;
    let original_time = call.dialog.snapshot().runtime.lifecycle[0].since_unix_epoch;
    store.release.cancel();
    request(&call.peer, Method::Ack).await;
    let fact = tokio::time::timeout(Duration::from_secs(1), call.facts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        fact.kind,
        DialogLifecycleKind::InviteAccepted { .. }
    ));
    assert_eq!(fact.occurred_at.since_unix_epoch, original_time);
    Ok(())
}

#[tokio::test]
async fn persistence_bye_during_answer_commit_keeps_original_facts() -> crate::Result<()> {
    let store = Storage::new(Gate::Answer);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let invite = request(&call.peer, Method::Invite).await;
    answer(&call, &invite).await;
    entered(&store).await;
    send_bye(&call, &invite, 2).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !call.dialog.state().is_terminated() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = call.dialog.snapshot();
    assert_eq!(before.runtime.lifecycle.len(), 3);
    assert!(call.facts.try_recv().is_err());
    silent(&call.peer).await;
    store.release.cancel();
    let messages = [receive(&call.peer).await, receive(&call.peer).await];
    assert!(messages
        .iter()
        .any(|m| matches!(m, SipMessage::Request(r) if r.method == Method::Ack)));
    assert!(messages
        .iter()
        .any(|m| matches!(m, SipMessage::Response(r) if r.status_code == StatusCode::OK)));
    for expected in 1..=3 {
        let fact = tokio::time::timeout(Duration::from_secs(1), call.facts.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fact.sequence, expected);
        assert_eq!(
            fact.occurred_at.since_unix_epoch,
            before.runtime.lifecycle[(expected - 1) as usize].since_unix_epoch
        );
    }
    assert_eq!(store.max_active.load(Ordering::SeqCst), 1);
    let revisions: Vec<_> = store
        .committed
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.snapshot.runtime.revision)
        .collect();
    assert!(revisions.windows(2).all(|w| w[0] <= w[1]));
    Ok(())
}

#[tokio::test]
async fn persistence_failed_answer_commit_returns_without_ack() -> crate::Result<()> {
    let store = Storage::new(Gate::Answer);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let invite = request(&call.peer, Method::Invite).await;
    answer(&call, &invite).await;
    entered(&store).await;
    store.fail.store(true, Ordering::SeqCst);
    store.release.cancel();
    assert!(tokio::time::timeout(Duration::from_secs(1), &mut call.task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    silent(&call.peer).await;
    answer(&call, &invite).await;
    silent(&call.peer).await;
    assert!(call.facts.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn persistence_failed_bye_response_is_not_cached_for_retransmit() -> crate::Result<()> {
    let store = Storage::new(Gate::ByeResponse);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let invite = established(&mut call).await;
    let bye = send_bye(&call, &invite, 2).await;
    entered(&store).await;
    silent(&call.peer).await;
    store.fail.store(true, Ordering::SeqCst);
    store.release.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while call.dialog.persistence_status().unwrap().failure.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    call.peer.send_to(&bye, call.local).await?;
    silent(&call.peer).await;
    Ok(())
}

#[tokio::test]
async fn persistence_concurrent_requests_commit_reserved_cseq_before_send() -> crate::Result<()> {
    let store = Storage::new(Gate::Info);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    established(&mut call).await;
    let first = call.dialog.clone();
    let second = call.dialog.clone();
    let a = tokio::spawn(async move { first.info(None, None).await });
    let b = tokio::spawn(async move { second.info(None, None).await });
    entered(&store).await;
    silent(&call.peer).await;
    store.release.cancel();
    let one = request(&call.peer, Method::Info).await;
    let two = request(&call.peer, Method::Info).await;
    assert_ne!(one.cseq_header()?.seq()?, two.cseq_header()?.seq()?);
    for req in [one, two] {
        let seq = req.cseq_header()?.seq()?;
        assert!(store.committed.lock().unwrap().iter().any(|c| c.reason == Reason::OutgoingRequest
            && c.snapshot.local_cseq >= seq && matches!(&c.message, Some(SipMessage::Request(r)) if r.cseq_header().unwrap().seq().unwrap() == seq)));
        call.peer
            .send_to(response(&req, "sip:bob@example.com").as_bytes(), call.local)
            .await?;
    }
    tokio::time::timeout(Duration::from_secs(1), a)
        .await
        .unwrap()
        .unwrap()?;
    tokio::time::timeout(Duration::from_secs(1), b)
        .await
        .unwrap()
        .unwrap()?;
    assert_eq!(store.max_active.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn persistence_worker_releases_dialog_and_handler_after_teardown() -> crate::Result<()> {
    use crate::dialog::dialog::DialogInner;
    use crate::dialog::DialogId;
    use crate::transaction::key::TransactionRole;
    // Isolate worker ownership from the INVITE Accepted transaction's Timer M.
    // That transaction intentionally retains its dialog to clean up forked 2xx.
    let store = Storage::new(Gate::Never);
    let req = super::test_dialog_states::create_invite_request("alice", "bob", "worker");
    let (states, _) = unbounded_channel();
    let (transactions, _) = unbounded_channel();
    let dialog = Arc::new(DialogInner::new(
        TransactionRole::Client,
        DialogId::try_from((&req, TransactionRole::Client))?,
        req,
        EndpointBuilder::new().build().inner,
        states,
        None,
        None,
        transactions,
    )?);
    dialog.configure_persistence(Some(store.config(Duration::from_secs(1))));
    dialog.checkpoint(Reason::SignalingCompleted, None).await?;
    let weak = Arc::downgrade(&dialog);
    drop(dialog);
    tokio::time::timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() || Arc::strong_count(&store) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("persistence worker retained a dialog or storage handler");
    Ok(())
}

#[tokio::test]
async fn persistence_uas_saves_before_200_and_after_ack() -> crate::Result<()> {
    let stop = CancellationToken::new();
    let (dialog, mut tx, _states, peer) =
        super::test_accept_before_handle::incoming_invite(&stop).await?;
    let store = Storage::new(Gate::UasResponse);
    dialog
        .inner
        .configure_persistence(Some(store.config(Duration::from_secs(2))));
    let (sender, mut facts) = dialog_lifecycle_channel();
    dialog.inner.lifecycle.lock().sender = Some(sender);
    let invite = tx.original.clone();
    let destination = crate::transport::SipAddr::try_from(&invite.uri)?.get_socketaddr()?;
    dialog.accept(None, None)?;
    let mut handler = dialog.clone();
    let task = tokio::spawn(async move { handler.handle(&mut tx).await });
    entered(&store).await;
    silent(&peer).await;
    assert!(facts.try_recv().is_err());
    store.release.cancel();
    let SipMessage::Response(response) = receive(&peer).await else {
        panic!("expected 200")
    };
    assert_eq!(response.status_code, StatusCode::OK);
    let event = tokio::time::timeout(Duration::from_secs(1), facts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        event.kind,
        DialogLifecycleKind::InviteAccepted { .. }
    ));
    let ack = format!("ACK {} SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bK-ack\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        invite.uri, peer.local_addr()?, response.from_header()?.value(), response.to_header()?.value(), response.call_id_header()?.value());
    peer.send_to(ack.as_bytes(), destination).await?;
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()?;
    let committed = store.committed.lock().unwrap();
    assert!(committed.last().unwrap().snapshot.is_quiescent());
    assert_eq!(
        committed.last().unwrap().snapshot.runtime.lifecycle.len(),
        1
    );
    assert!(committed
        .iter()
        .any(|c| c.reason == Reason::BeforeResponse && !c.snapshot.is_quiescent()));
    stop.cancel();
    Ok(())
}

#[tokio::test]
async fn persistence_uas_failed_write_never_sends_or_caches_200() -> crate::Result<()> {
    let stop = CancellationToken::new();
    let (dialog, mut tx, _states, peer) =
        super::test_accept_before_handle::incoming_invite(&stop).await?;
    let store = Storage::new(Gate::UasResponse);
    dialog
        .inner
        .configure_persistence(Some(store.config(Duration::from_secs(2))));
    dialog.accept(None, None)?;
    let mut handler = dialog.clone();
    let task = tokio::spawn(async move {
        let result = handler.handle(&mut tx).await;
        (result, tx.last_response.take())
    });
    entered(&store).await;
    store.fail.store(true, Ordering::SeqCst);
    store.release.cancel();
    let (result, last_response) = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(last_response.is_none());
    silent(&peer).await;
    assert!(dialog.snapshot().runtime.lifecycle.is_empty());
    stop.cancel();
    Ok(())
}

#[tokio::test]
async fn persistence_request_is_not_sent_if_peer_ends_during_commit() -> crate::Result<()> {
    let store = Storage::new(Gate::Info);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let invite = established(&mut call).await;
    let dialog = call.dialog.clone();
    let task = tokio::spawn(async move { dialog.info(None, None).await });
    entered(&store).await;
    send_bye(&call, &invite, 2).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !call.dialog.state().is_terminated() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    store.release.cancel();
    assert!(tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    let SipMessage::Response(response) = receive(&call.peer).await else {
        panic!("expected BYE response")
    };
    assert_eq!(response.status_code, StatusCode::OK);
    assert_eq!(response.cseq_header()?.method()?, Method::Bye);
    silent(&call.peer).await;
    Ok(())
}

#[tokio::test]
async fn persistence_incoming_reinvite_saves_response_and_ack_completion() -> crate::Result<()> {
    use crate::dialog::dialog::DialogState;
    let store = Storage::new(Gate::UasResponse);
    let mut call = start(store.clone(), Duration::from_secs(2)).await?;
    let initial = established(&mut call).await;
    store.committed.lock().unwrap().clear();
    let remote = call.peer.local_addr()?;
    let invite = Request::try_from(format!(
        "INVITE sip:alice@{} SIP/2.0\r\nVia: SIP/2.0/UDP {remote};branch=z9hG4bK-persist-reinvite\r\nFrom: <sip:bob@example.com>;tag=peer\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 10 INVITE\r\nContact: <sip:bob@{remote}>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        call.local, initial.from_header()?.value(), initial.call_id_header()?.value()
    ).as_str())?;
    call.peer
        .send_to(invite.to_string().as_bytes(), call.local)
        .await?;
    let handle = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(state) = call._states.recv().await {
            if let DialogState::Updated(_, _, handle) = state {
                return handle;
            }
        }
        panic!("missing re-INVITE handle");
    })
    .await
    .unwrap();
    handle.respond(StatusCode::OK, None, None).await?;
    entered(&store).await;
    let pending_revision = {
        let attempts = store.attempts.lock().unwrap();
        let before = attempts.last().unwrap();
        assert_eq!(before.reason, Reason::BeforeResponse);
        assert_eq!(before.snapshot.runtime.pending.negotiations, 1);
        assert!(!before.snapshot.is_quiescent());
        before.snapshot.runtime.revision
    };
    silent(&call.peer).await;
    store.release.cancel();
    let SipMessage::Response(response) = receive(&call.peer).await else {
        panic!("expected re-INVITE response");
    };
    assert_eq!(response.status_code, StatusCode::OK);
    assert_eq!(response.cseq_header()?.seq()?, 10);
    let mut ack = invite;
    ack.method = Method::Ack;
    ack.cseq_header_mut()?.mut_method(Method::Ack)?;
    call.peer
        .send_to(ack.to_string().as_bytes(), call.local)
        .await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let completed = store.committed.lock().unwrap().iter().any(|checkpoint| {
                checkpoint.reason == Reason::SignalingCompleted
                    && checkpoint.snapshot.is_quiescent()
                    && checkpoint.snapshot.runtime.revision > pending_revision
            });
            if completed {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("matching ACK must produce a quiescent checkpoint");
    assert!(call.dialog.snapshot().is_quiescent());
    Ok(())
}

#[tokio::test]
async fn persistence_reinvite_commit_precedes_deferred_ack_handler() -> crate::Result<()> {
    use crate::dialog::reinvite::{AckBody, InviteAnswerHandler, ReinviteOptions};
    use crate::sip::{Header, Response};
    struct DeferredAnswer {
        entered: CancellationToken,
        release: CancellationToken,
    }
    const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
    #[async_trait]
    impl InviteAnswerHandler for DeferredAnswer {
        async fn answer(&self, _: Response) -> crate::Result<AckBody> {
            self.entered.cancel();
            self.release.cancelled().await;
            Ok(AckBody::sdp(SDP.to_vec()))
        }
        fn fallback_answer(&self, _: &Response) -> AckBody {
            AckBody::sdp(SDP.to_vec())
        }
    }
    for fail in [false, true] {
        let store = Storage::new(Gate::ReinviteAnswer);
        let mut call = start(store.clone(), Duration::from_secs(2)).await?;
        established(&mut call).await;
        store.committed.lock().unwrap().clear();
        let handler = Arc::new(DeferredAnswer {
            entered: CancellationToken::new(),
            release: CancellationToken::new(),
        });
        let options = ReinviteOptions {
            answer_handler: Some(handler.clone()),
            ..Default::default()
        };
        let dialog = call.dialog.clone();
        let invite = dialog.prepare_reinvite(None, None)?;
        let sender = tokio::spawn(async move { dialog.send_reinvite(invite, options).await });
        let invite = request(&call.peer, Method::Invite).await;
        let mut success = Response::try_from(
            response(&invite, &format!("sip:bob@{}", call.peer.local_addr()?)).as_str(),
        )?;
        success.body = SDP.to_vec();
        success
            .headers
            .unique_push(Header::ContentType("application/sdp".into()));
        success
            .headers
            .unique_push(Header::ContentLength((SDP.len() as u32).into()));
        call.peer
            .send_to(success.to_string().as_bytes(), call.local)
            .await?;
        entered(&store).await;
        assert!(
            !handler.entered.is_cancelled(),
            "answer handler ran before storage committed"
        );
        assert!(!call.dialog.snapshot().is_quiescent());
        silent(&call.peer).await;
        store.fail.store(fail, Ordering::SeqCst);
        store.release.cancel();
        if fail {
            assert!(tokio::time::timeout(Duration::from_secs(2), sender)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            assert!(!handler.entered.is_cancelled());
            assert!(call.dialog.persistence_status().unwrap().failure.is_some());
            silent(&call.peer).await;
        } else {
            tokio::time::timeout(Duration::from_secs(2), handler.entered.cancelled())
                .await
                .unwrap();
            silent(&call.peer).await;
            handler.release.cancel();
            let ack = request(&call.peer, Method::Ack).await;
            assert_eq!(ack.body, SDP);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), sender)
                    .await
                    .unwrap()
                    .unwrap()?
                    .unwrap()
                    .status_code,
                StatusCode::OK
            );
            assert!(store.committed.lock().unwrap().iter().any(|checkpoint| {
                checkpoint.reason == Reason::SignalingCompleted
                    && checkpoint.snapshot.is_quiescent()
            }));
        }
    }
    Ok(())
}
