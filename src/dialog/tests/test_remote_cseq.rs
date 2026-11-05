use super::test_dialog_states::create_invite_request;
use crate::dialog::{dialog::DialogInner, invite_dialog::InviteDialog, DialogId};
use crate::sip::{Header, Method, Request};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
};
use crate::EndpointBuilder;
use futures::FutureExt;
use std::sync::{atomic::Ordering, Arc, Barrier};
use tokio::sync::mpsc::unbounded_channel;

fn request(method: Method, cseq: u32) -> Request {
    let mut request = create_invite_request("alice", "bob", "remote-cseq");
    request
        .headers
        .unique_push(Header::CSeq(format!("{cseq} {method}").into()));
    request.headers.unique_push(Header::Via(
        format!("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bK-{cseq}-{method}").into(),
    ));
    request.method = method;
    request
}

fn dialog() -> (
    Arc<DialogInner>,
    tokio::sync::mpsc::UnboundedReceiver<TransactionEvent>,
) {
    let endpoint = EndpointBuilder::new().build();
    let (states, _) = unbounded_channel();
    let (tu, rx) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Server,
        DialogId {
            call_id: "remote-cseq".into(),
            local_tag: "bob".into(),
            remote_tag: "alice".into(),
        },
        request(Method::Invite, 1),
        endpoint.inner,
        states,
        None,
        None,
        tu,
    )
    .unwrap();
    (Arc::new(inner), rx)
}

fn handle(inner: &Arc<DialogInner>, method: Method, cseq: u32) {
    let request = request(method, cseq);
    let key = TransactionKey::from_request(&request, TransactionRole::Server).unwrap();
    let mut tx = Transaction::new_server(key, request, inner.endpoint_inner.clone(), None);
    // In an early server dialog these requests complete synchronously. This
    // exercises the actual dialog admission path without transport scheduling.
    InviteDialog::from_inner(inner.clone())
        .handle(&mut tx)
        .now_or_never()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn concurrent_requests_never_lose_the_highest_remote_cseq() {
    const THREADS: usize = 8;
    const ROUNDS: usize = 4096;
    let (inner, _tu) = dialog();
    let barrier = Barrier::new(THREADS);
    let runtime = tokio::runtime::Handle::current();
    let failures = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|thread| {
                let inner = &inner;
                let barrier = &barrier;
                let runtime = &runtime;
                scope.spawn(move || {
                    let _entered = runtime.enter();
                    let mut failures = 0;
                    for round in 0..ROUNDS {
                        let base = (round * THREADS) as u32;
                        barrier.wait();
                        handle(inner, Method::Options, base + thread as u32 + 1);
                        barrier.wait();
                        if thread == 0
                            && inner.remote_seq.load(Ordering::Relaxed) != base + THREADS as u32
                        {
                            failures += 1;
                        }
                    }
                    failures
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .sum::<usize>()
    });
    assert_eq!(
        failures, 0,
        "accepted requests failed to advance remote CSeq"
    );
}

#[tokio::test]
async fn ack_and_cancel_do_not_advance_remote_cseq() {
    for method in [Method::Ack, Method::Cancel] {
        let (inner, _tu) = dialog();
        inner.remote_seq.store(10, Ordering::Relaxed);
        handle(&inner, method, 20);
        assert_eq!(inner.remote_seq.load(Ordering::Relaxed), 10);
    }
}

#[tokio::test]
async fn ack_for_earlier_invite_is_forwarded_after_a_newer_request() {
    let (inner, mut tu) = dialog();
    handle(&inner, Method::Options, 20);
    handle(&inner, Method::Ack, 1);
    let TransactionEvent::Received(crate::sip::SipMessage::Request(ack), _) =
        tu.try_recv().unwrap()
    else {
        panic!("expected forwarded ACK");
    };
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(inner.remote_seq.load(Ordering::Relaxed), 20);
}

#[tokio::test]
async fn remote_cseq_accepts_gaps_and_repeated_values_without_regressing() {
    let (inner, _tu) = dialog();
    for seq in [1, 1, 5, 5, 3, 10, 10] {
        let previous = inner.remote_seq.load(Ordering::Relaxed);
        handle(&inner, Method::Options, seq);
        assert_eq!(inner.remote_seq.load(Ordering::Relaxed), previous.max(seq));
    }
}
