//! Every concurrent caller must receive the sequence number it reserved,
//! rather than a later value loaded after another caller increments it.
use super::test_dialog_states::create_invite_request;
use crate::dialog::{dialog::DialogInner, dialog_layer::DialogLayer, DialogId};
use crate::transaction::{key::TransactionRole, transaction::transaction_event_sender_noop};
use crate::EndpointBuilder;
use std::sync::{Arc, Barrier};
use tokio::sync::mpsc::unbounded_channel;

fn assert_unique_sequences(next: impl Fn() -> u32 + Sync, initial: u32) {
    const THREADS: usize = 8;
    const REQUESTS: usize = 8_192;
    let barrier = Barrier::new(THREADS);
    let mut sequences = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let next = &next;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    (0..REQUESTS).map(|_| next()).collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    sequences.sort_unstable();
    let expected: Vec<_> = (initial + 1..=initial + (THREADS * REQUESTS) as u32).collect();
    // Report the first mismatch, not thousands of sequence numbers.
    for (actual, expected) in sequences.into_iter().zip(expected) {
        assert_eq!(actual, expected, "duplicate or missing reserved CSeq");
    }
}

#[tokio::test]
async fn concurrent_dialog_requests_reserve_distinct_cseq() -> crate::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let (states, _receiver) = unbounded_channel();
    let dialog = Arc::new(DialogInner::new(
        TransactionRole::Client,
        DialogId {
            call_id: "concurrent-cseq".into(),
            local_tag: "alice".into(),
            remote_tag: "bob".into(),
        },
        create_invite_request("alice", "bob", "concurrent-cseq"),
        endpoint.inner,
        states,
        None,
        None,
        transaction_event_sender_noop(),
    )?);
    assert_unique_sequences(|| dialog.increment_local_seq(), dialog.get_local_seq());
    Ok(())
}

#[test]
fn concurrent_dialog_creation_reserves_distinct_cseq() {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner);
    assert_unique_sequences(|| layer.increment_last_seq(), 0);
}
