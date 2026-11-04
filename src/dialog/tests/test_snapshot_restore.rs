use super::test_dialog_states::create_invite_request;
use crate::dialog::dialog::{Dialog, DialogInner, DialogSnapshot, DialogSnapshotState};
use crate::dialog::{dialog_layer::DialogLayer, DialogId};
use crate::sip::Uri;
use crate::transaction::key::TransactionRole;
use crate::EndpointBuilder;
use std::sync::{atomic::Ordering, Arc, Barrier};
use tokio::sync::mpsc::unbounded_channel;

fn snapshot(role: TransactionRole) -> DialogSnapshot {
    let endpoint = EndpointBuilder::new().build();
    let request = create_invite_request("alice-tag", "bob-tag", "restore-test");
    let id = DialogId::try_from((&request, role)).unwrap();
    let (states, _) = unbounded_channel();
    let (transactions, _) = unbounded_channel();
    let inner = DialogInner::new(
        role,
        id,
        request,
        endpoint.inner,
        states,
        None,
        None,
        transactions,
    )
    .unwrap();
    let mut snapshot = inner.snapshot();
    snapshot.state = DialogSnapshotState::Confirmed;
    snapshot.local_cseq = 42;
    snapshot
}

#[tokio::test]
async fn concurrent_snapshot_restore_has_one_winner() {
    const THREADS: usize = 8;
    const ROUNDS: usize = 64;
    for role in [TransactionRole::Client, TransactionRole::Server] {
        let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
        let original = snapshot(role);
        let barrier = Barrier::new(THREADS);
        let runtime = tokio::runtime::Handle::current();
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (layer, original, barrier, runtime) =
                        (&layer, &original, &barrier, &runtime);
                    scope.spawn(move || {
                        let _runtime = runtime.enter();
                        (0..ROUNDS)
                            .map(|round| {
                                let mut snapshot = original.clone();
                                snapshot.id.call_id = format!("restore-{round}");
                                let (states, _) = unbounded_channel();
                                barrier.wait();
                                let inserted = layer.restore_from_snapshot(snapshot, states);
                                // Every worker must finish before the next round.
                                barrier.wait();
                                inserted.unwrap()
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        for round in 0..ROUNDS {
            let winners = results.iter().filter(|worker| worker[round]).count();
            assert_eq!(winners, 1, "round {round}, role {role:?}");
        }
        assert_eq!(layer.len(), ROUNDS);
    }
}

#[tokio::test]
async fn repeated_snapshot_restore_preserves_live_dialog() -> crate::Result<()> {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
        let snapshot = snapshot(role);
        let (states, _) = unbounded_channel();
        assert!(layer.restore_from_snapshot(snapshot.clone(), states.clone())?);
        let Some(Dialog::Invite(live)) = layer.get_dialog(&snapshot.id) else {
            panic!("restored INVITE dialog missing");
        };
        live.inner.local_seq.store(100, Ordering::Relaxed);
        let refreshed = Uri::try_from("sip:refreshed@example.com")?;
        live.inner.set_remote_target(refreshed.clone(), None);

        assert!(!layer.restore_from_snapshot(snapshot.clone(), states)?);
        let Some(Dialog::Invite(retained)) = layer.get_dialog(&snapshot.id) else {
            panic!("live INVITE dialog missing");
        };
        assert!(Arc::ptr_eq(&live.inner, &retained.inner));
        assert_eq!(retained.snapshot().local_cseq, 100);
        assert_eq!(retained.snapshot().remote_uri, refreshed);
        assert!(!retained.cancel_token().is_cancelled());
    }
    Ok(())
}

#[tokio::test]
async fn snapshot_restore_still_skips_non_confirmed_states() -> crate::Result<()> {
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    for role in [TransactionRole::Client, TransactionRole::Server] {
        for state in [
            DialogSnapshotState::Calling,
            DialogSnapshotState::Trying,
            DialogSnapshotState::Early,
            DialogSnapshotState::WaitAck,
            DialogSnapshotState::Terminated,
        ] {
            let mut snapshot = snapshot(role);
            snapshot.state = state;
            let (states, _) = unbounded_channel();
            assert!(!layer.restore_from_snapshot(snapshot, states)?);
        }
    }
    assert!(layer.is_empty());
    Ok(())
}
