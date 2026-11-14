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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_never_mix_target_uri_and_contact() -> crate::Result<()> {
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    let original = snapshot(TransactionRole::Client);
    let (states, _) = unbounded_channel();
    layer.restore_from_snapshot(original.clone(), states)?;
    let Some(Dialog::Invite(dialog)) = layer.get_dialog(&original.id) else {
        unreachable!()
    };
    let uri = Uri::try_from("sip:target0@example.com")?;
    dialog.inner.set_remote_target(
        uri.clone(),
        Some(crate::sip::headers::untyped::Contact::from(
            crate::sip::typed::Contact::from(uri),
        )),
    );
    let writer = dialog.clone();
    let task = std::thread::spawn(move || {
        for n in 1..5000 {
            let uri = Uri::try_from(format!("sip:target{n}@example.com").as_str()).unwrap();
            writer.inner.set_remote_target(
                uri.clone(),
                Some(crate::sip::headers::untyped::Contact::from(
                    crate::sip::typed::Contact::from(uri),
                )),
            );
            writer.inner.update_remote_tag(&format!("tag{n}")).unwrap();
            writer.inner.increment_local_seq();
        }
    });
    let mut revision = 0;
    for _ in 0..5000 {
        let current = dialog.snapshot();
        use crate::sip::prelude::ToTypedHeader;
        assert_eq!(
            current.remote_uri,
            current.remote_contact.as_ref().unwrap().typed()?.uri
        );
        assert_eq!(current.id.remote_tag, current.to.tag().unwrap().value());
        assert!(current.runtime.revision >= revision);
        revision = current.runtime.revision;
    }
    task.join().unwrap();
    Ok(())
}

#[tokio::test]
async fn snapshot_restore_retains_facts_without_replaying_them() -> crate::Result<()> {
    use crate::dialog::dialog::{DialogState, TerminatedReason};
    use crate::dialog::lifecycle::{
        dialog_lifecycle_channel, DialogLifecycleKind as K, LifecycleTime,
    };
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    let original = snapshot(TransactionRole::Client);
    let (states, _) = unbounded_channel();
    layer.restore_from_snapshot(original.clone(), states.clone())?;
    let Some(Dialog::Invite(dialog)) = layer.get_dialog(&original.id) else {
        unreachable!()
    };
    dialog
        .inner
        .record_initial_acceptance(&crate::sip::Response::default(), LifecycleTime::now());
    let saved = dialog.snapshot();
    // Response::default() is 200 OK; this is an already established dialog.
    assert_eq!(saved.runtime.lifecycle.len(), 1);
    assert!(saved.is_quiescent());
    let restored = DialogLayer::new(EndpointBuilder::new().build().inner);
    let (sender, mut events) = dialog_lifecycle_channel();
    restored.set_lifecycle_events(Some(sender));
    assert!(restored.restore_from_snapshot(saved, states)?);
    assert!(events.try_recv().is_err());
    let Some(Dialog::Invite(dialog)) = restored.get_dialog(&original.id) else {
        unreachable!()
    };
    dialog.inner.transition(DialogState::Terminated(
        dialog.id(),
        TerminatedReason::Timeout,
    ));
    let event = events.try_recv().unwrap();
    assert_eq!(event.sequence, 2);
    assert!(matches!(event.kind, K::DialogTerminated { .. }));
    assert_eq!(dialog.snapshot().runtime.lifecycle.len(), 2);
    Ok(())
}

#[tokio::test]
async fn unfinished_or_corrupt_snapshot_is_not_silently_resumed() -> crate::Result<()> {
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    let (states, _) = unbounded_channel();
    let mut pending = snapshot(TransactionRole::Client);
    pending.runtime.pending.negotiations = 1;
    assert!(!pending.is_quiescent());
    assert!(layer
        .restore_from_snapshot(pending, states.clone())
        .is_err());
    let mut invalid = snapshot(TransactionRole::Client);
    invalid.runtime.revision = u64::MAX;
    assert!(layer.restore_from_snapshot(invalid, states).is_err());
    assert!(layer.is_empty());
    Ok(())
}
