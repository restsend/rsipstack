//! Exercise reconstruction through the public API, as a downstream crate.
#![cfg(feature = "platform-tokio")]

use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogSnapshot, DialogSnapshotState},
        dialog_layer::DialogLayer,
        lifecycle::{dialog_lifecycle_channel, DialogLifecycleKind},
        snapshot::{DialogLifecycleRecord, DialogSnapshotRuntime},
        DialogId,
    },
    sip::{prelude::ToTypedHeader, StatusCode},
    transaction::key::TransactionRole,
    EndpointBuilder,
};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn snapshot(history: Vec<DialogLifecycleRecord>) -> TestResult<DialogSnapshot> {
    let mut runtime = DialogSnapshotRuntime::default();
    runtime.revision = 42;
    runtime.lifecycle = history;
    Ok(DialogSnapshot {
        runtime,
        state: DialogSnapshotState::Confirmed,
        role: TransactionRole::Client,
        id: DialogId {
            call_id: "stored-call".into(),
            local_tag: "local".into(),
            remote_tag: "remote".into(),
        },
        from: rsipstack::sip::headers::From::from("<sip:alice@example.com>;tag=local").typed()?,
        to: rsipstack::sip::headers::To::from("<sip:bob@example.com>;tag=remote").typed()?,
        local_cseq: 7,
        remote_cseq: 3,
        local_contact: Some("sip:alice@127.0.0.1:5060".try_into()?),
        remote_uri: "sip:bob@127.0.0.1:5061".try_into()?,
        remote_contact: None,
        route_set: vec![],
        supports_100rel: false,
        session_id: None,
    })
}

#[tokio::test]
async fn external_application_can_reconstruct_persisted_lifecycle_history() -> TestResult {
    // These are application-decoded storage fields, not records cloned from a
    // live dialog. Both clock-bearing and clockless persisted facts are valid.
    for stored_timestamp in [Some(Duration::new(1_700_000_000, 123_456_789)), None] {
        let history = vec![DialogLifecycleRecord::new(
            1,
            stored_timestamp,
            DialogLifecycleKind::InviteAccepted {
                status: StatusCode::OK,
            },
        )];
        let mut saved = snapshot(history)?;
        // A second restart must retain the reconstructed history as well.
        for _ in 0..2 {
            let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
            let (sender, mut events) = dialog_lifecycle_channel();
            layer.set_lifecycle_events(Some(sender));
            let (states, _receiver) = layer.new_dialog_state_channel();
            let id = saved.id.clone();
            assert!(layer.restore_from_snapshot(saved, states)?);
            assert!(events.try_recv().is_err(), "restore must not replay facts");
            let Some(Dialog::Invite(dialog)) = layer.get_dialog(&id) else {
                panic!("restored dialog is missing");
            };
            saved = dialog.snapshot();
            assert!(saved.is_quiescent());
            assert_eq!(saved.runtime.revision, 42);
            assert_eq!(saved.runtime.lifecycle.len(), 1);
            let fact = &saved.runtime.lifecycle[0];
            assert_eq!(fact.sequence, 1);
            assert_eq!(fact.since_unix_epoch, stored_timestamp);
            assert!(matches!(
                fact.kind,
                DialogLifecycleKind::InviteAccepted {
                    status: StatusCode::OK
                }
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn reconstructed_records_still_pass_through_restore_validation() -> TestResult {
    for (sequence, status) in [(2, StatusCode::OK), (1, StatusCode::BusyHere)] {
        let record = DialogLifecycleRecord::new(
            sequence,
            None,
            DialogLifecycleKind::InviteAccepted { status },
        );
        let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
        let (states, _receiver) = layer.new_dialog_state_channel();
        assert!(layer
            .restore_from_snapshot(snapshot(vec![record])?, states)
            .is_err());
        assert!(layer.is_empty());
    }
    Ok(())
}
