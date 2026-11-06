//! Exercise reconstruction through the public API, as a downstream crate.
#![cfg(feature = "platform-tokio")]

use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogSnapshot, DialogSnapshotState, SessionIdState},
        dialog_layer::DialogLayer,
        lifecycle::{dialog_lifecycle_channel, DialogLifecycleKind},
        snapshot::{DialogLifecycleRecord, DialogSnapshotBuilder, DialogSnapshotRuntime},
        DialogId,
    },
    sip::{prelude::ToTypedHeader, StatusCode},
    transaction::key::TransactionRole,
    EndpointBuilder,
};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn builder() -> TestResult<DialogSnapshotBuilder> {
    Ok(DialogSnapshot::builder(
        DialogId {
            call_id: "stored-call".into(),
            local_tag: "local".into(),
            remote_tag: "remote".into(),
        },
        TransactionRole::Client,
        rsipstack::sip::headers::From::from("<sip:alice@example.com>;tag=local").typed()?,
        rsipstack::sip::headers::To::from("<sip:bob@example.com>;tag=remote").typed()?,
        "sip:bob@127.0.0.1:5061".try_into()?,
    ))
}

fn snapshot(history: Vec<DialogLifecycleRecord>) -> TestResult<DialogSnapshot> {
    let mut runtime = DialogSnapshotRuntime::default();
    runtime.revision = 42;
    runtime.lifecycle = history;
    Ok(builder()?
        .state(DialogSnapshotState::Confirmed)
        .local_cseq(7)
        .remote_cseq(3)
        .local_contact(Some("sip:alice@127.0.0.1:5060".try_into()?))
        .runtime(runtime)
        .build()?)
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
        // Builder and restore both validate: public fields remain mutable.
        assert!(snapshot(vec![record.clone()]).is_err());
        let mut corrupted = snapshot(vec![])?;
        corrupted.runtime.lifecycle.push(record);
        assert!(layer.restore_from_snapshot(corrupted, states).is_err());
        assert!(layer.is_empty());
    }
    Ok(())
}

#[test]
fn builder_requires_recovery_inputs_instead_of_guessing_defaults() -> TestResult {
    let base = builder()?;
    let state = DialogSnapshotState::Confirmed;
    let runtime = DialogSnapshotRuntime::default();
    for (builder, missing) in [
        (
            base.clone()
                .local_cseq(1)
                .remote_cseq(0)
                .runtime(runtime.clone()),
            "state",
        ),
        (
            base.clone()
                .state(state)
                .remote_cseq(0)
                .runtime(runtime.clone()),
            "local CSeq",
        ),
        (
            base.clone().state(state).local_cseq(1).runtime(runtime),
            "remote CSeq",
        ),
        (
            base.state(state).local_cseq(1).remote_cseq(0),
            "runtime metadata",
        ),
    ] {
        let error = builder
            .build()
            .expect_err("required input must not default");
        assert!(error.to_string().contains(missing), "{error}");
    }
    Ok(())
}

#[tokio::test]
async fn explicit_legacy_migration_uses_only_optional_defaults() -> TestResult {
    let saved = builder()?
        .state(DialogSnapshotState::Confirmed)
        .local_cseq(42)
        .remote_cseq(0)
        // The application has established that the legacy record was quiescent.
        .runtime(DialogSnapshotRuntime::default())
        .build()?;
    assert!(saved.local_contact.is_none());
    assert!(saved.remote_contact.is_none());
    assert!(saved.route_set.is_empty());
    assert!(!saved.supports_100rel);
    assert!(saved.session_id.is_none());
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    let (states, _) = layer.new_dialog_state_channel();
    let id = saved.id.clone();
    assert!(layer.restore_from_snapshot(saved, states)?);
    let Some(Dialog::Invite(dialog)) = layer.get_dialog(&id) else {
        panic!("restored dialog missing");
    };
    let saved = dialog.snapshot();
    assert_eq!(saved.local_cseq, 42);
    assert_eq!(saved.remote_cseq, 0);
    assert_eq!(saved.runtime.revision, 0);
    assert!(saved.runtime.lifecycle.is_empty());
    Ok(())
}

#[test]
fn builder_preserves_all_supplied_fields_and_allows_non_exhaustive_patterns() -> TestResult {
    let mut stored = snapshot(vec![DialogLifecycleRecord::new(
        1,
        Some(Duration::from_nanos(123)),
        DialogLifecycleKind::InviteAccepted {
            status: StatusCode::OK,
        },
    )])?;
    stored.remote_contact = Some(rsipstack::sip::headers::Contact::from(
        "<sip:bob@127.0.0.1:5061>",
    ));
    stored.route_set = vec![rsipstack::sip::Route::from("<sip:proxy@example.com;lr>")];
    stored.supports_100rel = true;
    stored.session_id = Some(SessionIdState {
        local: "0123456789abcdef0123456789abcdef".into(),
        remote: Some("abcdef0123456789abcdef0123456789".into()),
    });
    // A persistence adapter must explicitly map every stored field. Exercise
    // both roles without deriving either role or state from default values.
    for role in [TransactionRole::Client, TransactionRole::Server] {
        stored.role = role;
        let DialogSnapshot {
            id,
            role,
            from,
            to,
            remote_uri,
            state,
            local_cseq,
            remote_cseq,
            local_contact,
            remote_contact,
            route_set,
            supports_100rel,
            session_id,
            runtime,
            ..
        } = stored.clone();
        let rebuilt = DialogSnapshot::builder(id, role, from, to, remote_uri)
            .state(state)
            .local_cseq(local_cseq)
            .remote_cseq(remote_cseq)
            .local_contact(local_contact)
            .remote_contact(remote_contact)
            .route_set(route_set)
            .supports_100rel(supports_100rel)
            .session_id(session_id)
            .runtime(runtime)
            .build()?;
        assert_eq!(format!("{rebuilt:?}"), format!("{stored:?}"));
    }
    Ok(())
}

#[tokio::test]
async fn builder_preserves_each_pending_flag_and_restore_refuses_to_resume() -> TestResult {
    for flag in 0..7 {
        let mut runtime = DialogSnapshotRuntime::default();
        match flag {
            0 => runtime.pending.local_invite = true,
            1 => runtime.pending.remote_invite = true,
            2 => runtime.pending.remote_invite_awaiting_ack = true,
            3 => runtime.pending.initial_ack = true,
            4 => runtime.pending.negotiations = 2,
            5 => runtime.pending.local_termination = true,
            _ => runtime.pending.remote_termination = true,
        }
        let saved = builder()?
            .state(DialogSnapshotState::Confirmed)
            .local_cseq(7)
            .remote_cseq(3)
            .runtime(runtime.clone())
            .build()?;
        assert_eq!(saved.runtime.pending, runtime.pending);
        assert!(!saved.is_quiescent());
        let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
        let (states, _) = layer.new_dialog_state_channel();
        let error = layer.restore_from_snapshot(saved, states).unwrap_err();
        assert!(error.to_string().contains("unfinished signaling"));
        assert!(layer.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn builder_keeps_non_confirmed_snapshots_inspectable() -> TestResult {
    use rsipstack::dialog::dialog::TerminatedReason;
    let mut runtime = DialogSnapshotRuntime::default();
    runtime.revision = 1;
    runtime.lifecycle.push(DialogLifecycleRecord::new(
        1,
        None,
        DialogLifecycleKind::DialogTerminated {
            reason: TerminatedReason::Timeout,
        },
    ));
    let saved = builder()?
        .state(DialogSnapshotState::Terminated)
        .local_cseq(7)
        .remote_cseq(3)
        .runtime(runtime)
        .build()?;
    assert_eq!(saved.runtime.lifecycle.len(), 1);
    assert!(!saved.is_quiescent());
    let layer = DialogLayer::new(EndpointBuilder::new().build().inner);
    let (states, _) = layer.new_dialog_state_channel();
    assert!(!layer.restore_from_snapshot(saved, states)?);
    assert!(layer.is_empty());
    Ok(())
}
