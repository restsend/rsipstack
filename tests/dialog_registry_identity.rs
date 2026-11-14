//! Dialog registry identity must not depend on the human-readable Display format.
use rsipstack::{
    dialog::{
        dialog::{DialogSnapshot, DialogSnapshotState},
        dialog_layer::DialogLayer,
        DialogId,
    },
    sip::ToTypedHeader,
    transaction::{
        key::{TransactionKey, TransactionRole},
        transaction::Transaction,
        EndpointBuilder,
    },
};

fn ids() -> [DialogId; 3] {
    [
        DialogId {
            call_id: "a-b".into(),
            local_tag: "c".into(),
            remote_tag: "d".into(),
        },
        DialogId {
            call_id: "a".into(),
            local_tag: "b-c".into(),
            remote_tag: "d".into(),
        },
        DialogId {
            call_id: "a".into(),
            local_tag: "b".into(),
            remote_tag: "c-d".into(),
        },
    ]
}

#[tokio::test]
async fn incoming_request_matching_uses_all_identity_components() -> rsipstack::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner.clone());
    let [present, absent, _] = ids();
    let (states, _) = layer.new_dialog_state_channel();
    assert!(layer.restore_from_snapshot(snapshot(present.clone())?, states)?);
    for id in [present.clone(), absent] {
        let request: rsipstack::sip::Request = format!(
            "OPTIONS sip:local@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-registry\r\nFrom: <sip:remote@127.0.0.1>;tag={}\r\nTo: <sip:local@127.0.0.1>;tag={}\r\nCall-ID: {}\r\nCSeq: 2 OPTIONS\r\nContent-Length: 0\r\n\r\n",
            id.remote_tag, id.local_tag, id.call_id,
        ).as_str().try_into()?;
        let tx = Transaction::new_server(
            TransactionKey::from_request(&request, TransactionRole::Server)?,
            request,
            endpoint.inner.clone(),
            None,
        );
        let matched = layer.match_dialog(&tx).map(|d| d.id());
        assert_eq!(matched, (id == present).then_some(id));
    }
    Ok(())
}

fn snapshot(id: DialogId) -> rsipstack::Result<DialogSnapshot> {
    Ok(DialogSnapshot {
        state: DialogSnapshotState::Confirmed,
        role: TransactionRole::Client,
        from: rsipstack::sip::From::from(format!("<sip:local@127.0.0.1>;tag={}", id.local_tag))
            .typed()?,
        to: rsipstack::sip::To::from(format!("<sip:remote@127.0.0.1>;tag={}", id.remote_tag))
            .typed()?,
        id,
        local_cseq: 1,
        remote_cseq: 0,
        local_contact: None,
        remote_uri: "sip:remote@127.0.0.1:5060".try_into()?,
        remote_contact: None,
        route_set: vec![],
        supports_100rel: false,
        session_id: None,
    })
}

#[tokio::test]
async fn distinct_structured_ids_with_colliding_display_restore_independently(
) -> rsipstack::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner.clone());
    let ids = ids();
    assert!(ids
        .windows(2)
        .all(|pair| pair[0] != pair[1] && pair[0].to_string() == pair[1].to_string()));
    let (states, _) = layer.new_dialog_state_channel();
    for id in &ids {
        assert!(
            layer.restore_from_snapshot(snapshot(id.clone())?, states.clone())?,
            "distinct ID was treated as already restored: {id:?}"
        );
    }
    assert_eq!(layer.len(), ids.len());
    for id in &ids {
        assert_eq!(layer.get_dialog(id).unwrap().id(), *id);
        assert!(!layer.restore_from_snapshot(snapshot(id.clone())?, states.clone())?);
    }
    layer.remove_dialog(&ids[1]);
    assert!(layer.get_dialog(&ids[1]).is_none());
    assert_eq!(layer.get_dialog(&ids[0]).unwrap().id(), ids[0]);
    assert_eq!(layer.get_dialog(&ids[2]).unwrap().id(), ids[2]);
    Ok(())
}

#[tokio::test]
async fn absent_id_never_finds_or_removes_another_dialog() -> rsipstack::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner.clone());
    let [present, absent, _] = ids();
    let (states, _) = layer.new_dialog_state_channel();
    assert!(layer.restore_from_snapshot(snapshot(present.clone())?, states)?);
    assert!(layer.get_dialog(&absent).is_none());
    layer.remove_dialog(&absent);
    assert_eq!(layer.get_dialog(&present).unwrap().id(), present);
    Ok(())
}

#[tokio::test]
async fn typed_enumeration_preserves_ids_and_legacy_lookup_rejects_ambiguity(
) -> rsipstack::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner.clone());
    let [first, second, _] = ids();
    let (states, _) = layer.new_dialog_state_channel();
    let display = first.to_string();
    assert!(layer.restore_from_snapshot(snapshot(first.clone())?, states.clone())?);
    assert_eq!(layer.get_dialog_with(&display).unwrap().id(), first);
    assert!(layer.restore_from_snapshot(snapshot(second.clone())?, states)?);
    let mut actual = layer.dialog_ids();
    actual.sort();
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    assert_eq!(actual, expected);
    assert_eq!(
        layer.all_dialog_ids(),
        vec![display.clone(), display.clone()]
    );
    assert!(
        layer.get_dialog_with(&display).is_none(),
        "ambiguous legacy lookup must not pick a dialog"
    );
    layer.remove_dialog(&first);
    assert_eq!(layer.get_dialog_with(&display).unwrap().id(), second);
    Ok(())
}
