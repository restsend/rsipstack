//! Incoming request ordering applies equally to both original dialog roles.
use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogSnapshot, DialogSnapshotState},
        dialog_layer::DialogLayer,
        DialogId,
    },
    sip::{HeadersExt, Method, Request, SipMessage, StatusCode, ToTypedHeader},
    transaction::{
        key::{TransactionKey, TransactionRole},
        transaction::Transaction,
        EndpointBuilder,
    },
    transport::{channel::ChannelConnection, SipConnection, TransportEvent},
};
use tokio::sync::mpsc::unbounded_channel;

async fn reject_stale(role: TransactionRole, legacy: bool) -> rsipstack::Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let layer = DialogLayer::new(endpoint.inner.clone());
    let id = DialogId {
        call_id: "ordering".into(),
        local_tag: "local".into(),
        remote_tag: "remote".into(),
    };
    let local = "<sip:local@127.0.0.1>;tag=local";
    let remote = "<sip:remote@127.0.0.1>;tag=remote";
    let (from, to) = if role == TransactionRole::Client {
        (local, remote)
    } else {
        (remote, local)
    };
    let snapshot = DialogSnapshot {
        id: id.clone(),
        role,
        state: DialogSnapshotState::Confirmed,
        from: rsipstack::sip::From::from(from).typed()?,
        to: rsipstack::sip::To::from(to).typed()?,
        local_cseq: 1,
        remote_cseq: 10,
        local_contact: None,
        remote_uri: "sip:remote@127.0.0.1".try_into()?,
        remote_contact: None,
        route_set: vec![],
        supports_100rel: false,
        session_id: None,
    };
    let (states, mut events) = unbounded_channel();
    assert!(layer.restore_from_snapshot(snapshot, states)?);
    let Some(Dialog::Invite(mut dialog)) = layer.get_dialog(&id) else {
        panic!("missing dialog")
    };
    let (_, incoming) = unbounded_channel();
    let (outgoing, mut received) = unbounded_channel();
    let conn: SipConnection = ChannelConnection::create_connection(
        incoming,
        outgoing,
        "127.0.0.1:5060"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        None,
    )
    .await?
    .into();
    for method in [Method::Info, Method::Update, Method::Invite, Method::Bye] {
        let request: Request = format!("{method} sip:local@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-old-{method}\r\nFrom: {remote}\r\nTo: {local}\r\nCall-ID: ordering\r\nCSeq: 9 {method}\r\nContact: <sip:changed@127.0.0.1>\r\nContent-Length: 0\r\n\r\n").as_str().try_into()?;
        let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
        let mut tx =
            Transaction::new_server(key, request, endpoint.inner.clone(), Some(conn.clone()));
        #[allow(deprecated)]
        if legacy {
            match role {
                TransactionRole::Client => {
                    rsipstack::dialog::client_dialog::ClientInviteDialog::try_from(dialog.clone())?
                        .handle(&mut tx)
                        .await?
                }
                TransactionRole::Server => {
                    rsipstack::dialog::server_dialog::ServerInviteDialog::try_from(dialog.clone())?
                        .handle(&mut tx)
                        .await?
                }
            }
        } else {
            dialog.handle(&mut tx).await?;
        }
        let TransportEvent::Incoming(SipMessage::Response(response), _, _) = received
            .try_recv()
            .expect("stale request must receive a response")
        else {
            panic!("expected response")
        };
        assert_eq!(response.status_code, StatusCode::ServerInternalError);
        assert_eq!(response.cseq_header()?.method()?, method);
        let snapshot = dialog.snapshot();
        assert_eq!(snapshot.remote_cseq, 10);
        assert_eq!(snapshot.remote_uri.to_string(), "sip:remote@127.0.0.1");
        assert_eq!(snapshot.state, DialogSnapshotState::Confirmed);
        assert!(
            events.try_recv().is_err(),
            "stale request reached application"
        );
    }
    Ok(())
}

#[tokio::test]
async fn original_uac_rejects_stale_requests() -> rsipstack::Result<()> {
    reject_stale(TransactionRole::Client, false).await
}
#[tokio::test]
async fn original_uas_rejects_stale_requests() -> rsipstack::Result<()> {
    reject_stale(TransactionRole::Server, false).await
}
#[tokio::test]
async fn legacy_uac_rejects_stale_requests() -> rsipstack::Result<()> {
    reject_stale(TransactionRole::Client, true).await
}
#[tokio::test]
async fn legacy_uas_rejects_stale_requests() -> rsipstack::Result<()> {
    reject_stale(TransactionRole::Server, true).await
}
