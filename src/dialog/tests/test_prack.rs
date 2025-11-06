use super::test_dialog_states::{create_invite_request, create_test_endpoint};
use crate::dialog::{dialog::DialogInner, server_dialog::ServerInviteDialog, DialogId};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{
    channel::ChannelConnection, connection::TransportEvent, SipAddr, SipConnection,
};
use rsip::headers::*;
use rsip::{Header, Method, Request, SipMessage, StatusCode};
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn server_dialog_handles_prack_request() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-prack".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "bob-tag".to_string(),
    };

    let invite_req = create_invite_request(&dialog_id.from_tag, "", &dialog_id.call_id);

    let dialog_inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
        tu_sender,
    )?;

    let mut server_dialog = ServerInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Build PRACK request
    let prack_request = Request {
        method: Method::PRack,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKprack01").into(),
            CSeq::new("2 PRACK").into(),
            From::new(&format!(
                "Alice <sip:alice@example.com>;tag={}",
                dialog_id.from_tag
            ))
            .into(),
            To::new(&format!(
                "Bob <sip:bob@example.com>;tag={}",
                dialog_id.to_tag
            ))
            .into(),
            CallId::new(&dialog_id.call_id).into(),
            Header::Other("RAck".into(), "1 1 INVITE".into()),
            Contact::new("<sip:alice@198.51.100.1:5060>").into(),
            MaxForwards::new("70").into(),
            Header::ContentLength((0u32).into()),
        ]
        .into(),
        version: rsip::Version::V2,
        body: vec![],
    };

    let key = TransactionKey::from_request(&prack_request, TransactionRole::Server)?;

    let (_, incoming_rx) = unbounded_channel();
    let (transport_tx, mut transport_rx) = unbounded_channel();

    let sip_addr: SipAddr = rsip::HostWithPort::try_from("127.0.0.1:5060")?.into();

    let channel =
        ChannelConnection::create_connection(incoming_rx, transport_tx, sip_addr.clone(), None)
            .await?;
    let connection = SipConnection::Channel(channel);

    let mut tx =
        Transaction::new_server(key, prack_request, endpoint.inner.clone(), Some(connection));
    tx.destination = Some(sip_addr.clone());

    server_dialog.handle(&mut tx).await?;

    let event = timeout(Duration::from_secs(1), transport_rx.recv())
        .await
        .expect("timeout waiting for PRACK response")
        .expect("transport event");
    match event {
        TransportEvent::Incoming(SipMessage::Response(resp), _, _) => {
            assert_eq!(resp.status_code, StatusCode::OK);
        }
        other => panic!("unexpected transport event: {other:?}"),
    }

    Ok(())
}
