//! An application may answer an INVITE (`accept()`) before it starts
//! `handle()` on the transaction. Once the 2xx is queued the UAS waits for
//! the ACK (RFC 3261 §13.3.1.4): `handle()` must not move the dialog from
//! `WaitAck` back to `Calling`.
#![allow(deprecated)]
use crate::dialog::{
    dialog::{Dialog, DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
    server_dialog::ServerInviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, SipMessage};
use crate::transaction::transaction::Transaction;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "accept-before-handle-test";

/// A new server INVITE dialog and its transaction, with `handle()` not yet
/// started, plus the raw UAC socket that sent the INVITE.
async fn incoming_invite(
    token: &CancellationToken,
) -> crate::Result<(InviteDialog, Transaction, DialogStateReceiver, UdpSocket)> {
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uas: SocketAddr = udp.get_addr().get_socketaddr()?;
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let mut incoming = endpoint.incoming_transactions()?;
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = peer.local_addr()?;
    let invite = format!(
        "INVITE sip:bob@{uas} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {addr};branch=z9hG4bK-invite\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@{addr}>;tag=uac-tag\r\n\
         To: <sip:bob@{uas}>\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@{addr}>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    peer.send_to(invite.as_bytes(), uas).await?;

    let tx = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("timeout waiting for the INVITE")
        .unwrap();
    let (state_sender, states) = unbounded_channel();
    let dialog = dialog_layer.get_or_create_server_invite(&tx, state_sender, None, None)?;
    Ok((dialog, tx, states, peer))
}

/// Whether the UAC receives the 2xx to its INVITE within `wait`.
async fn receives_invite_2xx(peer: &UdpSocket, wait: Duration) -> bool {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((len, _))) = tokio::time::timeout_at(deadline, peer.recv_from(&mut buf)).await {
        let Ok(SipMessage::Response(resp)) =
            SipMessage::try_from(std::str::from_utf8(&buf[..len]).unwrap())
        else {
            continue;
        };
        if resp.status_code.code() == 200
            && resp.cseq_header().unwrap().method().unwrap() == Method::Invite
        {
            return true;
        }
    }
    false
}

/// Every state notified so far, without waiting.
fn drain(states: &mut DialogStateReceiver) -> Vec<DialogState> {
    let mut out = Vec::new();
    while let Ok(state) = states.try_recv() {
        out.push(state);
    }
    out
}

fn assert_never_back_to_calling(states: &[DialogState]) {
    let after_wait_ack = states
        .iter()
        .skip_while(|s| !matches!(s, DialogState::WaitAck(..)));
    for state in after_wait_ack {
        assert!(
            !matches!(state, DialogState::Calling(_)),
            "dialog went back to Calling after WaitAck: {states:?}"
        );
    }
}

#[tokio::test]
async fn test_invite_dialog_accept_before_handle_stays_wait_ack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog, mut tx, mut states, peer) = incoming_invite(&token).await?;

    dialog.accept(None, None)?;
    let mut handler = dialog.clone();
    tokio::spawn(async move {
        let _ = handler.handle(&mut tx).await;
    });

    assert!(
        receives_invite_2xx(&peer, Duration::from_secs(1)).await,
        "handle() must send the queued 2xx"
    );
    assert!(
        matches!(dialog.state(), DialogState::WaitAck(..)),
        "dialog must wait for the ACK, got {}",
        dialog.state()
    );
    assert_never_back_to_calling(&drain(&mut states));

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_server_invite_dialog_accept_before_handle_stays_wait_ack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog, mut tx, mut states, peer) = incoming_invite(&token).await?;
    let server = ServerInviteDialog::try_from(&Dialog::Invite(dialog))?;

    server.accept(None, None)?;
    let mut handler = server.clone();
    tokio::spawn(async move {
        let _ = handler.handle(&mut tx).await;
    });

    assert!(
        receives_invite_2xx(&peer, Duration::from_secs(1)).await,
        "handle() must send the queued 2xx"
    );
    assert!(
        matches!(server.state(), DialogState::WaitAck(..)),
        "dialog must wait for the ACK, got {}",
        server.state()
    );
    assert!(
        server.inner.waiting_ack(),
        "waiting_ack() must hold until the ACK arrives"
    );
    assert_never_back_to_calling(&drain(&mut states));

    token.cancel();
    Ok(())
}
