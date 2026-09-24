//! Once a dialog has terminated (RFC 3261 §15: a BYE ends the dialog), the
//! state channel must not report it as anything else. A mid-dialog request
//! that the application answers after the peer's BYE must not produce a
//! `Confirmed` notification after `Terminated`.
use crate::dialog::{
    dialog::{Dialog, DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, Response, SipMessage, StatusCode};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "state-after-terminated-test";
const FROM_TAG: &str = "uac-tag";

/// A raw UAC peer.
struct Peer {
    socket: UdpSocket,
    uas: SocketAddr,
}

impl Peer {
    async fn send_request(&self, method: Method, cseq: u32, to_tag: Option<&str>) {
        let addr = self.socket.local_addr().unwrap();
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@{}>;tag={tag}", self.uas),
            None => format!("<sip:bob@{}>", self.uas),
        };
        let msg = format!(
            "{method} sip:bob@{uas} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch=z9hG4bK-{method}-{cseq}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@{addr}>;tag={FROM_TAG}\r\n\
             To: {to}\r\n\
             Call-ID: {CALL_ID}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@{addr}>\r\n\
             Content-Length: 0\r\n\r\n",
            uas = self.uas,
        );
        self.socket.send_to(msg.as_bytes(), self.uas).await.unwrap();
    }

    /// Wait for the final response to the request with `cseq`.
    async fn recv_final(&self, cseq: u32) -> Response {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf))
                    .await
                    .expect("timeout waiting for a final response")
                    .unwrap();
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
                let seq = resp.cseq_header().unwrap().seq().unwrap();
                if seq == cseq && resp.status_code.code() >= 200 {
                    return resp;
                }
            }
        }
    }
}

/// A UAS endpoint running the usual incoming-transaction loop.
async fn setup(
    token: &CancellationToken,
) -> crate::Result<(DialogStateReceiver, UnboundedReceiver<InviteDialog>, Peer)> {
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

    let (state_sender, states) = unbounded_channel();
    let (dialog_sender, dialogs) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            let has_to_tag = tx.original.to_header().unwrap().tag().unwrap().is_some();
            let dialog = if has_to_tag {
                dialog_layer.match_dialog(&tx)
            } else if tx.original.method == Method::Invite {
                let dialog = dialog_layer
                    .get_or_create_server_invite(&tx, state_sender.clone(), None, None)
                    .expect("server dialog");
                dialog_sender.send(dialog.clone()).unwrap();
                Some(Dialog::Invite(dialog))
            } else {
                None
            };
            if let Some(mut dialog) = dialog {
                tokio::spawn(async move {
                    let _ = dialog.handle(&mut tx).await;
                });
            }
        }
    });

    let peer = Peer {
        socket: UdpSocket::bind("127.0.0.1:0").await?,
        uas,
    };
    Ok((states, dialogs, peer))
}

async fn next_state(rx: &mut DialogStateReceiver) -> DialogState {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for dialog state")
        .expect("state channel closed")
}

#[tokio::test]
async fn test_info_answered_after_peer_bye_is_not_notified_as_confirmed() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;

    // Establish the call: INVITE, 200, ACK.
    peer.send_request(Method::Invite, 1, None).await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;
    let ok = peer.recv_final(1).await;
    let to_tag = ok.to_header()?.tag()?.expect("To tag").value().to_string();
    peer.send_request(Method::Ack, 1, Some(&to_tag)).await;
    while !matches!(next_state(&mut states).await, DialogState::Confirmed(..)) {}

    // An INFO arrives; the application takes a moment to answer it.
    peer.send_request(Method::Info, 2, Some(&to_tag)).await;
    let info = loop {
        if let DialogState::Info(_, _, handle) = next_state(&mut states).await {
            break handle;
        }
    };

    // Meanwhile the peer hangs up.
    peer.send_request(Method::Bye, 3, Some(&to_tag)).await;
    assert_eq!(peer.recv_final(3).await.status_code, StatusCode::OK);
    assert!(
        matches!(next_state(&mut states).await, DialogState::Terminated(..)),
        "the peer's BYE must terminate the dialog"
    );

    // Now the application answers the INFO.
    info.reply(StatusCode::OK).await.ok();
    assert_eq!(peer.recv_final(2).await.status_code, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut after = Vec::new();
    while let Ok(state) = states.try_recv() {
        after.push(state.to_string());
    }
    assert!(
        after.is_empty(),
        "nothing may be notified after Terminated, got {after:?}"
    );
    assert!(dialog.state().is_terminated());

    token.cancel();
    Ok(())
}
