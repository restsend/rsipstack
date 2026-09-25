//! When a UAS puts the offer in its 2xx (the INVITE or re-INVITE carried no
//! offer), the UAC's answer arrives in the ACK (RFC 3261 §13.2.1, §14.2;
//! RFC 3264 §4). The server dialog must make that ACK available to the
//! application, otherwise the offer/answer exchange can never complete.
use crate::dialog::{
    dialog::{DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, Response, SipMessage};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "ack-answer-test";
const FROM_TAG: &str = "uac-tag";
const OFFER: &str = "v=0\r\no=uas 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

fn answer(version: u32) -> String {
    format!(
        "v=0\r\no=uac 1 {version} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n"
    )
}

/// A raw UAC: builds requests by hand so the test controls every byte of the ACK.
struct Peer {
    socket: UdpSocket,
    uas: SocketAddr,
}

impl Peer {
    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    async fn send_request(
        &self,
        method: Method,
        cseq: u32,
        branch: &str,
        to_tag: Option<&str>,
        body: Option<&str>,
    ) {
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@{}>;tag={tag}", self.uas),
            None => format!("<sip:bob@{}>", self.uas),
        };
        let (content_type, body) = match body {
            Some(body) => ("Content-Type: application/sdp\r\n", body),
            None => ("", ""),
        };
        let msg = format!(
            "{method} sip:bob@{uas} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@{addr}>;tag={FROM_TAG}\r\n\
             To: {to}\r\n\
             Call-ID: {CALL_ID}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@{addr}>\r\n\
             {content_type}\
             Content-Length: {len}\r\n\r\n{body}",
            uas = self.uas,
            addr = self.addr(),
            len = body.len(),
        );
        self.socket.send_to(msg.as_bytes(), self.uas).await.unwrap();
    }

    /// Wait for the 2xx to the request with `cseq`, skipping anything else.
    async fn recv_2xx(&self, cseq: u32) -> Response {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf))
                    .await
                    .expect("timeout waiting for 2xx")
                    .unwrap();
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
                let seq = resp.cseq_header().unwrap().seq().unwrap();
                if seq == cseq && resp.status_code.code() / 100 == 2 {
                    return resp;
                }
            }
        }
    }
}

struct Uas {
    states: DialogStateReceiver,
    dialogs: tokio::sync::mpsc::UnboundedReceiver<InviteDialog>,
}

async fn setup(token: &CancellationToken) -> crate::Result<(Uas, Peer)> {
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

    // The usual UAS loop: in-dialog requests go to the matched dialog, an
    // out-of-dialog INVITE creates a server dialog.
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
                Some(crate::dialog::dialog::Dialog::Invite(dialog))
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
    Ok((Uas { states, dialogs }, peer))
}

async fn next_state(rx: &mut DialogStateReceiver) -> DialogState {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for dialog state")
        .expect("state channel closed")
}

/// Offerless INVITE, offer in our 200, answer in the ACK. Returns the
/// confirmed dialog and the To tag.
async fn establish_with_offer_in_2xx(
    uas: &mut Uas,
    peer: &Peer,
) -> crate::Result<(InviteDialog, String)> {
    peer.send_request(Method::Invite, 1, "z9hG4bK-invite-1", None, None)
        .await;
    let dialog = tokio::time::timeout(Duration::from_secs(2), uas.dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, Some(OFFER.as_bytes().to_vec()))?;
    let ok = peer.recv_2xx(1).await;
    let to_tag = ok
        .to_header()?
        .tag()?
        .expect("2xx To tag")
        .value()
        .to_string();
    assert_eq!(ok.body, OFFER.as_bytes(), "the 200 carries the UAS offer");
    assert!(dialog.last_remote_ack().is_none(), "no ACK received yet");
    peer.send_request(
        Method::Ack,
        1,
        "z9hG4bK-ack-1",
        Some(&to_tag),
        Some(&answer(1)),
    )
    .await;
    loop {
        if let DialogState::Confirmed(..) = next_state(&mut uas.states).await {
            break;
        }
    }
    Ok((dialog, to_tag))
}

#[tokio::test]
async fn test_answer_in_ack_to_initial_invite_is_available() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut uas, peer) = setup(&token).await?;
    let (dialog, _) = establish_with_offer_in_2xx(&mut uas, &peer).await?;

    let ack = dialog
        .last_remote_ack()
        .expect("the ACK that confirmed the dialog must be available");
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(ack.cseq_header()?.seq()?, 1);
    assert_eq!(ack.body, answer(1).as_bytes(), "the ACK carries the answer");
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_answer_in_ack_to_reinvite_is_available() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut uas, peer) = setup(&token).await?;
    let (dialog, to_tag) = establish_with_offer_in_2xx(&mut uas, &peer).await?;

    assert_eq!(dialog.last_remote_ack().unwrap().cseq_header()?.seq()?, 1);

    // Offerless re-INVITE: we answer it with a new offer in the 200.
    peer.send_request(Method::Invite, 2, "z9hG4bK-invite-2", Some(&to_tag), None)
        .await;
    loop {
        if let DialogState::Updated(_, req, handle) = next_state(&mut uas.states).await {
            assert!(req.body.is_empty(), "the re-INVITE carries no offer");
            handle
                .respond(
                    crate::sip::StatusCode::OK,
                    None,
                    Some(OFFER.as_bytes().to_vec()),
                )
                .await
                .unwrap();
            break;
        }
    }
    peer.recv_2xx(2).await;
    assert_eq!(
        dialog.last_remote_ack().unwrap().cseq_header()?.seq()?,
        1,
        "the re-INVITE does not clear the previous ACK before its own arrives"
    );
    peer.send_request(
        Method::Ack,
        2,
        "z9hG4bK-ack-2",
        Some(&to_tag),
        Some(&answer(2)),
    )
    .await;
    loop {
        if let DialogState::Confirmed(..) = next_state(&mut uas.states).await {
            break;
        }
    }

    let ack = dialog
        .last_remote_ack()
        .expect("the ACK for the re-INVITE must be available");
    assert_eq!(
        ack.cseq_header()?.seq()?,
        2,
        "the ACK of the re-INVITE, not the initial one"
    );
    assert_eq!(ack.body, answer(2).as_bytes(), "the ACK carries the answer");
    token.cancel();
    Ok(())
}
