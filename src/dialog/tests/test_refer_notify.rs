//! RFC 3515 regression: after an in-dialog REFER is answered (usually 202),
//! the dialog must return to `Confirmed` — the implicit subscription's
//! NOTIFYs are in-dialog requests that need the confirmed dialog. Leaving
//! the dialog in the `Refer` state starved the referrer of every NOTIFY.
use crate::dialog::{
    dialog::{Dialog, DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, SipMessage, StatusCode};
use crate::transaction::endpoint::EndpointOption;
use crate::transport::udp::UdpConnection;
use crate::transport::TransportLayer;
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "refer-notify-test";
const FROM_TAG: &str = "referrer-tag";

struct Harness {
    states: DialogStateReceiver,
    dialogs: UnboundedReceiver<InviteDialog>,
    peer: UdpSocket,
    uas: SocketAddr,
}

async fn setup(token: &CancellationToken) -> crate::Result<Harness> {
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
        .with_option(EndpointOption {
            t1: Duration::from_millis(20),
            t1x64: Duration::from_millis(64 * 20),
            ..Default::default()
        })
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

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    Ok(Harness {
        states,
        dialogs,
        peer,
        uas,
    })
}

async fn recv_message(
    socket: &UdpSocket,
    buf: &mut [u8],
    wait: Duration,
) -> Option<(String, SocketAddr)> {
    let deadline = Instant::now() + wait;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let Ok(Ok((len, src))) = tokio::time::timeout(deadline - now, socket.recv_from(buf)).await
        else {
            return None;
        };
        return Some((String::from_utf8_lossy(&buf[..len]).to_string(), src));
    }
}

/// Confirm a call, then REFER it: the dialog must answer 202, return to
/// Confirmed, and `notify_refer` must deliver the 100 Trying NOTIFY.
#[tokio::test]
async fn test_refer_returns_dialog_to_confirmed_and_notify_works() -> crate::Result<()> {
    let token = CancellationToken::new();
    let Harness {
        mut states,
        mut dialogs,
        peer,
        uas,
    } = setup(&token).await?;

    let peer_addr = peer.local_addr()?;
    let invite = format!(
        "INVITE sip:bob@{uas} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-rn-invite\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag={FROM_TAG}\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@{peer_addr}>\r\n\
         Content-Length: 0\r\n\r\n",
    );
    peer.send_to(invite.as_bytes(), uas).await?;

    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    // First 200 OK, remember its To tag.
    let mut buf = vec![0u8; 4096];
    let to_tag = loop {
        let (text, _) = recv_message(&peer, &mut buf, Duration::from_secs(2))
            .await
            .expect("timeout waiting for the first 200");
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text.as_str()) {
            if resp.status_code.code() == 200 {
                break resp
                    .to_header()?
                    .tag()?
                    .expect("the 200 must carry the local tag")
                    .value()
                    .to_string();
            }
        }
    };
    // Confirm the dialog.
    let ack = format!(
        "ACK sip:alice@{peer_addr} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-rn-ack\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag={FROM_TAG}\r\n\
         To: <sip:bob@example.com>;tag={to_tag}\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\r\n",
    );
    peer.send_to(ack.as_bytes(), uas).await?;

    // In-dialog REFER transferring the call elsewhere.
    let refer = format!(
        "REFER sip:bob@{uas} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-rn-refer\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag={FROM_TAG}\r\n\
         To: <sip:bob@example.com>;tag={to_tag}\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 2 REFER\r\n\
         Refer-To: <sip:agent@example.com>\r\n\
         Contact: <sip:alice@{peer_addr}>\r\n\
         Content-Length: 0\r\n\r\n",
    );
    peer.send_to(refer.as_bytes(), uas).await?;

    // The application answers the REFER with 202 (as an RFC 3515 referee).
    let mut refer_handle = None;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        while let Ok(state) = states.try_recv() {
            if let DialogState::Refer(_, _, handle) = state {
                refer_handle = Some(handle);
            }
        }
        if refer_handle.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let refer_handle = refer_handle.expect("the dialog never surfaced the REFER");
    refer_handle
        .reply(StatusCode::Other(202, "Accepted".into()))
        .await
        .ok();

    // The referrer sees the 202 ...
    let saw_202 = loop {
        let (text, _) = recv_message(&peer, &mut buf, Duration::from_secs(2))
            .await
            .expect("timeout waiting for the 202");
        if text.starts_with("SIP/2.0 202") {
            break true;
        }
    };
    assert!(saw_202);

    // ... and the dialog re-surfaces a Confirmed event: in-dialog request
    // events do not change the stored state, but TU-side logic (e.g. a
    // pending refer NOTIFY) waits on the Confirmed event after answering.
    // Without `return_to_confirmed` in handle_refer it never arrives.
    let reconfirmed = {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut seen = false;
        while Instant::now() < deadline {
            while let Ok(state) = states.try_recv() {
                if matches!(state, DialogState::Confirmed(..)) {
                    seen = true;
                }
            }
            if seen {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        seen
    };
    assert!(
        reconfirmed,
        "answering the REFER must re-surface a Confirmed event for the dialog"
    );
    assert!(dialog.state().is_confirmed());

    // The 100 Trying NOTIFY for the implicit subscription goes out.
    let notify = dialog.notify_refer(StatusCode::Trying, "active").await;
    assert!(
        notify.is_ok(),
        "notify_refer must work once the dialog is Confirmed again: {:?}",
        notify.err()
    );
    let saw_notify = loop {
        let (text, src) = recv_message(&peer, &mut buf, Duration::from_secs(2))
            .await
            .expect("timeout waiting for the NOTIFY");
        if text.starts_with("NOTIFY") {
            assert!(
                text.contains("Event: refer"),
                "the NOTIFY must carry Event: refer, got {text}"
            );
            assert!(
                text.contains("Subscription-State: active"),
                "the NOTIFY must carry Subscription-State: active, got {text}"
            );
            assert!(
                text.contains("SIP/2.0 100"),
                "the NOTIFY body must carry the 100 Trying sipfrag, got {text}"
            );
            // Answer the NOTIFY so the transaction completes.
            let header = |name: &str| {
                text.lines()
                    .find(|l| l.starts_with(name))
                    .unwrap()
                    .strip_prefix(&format!("{name} "))
                    .unwrap()
                    .to_string()
            };
            let resp = format!(
                "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
                header("Via:"),
                header("From:"),
                header("To:"),
                header("Call-ID:"),
                header("CSeq:"),
            );
            peer.send_to(resp.as_bytes(), src).await?;
            break true;
        }
    };
    assert!(saw_notify);

    token.cancel();
    Ok(())
}
