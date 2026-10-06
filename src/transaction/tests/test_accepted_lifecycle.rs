//! Lifecycle guards for the RFC 6026 Accepted state: a confirmed dialog
//! must not leave the transaction parked in the endpoint's tables.
//!
//! - server: a matching ACK ends the Accepted transaction at once
//!   (`transactions` and `waiting_ack` are cleaned up immediately, not
//!   after Timer L).
//! - client: the Accepted transaction is detached when Timer M expires
//!   (the do_invite drainer keeps receiving until then).
use crate::dialog::{
    dialog::{Dialog, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, SipMessage};
use crate::transaction::endpoint::EndpointOption;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transport::udp::UdpConnection;
use crate::transport::TransportLayer;
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "accepted-lifecycle-test";
const FROM_TAG: &str = "lifecycle-uac";

fn invite_request(peer: SocketAddr, branch: &str) -> crate::sip::Request {
    crate::sip::Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from(format!("sip:bob@{peer}").as_str()).unwrap(),
        headers: vec![
            crate::sip::headers::Via::new(format!(
                "SIP/2.0/UDP {addr};branch={branch}",
                addr = "127.0.0.1:5060"
            ))
            .into(),
            crate::sip::headers::CSeq::new("1 INVITE").into(),
            crate::sip::headers::From::new(format!("<sip:alice@example.com>;tag={FROM_TAG}"))
                .into(),
            crate::sip::headers::To::new("<sip:bob@example.com>").into(),
            crate::sip::headers::CallId::new(CALL_ID).into(),
            crate::sip::headers::MaxForwards::new("70").into(),
            crate::sip::headers::Contact::new("<sip:alice@127.0.0.1:5060>").into(),
            crate::sip::headers::ContentLength::new("0").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

struct ServerHarness {
    endpoint: crate::transaction::endpoint::Endpoint,
    dialogs: UnboundedReceiver<InviteDialog>,
    states: DialogStateReceiver,
    peer: UdpSocket,
    uas: SocketAddr,
}

async fn server_setup(
    token: &CancellationToken,
    option: EndpointOption,
) -> crate::Result<ServerHarness> {
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
        .with_option(option)
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
    Ok(ServerHarness {
        endpoint,
        dialogs,
        states,
        peer,
        uas,
    })
}

/// Server side: once the ACK confirms the dialog, the Accepted transaction
/// must be gone from the endpoint's tables — not parked there until Timer L
/// (64*T1) — and `waiting_ack` must be empty.
#[tokio::test]
async fn test_server_accepted_transaction_ends_on_ack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let option = EndpointOption {
        t1: Duration::from_millis(20),
        t1x64: Duration::from_millis(64 * 20),
        ..Default::default()
    };
    let harness = server_setup(&token, option).await?;
    let ServerHarness {
        endpoint,
        mut dialogs,
        mut states,
        peer,
        uas,
    } = harness;
    let inner = endpoint.inner.clone();

    let invite = invite_request(uas, "z9hG4bK-accepted-lifecycle");
    let key = TransactionKey::from_request(&invite, TransactionRole::Server)?;
    peer.send_to(invite.to_string().as_bytes(), uas).await?;

    let dialog = tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap();
    dialog.accept(None, None)?;

    // First 200 OK, remember its To tag.
    let mut buf = vec![0u8; 4096];
    let to_tag = loop {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the 200");
        };
        let text = std::str::from_utf8(&buf[..len]).unwrap();
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
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

    // The matching ACK confirms the dialog and must end the transaction.
    let ack = format!(
        "ACK sip:bob@{uas} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-accepted-lifecycle-ack\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag={FROM_TAG}\r\n\
         To: <sip:bob@example.com>;tag={to_tag}\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\r\n",
        uas = uas,
    );
    let acked_at = Instant::now();
    peer.send_to(ack.as_bytes(), uas).await?;

    let mut confirmed = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        while let Ok(state) = states.try_recv() {
            if matches!(state, crate::dialog::dialog::DialogState::Confirmed(_, _)) {
                confirmed = true;
            }
        }
        if confirmed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(confirmed, "the ACK must confirm the dialog");

    // Detached synchronously with the ACK — nothing parked until Timer L.
    assert!(
        !inner.transactions.contains_key(&key),
        "the Accepted transaction must be detached as soon as the ACK confirms the dialog (leaked for {:?} until now)",
        acked_at.elapsed()
    );
    assert!(
        inner.waiting_ack.is_empty(),
        "waiting_ack must not retain the confirmed dialog"
    );
    assert!(
        inner.waiting_ack_cseq.is_empty(),
        "waiting_ack_cseq must not retain the confirmed dialog's (dialog, CSeq) route"
    );
    // The 2xx stays cached so retransmitted ACKs / late INVITE retransmits
    // are absorbed below the TU.
    assert!(
        inner.finished_transactions.contains_key(&key),
        "the 2xx must stay cached for late retransmission absorption"
    );

    token.cancel();
    Ok(())
}

/// Client side: the Accepted transaction is detached when Timer M expires.
/// The drainer installed by `DialogLayer::do_invite` must be what keeps it
/// receiving; here the same loop is driven manually with short timers.
#[tokio::test]
async fn test_client_accepted_transaction_detaches_on_timer_m() -> crate::Result<()> {
    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_option(EndpointOption {
            t1: Duration::from_millis(25),
            t1x64: Duration::from_millis(400),
            ..Default::default()
        })
        .build();

    let endpoint_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let invite = invite_request(peer_addr, "z9hG4bK-timer-m");
    let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
    let mut tx = crate::transaction::transaction::Transaction::new_client(
        key.clone(),
        invite,
        endpoint.inner.clone(),
        None,
    );
    tx.send().await?;

    // Answer the INVITE (and its retransmissions) with a tagged 200 OK.
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok(Ok((len, src))) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the INVITE");
        };
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        if text.starts_with("INVITE") {
            let resp = format!(
                "SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: {from}\r\nTo: {to};tag=peer-tag\r\nCall-ID: {callid}\r\nCSeq: 1 INVITE\r\nContact: <sip:bob@{src}>\r\nContent-Length: 0\r\n\r\n",
                via = text
                    .lines()
                    .find(|l| l.starts_with("Via:"))
                    .unwrap()
                    .strip_prefix("Via: ")
                    .unwrap(),
                from = text
                    .lines()
                    .find(|l| l.starts_with("From:"))
                    .unwrap()
                    .strip_prefix("From: ")
                    .unwrap(),
                to = text
                    .lines()
                    .find(|l| l.starts_with("To:"))
                    .unwrap()
                    .strip_prefix("To: ")
                    .unwrap(),
                callid = CALL_ID,
                src = src,
            );
            peer.send_to(resp.as_bytes(), src).await?;
            break;
        }
    }

    // First 2xx → Accepted (auto-ACK fired on the wire).
    let first = tokio::time::timeout(Duration::from_secs(2), tx.receive())
        .await
        .expect("timeout waiting for the 200")
        .expect("transaction ended before the 200");
    assert!(matches!(first, SipMessage::Response(ref r) if r.status_code.code() == 200));
    assert_eq!(
        tx.state,
        crate::transaction::TransactionState::Accepted,
        "the client INVITE 2xx must park the transaction in Accepted (RFC 6026 §7.2)"
    );
    assert!(
        endpoint.inner.transactions.contains_key(&key),
        "the Accepted transaction must stay in the table during the Timer M window"
    );

    // Drive receive() until Timer M ends the transaction (what the do_invite
    // drainer does).
    let started = Instant::now();
    while tokio::time::timeout(Duration::from_secs(3), tx.receive())
        .await
        .expect("drain timed out")
        .is_some()
    {}
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "the transaction must stay in Accepted until Timer M, ended after {:?}",
        started.elapsed()
    );
    assert_eq!(
        tx.state,
        crate::transaction::TransactionState::Terminated,
        "Timer M must terminate the Accepted transaction"
    );
    assert!(
        !endpoint.inner.transactions.contains_key(&key),
        "Timer M must detach the Accepted transaction from the endpoint's table"
    );
    // The stored ACK stays cached so late 2xx retransmissions are absorbed.
    assert!(endpoint.inner.finished_transactions.contains_key(&key));

    serve.abort();
    token.cancel();
    Ok(())
}

/// Integration guard for the do_invite drainer (#164): after `do_invite`
/// returns a confirmed dialog, a retransmitted 200 OK must still be
/// re-ACKed on the wire. Without the drainer the Accepted transaction's
/// channel would go unread and the re-ACK would never fire.
#[tokio::test]
async fn test_do_invite_drainer_reacks_retransmitted_2xx() -> crate::Result<()> {
    use crate::dialog::invitation::InviteOption;
    use crate::sip::Uri;

    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.child_token());
    let udp =
        UdpConnection::create_connection("127.0.0.1:0".parse()?, None, Some(token.child_token()))
            .await?;
    let uac_addr = udp.get_addr().addr.clone();
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;

    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{peer_addr};transport=udp").as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        ..Default::default()
    };
    let (state_sender, mut states) = tokio::sync::mpsc::unbounded_channel();
    let invite = {
        let dialog_layer = dialog_layer.clone();
        tokio::spawn(async move { dialog_layer.do_invite(option, state_sender).await })
    };

    // The raw UAS: answer the INVITE with a tagged 200 OK, twice.
    let mut buf = vec![0u8; 4096];
    let ok = loop {
        let Ok(Ok((len, src))) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await
        else {
            panic!("timeout waiting for the INVITE");
        };
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        if text.starts_with("INVITE") {
            let header = |name: &str| {
                text.lines()
                    .find(|l| l.starts_with(name))
                    .expect("INVITE header missing")
                    .strip_prefix(&format!("{name} "))
                    .expect("INVITE header malformed")
                    .to_string()
            };
            let ok = format!(
                "SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: {from}\r\nTo: {to};tag=drain-tag\r\nCall-ID: {callid}\r\nCSeq: {cseq}\r\nContact: <sip:bob@{peer_addr};transport=udp>\r\nContent-Length: 0\r\n\r\n",
                via = header("Via:"),
                from = header("From:"),
                to = header("To:"),
                callid = header("Call-ID:"),
                cseq = header("CSeq:"),
                peer_addr = peer_addr,
            );
            peer.send_to(ok.as_bytes(), src).await?;
            break ok;
        }
    };

    // do_invite confirms; then the UAS retransmits the same 200 OK.
    let (dialog, resp) = tokio::time::timeout(Duration::from_secs(2), invite)
        .await
        .expect("do_invite timed out")
        .expect("do_invite task panicked")
        .expect("do_invite failed");
    assert!(matches!(
        resp.as_ref().map(|r| r.status_code.code()),
        Some(200)
    ));
    peer.send_to(ok.as_bytes(), peer_addr).await?;

    // The drainer must have re-ACKed the retransmission.
    loop {
        let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await
        else {
            panic!("no re-ACK for the retransmitted 200 OK — did the do_invite drainer stop receiving?");
        };
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        if text.starts_with("BYE") {
            panic!("a confirmed dialog must not be ended with a BYE");
        }
        if text.starts_with("ACK") {
            assert!(
                text.contains(";tag=drain-tag"),
                "the re-ACK must carry the 2xx's To tag, got {text}"
            );
            break;
        }
    }
    let _ = &mut states;
    drop(dialog);

    token.cancel();
    Ok(())
}
