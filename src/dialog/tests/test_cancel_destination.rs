//! A UAC dialog whose INVITE went to an explicit `InviteOption::destination`
//! (an outbound proxy or trunk next hop) must send its CANCEL to that same
//! address, port and transport (RFC 3261 §9.1), not to wherever the
//! Request-URI resolves. Here the Request-URI host does not resolve at all,
//! so a CANCEL that follows it never arrives.
use crate::dialog::{dialog::DialogState, dialog_layer::DialogLayer, invitation::InviteOption};
use crate::sip::{prelude::HeadersExt, typed::Route, Method, Request, SipMessage, Uri};
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

/// Receive the next request with `method` on the raw peer socket within
/// `wait`, skipping anything else.
async fn recv_request(socket: &UdpSocket, method: Method, wait: Duration) -> (Request, SocketAddr) {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            if req.method == method {
                return (req, from);
            }
        }
    }
}

/// Build a response to `req` as the peer UA, adding the peer's To tag.
fn response(req: &Request, code: u16, reason: &str, contact: &str) -> String {
    let to = req.to_header().unwrap().value().to_string();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={PEER_TAG}")
    };
    format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {to}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <{contact}>\r\n\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
    )
}

async fn reply(socket: &UdpSocket, to: SocketAddr, req: &Request, code: u16, reason: &str) {
    let contact = format!("sip:bob@{}", socket.local_addr().unwrap());
    socket
        .send_to(response(req, code, reason, &contact).as_bytes(), to)
        .await
        .expect("send_to failed");
}

/// A UAC whose INVITE names an unresolvable Request-URI host and goes to the
/// raw `peer` socket as its explicit next hop.
async fn setup(
    token: &CancellationToken,
) -> crate::Result<(Arc<DialogLayer>, InviteOption, UdpSocket)> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
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
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from("sip:+15551234567@carrier.invalid")?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        destination: Some(SipAddr::from(peer.local_addr()?)),
        ..Default::default()
    };
    Ok((
        Arc::new(DialogLayer::new(endpoint.inner.clone())),
        option,
        peer,
    ))
}

/// Sends the INVITE, answers it with 180 from the peer and waits for Early.
async fn ringing(
    token: &CancellationToken,
    preloaded_route: bool,
) -> crate::Result<(
    Arc<DialogLayer>,
    UdpSocket,
    Request,
    tokio::task::JoinHandle<()>,
)> {
    let (dialog_layer, mut option, peer) = setup(token).await?;
    if preloaded_route {
        option.destination = None;
        let route = Route::parse(&format!("<sip:{};lr>", peer.local_addr()?))?;
        option.route_set.push(route);
    }
    let wait = Duration::from_secs(2);
    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move {
        let _ = layer.do_invite(option, state_sender).await;
    });
    let (inv, uac) = recv_request(&peer, Method::Invite, wait).await;
    assert_eq!(inv.uri.to_string(), "sip:+15551234567@carrier.invalid");
    assert_eq!(inv.route_header().is_some(), preloaded_route);
    reply(&peer, uac, &inv, 180, "Ringing").await;
    tokio::time::timeout(wait, async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Early(_, _)) {
                return;
            }
        }
    })
    .await
    .expect("no Early state");
    Ok((dialog_layer, peer, inv, invite))
}

fn assert_cancels(cancel: &Request, invite: &Request) {
    assert_eq!(cancel.uri, invite.uri);
    assert_eq!(cancel.route_header(), invite.route_header());
    assert_eq!(
        cancel.call_id_header().unwrap().value(),
        invite.call_id_header().unwrap().value()
    );
    assert_eq!(
        cancel.via_header().unwrap().value(),
        invite.via_header().unwrap().value()
    );
}

#[tokio::test]
async fn test_explicit_cancel_goes_to_the_invite_destination() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog_layer, peer, inv, invite) = ringing(&token, false).await?;
    let call_id = inv.call_id_header()?.value().to_string();
    let dialogs = dialog_layer.get_client_dialog_by_call_id(&call_id);
    assert_eq!(dialogs.len(), 1);
    let dialog = dialogs[0].clone();
    let cancelling = tokio::spawn(async move { dialog.cancel().await });
    let (cancel, uac) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    reply(&peer, uac, &cancel, 200, "OK").await;
    cancelling.await.expect("cancel task")?;
    invite.abort();
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_cancel_crossing_2xx_uses_the_invite_destination() -> crate::Result<()> {
    use std::sync::atomic::Ordering;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    let token = CancellationToken::new();
    let _cancel_on_drop = token.clone().drop_guard();
    let (layer, mut option, invite_peer) = setup(&token).await?;
    option.callee = Uri::try_from(format!("sip:bob@{}", invite_peer.local_addr()?).as_str())?;
    let contact_peer = UdpSocket::bind("127.0.0.1:0").await?;
    let contact = format!("sip:bob@{}", contact_peer.local_addr()?);
    let wait = Duration::from_secs(2);

    let (state_sender, mut states) = unbounded_channel();
    let (dialog, invitation) = layer.do_invite_async(option, state_sender)?;
    let (invite, uac) = recv_request(&invite_peer, Method::Invite, wait).await;
    reply(&invite_peer, uac, &invite, 180, "Ringing").await;
    timeout(wait, async {
        while !matches!(
            states.recv().await.expect("dialog state"),
            DialogState::Early(..)
        ) {}
    })
    .await
    .expect("no Early state");

    // Block hangup after its Early check and before it can make the CANCEL.
    // Keep the blocking mutex off the runtime thread so it can process the 200.
    let inner = dialog.inner.clone();
    let locked_inner = inner.clone();
    let (request_locked, wait_for_request_lock) = oneshot::channel();
    let (release_request, wait_for_release) = std::sync::mpsc::channel();
    let lock_holder = std::thread::spawn(move || {
        let _request = locked_inner.initial_request.lock();
        let _ = request_locked.send(());
        let _ = wait_for_release.recv_timeout(wait * 5);
    });
    timeout(wait, wait_for_request_lock)
        .await
        .expect("initial request lock timed out")
        .expect("request lock task stopped");

    let runtime = tokio::runtime::Handle::current();
    let cancel_token = token.child_token();
    let (hangup_done, hangup_result) = oneshot::channel();
    let cancelling = std::thread::spawn(move || {
        let result = runtime.block_on(async {
            tokio::select! {
                result = dialog.hangup() => result,
                _ = cancel_token.cancelled() => Ok(()),
            }
        });
        let _ = hangup_done.send(result);
    });
    timeout(wait, async {
        while !inner.cancel_requested.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("hangup did not start CANCEL");

    let ok = response(&invite, 200, "OK", &contact);
    invite_peer.send_to(ok.as_bytes(), uac).await?;
    timeout(wait, invitation)
        .await
        .expect("INVITE task timed out")
        .expect("INVITE task failed")?;
    let (ack, _) = recv_request(&contact_peer, Method::Ack, wait).await;
    assert_eq!(ack.uri.to_string(), contact);
    let (bye, bye_from) = recv_request(&contact_peer, Method::Bye, wait).await;
    reply(&contact_peer, bye_from, &bye, 200, "OK").await;

    release_request.send(()).expect("resume hangup");
    lock_holder.join().expect("request lock task failed");
    let (cancel, cancel_from) = tokio::select! {
        packet = recv_request(&invite_peer, Method::Cancel, wait) => packet,
        _ = recv_request(&contact_peer, Method::Cancel, wait) => panic!("CANCEL followed the 2xx ACK"),
    };
    assert_cancels(&cancel, &invite);
    reply(&invite_peer, cancel_from, &cancel, 200, "OK").await;
    timeout(wait, hangup_result)
        .await
        .expect("hangup timed out")
        .expect("hangup task stopped")?;
    cancelling.join().expect("hangup task failed");
    Ok(())
}

#[tokio::test]
async fn test_dropped_invite_cancel_goes_to_the_invite_destination() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (_dialog_layer, peer, inv, invite) = ringing(&token, false).await?;
    invite.abort();
    let _ = invite.await;
    let (cancel, _) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_cancel_goes_to_the_preloaded_route() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (dialog_layer, peer, inv, invite) = ringing(&token, true).await?;
    let dialog = dialog_layer
        .get_client_dialog_by_call_id(inv.call_id_header()?.value())
        .pop()
        .expect("early client dialog");
    let cancelling = tokio::spawn(async move { dialog.cancel().await });
    let (cancel, uac) = recv_request(&peer, Method::Cancel, Duration::from_secs(2)).await;
    assert_cancels(&cancel, &inv);
    reply(&peer, uac, &cancel, 200, "OK").await;
    cancelling.await.expect("cancel task")?;
    invite.abort();
    token.cancel();
    Ok(())
}

/// DomainResolver that returns `first` on call 1 and `rotated` on any later call.
struct RotatingDomainResolver {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    first: SipAddr,
    rotated: SipAddr,
}

#[async_trait::async_trait]
impl crate::transport::transport_layer::DomainResolver for RotatingDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> crate::Result<SipAddr> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let chosen = if n == 0 { &self.first } else { &self.rotated };
        Ok(SipAddr {
            r#type: target.r#type.or(chosen.r#type),
            addr: chosen.addr.clone(),
        })
    }
}

/// TargetLocator that routes INVITE to `first`, then switches subsequent calls
/// to `rotated` (simulating re-registration or cluster failover between INVITE
/// and CANCEL, while also tracking in-dialog lookups like PRACK).
struct SwitchingTargetLocator {
    seen_uris: Arc<std::sync::Mutex<Vec<String>>>,
    first: SipAddr,
    rotated: SipAddr,
}

#[async_trait::async_trait]
impl crate::transaction::endpoint::TargetLocator for SwitchingTargetLocator {
    async fn locate(&self, uri: &Uri) -> crate::Result<SipAddr> {
        let mut seen = self.seen_uris.lock().unwrap();
        let n = seen.len();
        seen.push(uri.to_string());
        Ok(if n == 0 {
            self.first.clone()
        } else {
            self.rotated.clone()
        })
    }
}

async fn run_domain_cancel_reuses_resolved_ip(
    domain_destination: bool,
    drop_invite: bool,
) -> crate::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let token = CancellationToken::new();
    let peer_a = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_b = UdpSocket::bind("127.0.0.1:0").await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = RotatingDomainResolver {
        calls: calls.clone(),
        first: SipAddr::from(peer_a.local_addr()?),
        rotated: SipAddr::from(peer_b.local_addr()?),
    };
    let transport_layer =
        TransportLayer::new_with_domain_resolver(token.child_token(), Box::new(resolver));
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
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

    let destination = if domain_destination {
        Some(SipAddr {
            r#type: Some(crate::sip::Transport::Udp),
            addr: crate::sip::HostWithPort {
                host: crate::sip::Host::Domain("ims.example.invalid".into()),
                port: None,
            },
        })
    } else {
        None
    };
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from("sip:+15551234567@ims.example.invalid")?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        destination,
        ..Default::default()
    };

    let wait = Duration::from_secs(2);
    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move {
        let _ = layer.do_invite(option, state_sender).await;
    });

    let (inv, uac) = recv_request(&peer_a, Method::Invite, wait).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    reply(&peer_a, uac, &inv, 180, "Ringing").await;
    tokio::time::timeout(wait, async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Early(_, _)) {
                return;
            }
        }
    })
    .await
    .expect("no Early state");

    if drop_invite {
        invite.abort();
        let _ = invite.await;
        let (cancel, _) = recv_request(&peer_a, Method::Cancel, wait).await;
        assert_cancels(&cancel, &inv);
    } else {
        let dialog = dialog_layer
            .get_client_dialog_by_call_id(inv.call_id_header()?.value())
            .pop()
            .expect("early client dialog");
        let cancelling = tokio::spawn(async move { dialog.cancel().await });
        let (cancel, uac) = recv_request(&peer_a, Method::Cancel, wait).await;
        assert_cancels(&cancel, &inv);
        reply(&peer_a, uac, &cancel, 200, "OK").await;
        cancelling.await.expect("cancel task")?;
        invite.abort();
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "CANCEL must reuse the resolved INVITE peer without re-running DNS"
    );
    let mut buf = [0u8; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(150), peer_b.recv_from(&mut buf))
            .await
            .is_err(),
        "CANCEL must not be sent to the rotated peer"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_domain_destination_cancel_reuses_resolved_ip_explicit() -> crate::Result<()> {
    run_domain_cancel_reuses_resolved_ip(true, false).await
}

#[tokio::test]
async fn test_domain_destination_cancel_reuses_resolved_ip_on_drop() -> crate::Result<()> {
    run_domain_cancel_reuses_resolved_ip(true, true).await
}

#[tokio::test]
async fn test_domain_request_uri_cancel_reuses_resolved_ip_on_drop() -> crate::Result<()> {
    run_domain_cancel_reuses_resolved_ip(false, true).await
}

/// TargetLocator is used for the INVITE and remains used for in-dialog requests
/// (such as PRACK to the Contact target), while CANCEL sticks to the exact UDP
/// peer that received the INVITE even if TargetLocator later resolves elsewhere.
#[tokio::test]
async fn test_udp_cancel_pins_invite_peer_without_bypassing_locator_for_indialog(
) -> crate::Result<()> {
    let token = CancellationToken::new();
    let peer_a = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_b = UdpSocket::bind("127.0.0.1:0").await?;
    let seen_uris = Arc::new(std::sync::Mutex::new(Vec::new()));
    let locator = SwitchingTargetLocator {
        seen_uris: seen_uris.clone(),
        first: SipAddr::from(peer_a.local_addr()?),
        rotated: SipAddr::from(peer_b.local_addr()?),
    };
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uac_addr = udp.get_addr().addr.clone();
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_target_locator(Box::new(locator))
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from("sip:bob@registered.invalid")?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        support_prack: true,
        ..Default::default()
    };

    let wait = Duration::from_secs(2);
    let (state_sender, mut states) = unbounded_channel();
    let layer = dialog_layer.clone();
    let invite = tokio::spawn(async move {
        let _ = layer.do_invite(option, state_sender).await;
    });

    let (inv, uac) = recv_request(&peer_a, Method::Invite, wait).await;
    // Reply with a reliable 183 carrying a logical Contact URI that requires TargetLocator.
    let progress = response(&inv, 183, "Session Progress", "sip:bob@contact.invalid").replace(
        "Content-Length: 0",
        "Require: 100rel\r\nRSeq: 1\r\nContent-Length: 0",
    );
    peer_a.send_to(progress.as_bytes(), uac).await?;

    // PRACK is in-dialog: TargetLocator must still be consulted with the Contact URI
    // (which routes to peer_b in our test locator).
    let (prack, prack_from) = recv_request(&peer_b, Method::PRack, wait).await;
    reply(&peer_b, prack_from, &prack, 200, "OK").await;
    tokio::time::timeout(wait, async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Early(_, _)) {
                return;
            }
        }
    })
    .await
    .expect("no Early state");

    // Now drop the INVITE to trigger CANCEL: CANCEL must still go to peer_a
    // (the INVITE's UDP peer), NOT peer_b, and must not query TargetLocator again.
    let calls_before_cancel = seen_uris.lock().unwrap().len();
    invite.abort();
    let _ = invite.await;
    let (cancel, _) = recv_request(&peer_a, Method::Cancel, wait).await;
    assert_cancels(&cancel, &inv);
    assert_eq!(
        seen_uris.lock().unwrap().as_slice(),
        &[
            "sip:bob@registered.invalid".to_string(),
            "sip:bob@contact.invalid".to_string(),
        ],
        "TargetLocator must serve INVITE and in-dialog PRACK, never CANCEL"
    );
    assert_eq!(seen_uris.lock().unwrap().len(), calls_before_cancel);
    token.cancel();
    Ok(())
}
