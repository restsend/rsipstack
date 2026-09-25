//! A UAC INVITE challenged with 401/407 (RFC 3261 §22.2 / §22.3).
//!
//! With a credential configured the UAC retries once with Authorization /
//! Proxy-Authorization. Without one it cannot retry, so the challenge is the
//! final response and must be returned to the caller, not dropped.
use crate::dialog::{
    authenticate::Credential,
    client_dialog::ClientInviteDialog,
    dialog::{DialogState, TerminatedReason},
    dialog_layer::DialogLayer,
    invitation::InviteOption,
};
use crate::sip::{headers::*, Header, Method, Response, StatusCode, Uri};
use crate::transaction::TransactionReceiver;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

/// Upper bound for the INVITE to complete; well below Timer B/D (32 s), so a
/// response held until the transaction times out fails the test too.
const PROMPT: Duration = Duration::from_secs(5);

const CHALLENGE: &str =
    r#"Digest realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5"#;

struct Peers {
    token: CancellationToken,
    uac_layer: DialogLayer,
    uas_port: u16,
    uac_port: u16,
}

async fn udp_endpoint(
    token: &CancellationToken,
    ua: &str,
) -> crate::Result<(crate::transaction::endpoint::Endpoint, u16)> {
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let port = udp.get_addr().addr.port.map(u16::from).unwrap_or(0);
    tl.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent(ua)
        .with_transport_layer(tl)
        .with_cancel_token(token.child_token())
        .build();
    endpoint.inner.transport_layer.serve_listens().await?;
    let inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = inner.serve().await;
    });
    Ok((endpoint, port))
}

/// Returns the peers and the UAS's incoming transactions.
async fn peers() -> crate::Result<(Peers, TransactionReceiver)> {
    let token = CancellationToken::new();
    let (uas, uas_port) = udp_endpoint(&token, "rsipstack-uas").await?;
    let (uac, uac_port) = udp_endpoint(&token, "rsipstack-uac").await?;
    let uas_incoming = uas.incoming_transactions()?;
    let peers = Peers {
        token,
        uac_layer: DialogLayer::new(uac.inner.clone()),
        uas_port,
        uac_port,
    };
    Ok((peers, uas_incoming))
}

fn invite_option(p: &Peers, credential: Option<Credential>) -> InviteOption {
    InviteOption {
        caller: Uri::try_from("sip:alice@example.com").unwrap(),
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{};transport=udp", p.uas_port)).unwrap(),
        contact: Uri::try_from(format!("sip:alice@127.0.0.1:{}", p.uac_port)).unwrap(),
        credential,
        ..Default::default()
    }
}

fn challenge_header(status: &StatusCode) -> Header {
    match status {
        StatusCode::ProxyAuthenticationRequired => ProxyAuthenticate::new(CHALLENGE).into(),
        _ => WwwAuthenticate::new(CHALLENGE).into(),
    }
}

/// Whether the INVITE answers a `status` challenge with the matching header:
/// Authorization for 401 (§22.3), Proxy-Authorization for 407 (§22.3).
fn answers_challenge(status: &StatusCode, headers: &Headers) -> bool {
    headers.iter().any(|h| match status {
        StatusCode::ProxyAuthenticationRequired => matches!(h, Header::ProxyAuthorization(_)),
        _ => matches!(h, Header::Authorization(_)),
    })
}

/// UAS: challenge every INVITE with `status`, except that one answering the
/// challenge gets 200 OK when `accept_credentials`. Reports, per INVITE,
/// whether it answered the challenge.
fn spawn_uas(
    mut incoming: TransactionReceiver,
    status: StatusCode,
    uas_port: u16,
    accept_credentials: bool,
) -> UnboundedReceiver<bool> {
    let (seen_tx, seen_rx) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            if tx.original.method != Method::Invite {
                continue;
            }
            let authed = answers_challenge(&status, &tx.original.headers);
            let _ = seen_tx.send(authed);
            let status = status.clone();
            tokio::spawn(async move {
                if authed && accept_credentials {
                    let contact = Contact::new(format!("<sip:bob@127.0.0.1:{}>", uas_port));
                    tx.reply_with(StatusCode::OK, vec![contact.into()], None)
                        .await
                        .expect("reply 200");
                } else {
                    tx.reply_with(status.clone(), vec![challenge_header(&status)], None)
                        .await
                        .expect("reply challenge");
                }
                // Keep the server transaction alive to absorb the ACK.
                while tx.receive().await.is_some() {}
            });
        }
    });
    seen_rx
}

/// No further INVITE reaches the UAS. Any retry is sent before the INVITE
/// completes, so on loopback it would arrive well within this window.
async fn assert_no_more_invites(seen: &mut UnboundedReceiver<bool>) {
    let next = tokio::time::timeout(Duration::from_millis(300), seen.recv()).await;
    assert!(next.is_err(), "unexpected further INVITE: {next:?}");
}

fn credential() -> Credential {
    Credential {
        username: "alice".to_string(),
        password: "secret".to_string(),
        realm: None,
    }
}

fn is_auth_terminated(state: &DialogState) -> bool {
    matches!(
        state,
        DialogState::Terminated(_, TerminatedReason::ProxyAuthRequired)
    )
}

async fn assert_challenge_returned_without_credential(status: StatusCode) -> crate::Result<()> {
    let (p, uas_incoming) = peers().await?;
    let mut seen = spawn_uas(uas_incoming, status.clone(), p.uas_port, true);
    let (state_tx, mut state_rx) = unbounded_channel();

    let opt = invite_option(&p, None);
    let (dialog, resp) = tokio::time::timeout(PROMPT, p.uac_layer.do_invite(opt, state_tx))
        .await
        .unwrap_or_else(|_| panic!("do_invite did not return the {status} challenge promptly"))?;

    let resp = resp.unwrap_or_else(|| panic!("the {status} challenge must be the final response"));
    assert_eq!(resp.status_code, status);
    assert!(is_auth_terminated(&dialog.state()));
    let mut terminated = false;
    while let Ok(state) = state_rx.try_recv() {
        terminated |= is_auth_terminated(&state);
    }
    assert!(terminated, "ProxyAuthRequired termination must be emitted");
    assert_eq!(seen.recv().await, Some(false));
    assert_no_more_invites(&mut seen).await;

    p.token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_invite_401_without_credential_is_final_response() -> crate::Result<()> {
    assert_challenge_returned_without_credential(StatusCode::Unauthorized).await
}

#[tokio::test]
async fn test_invite_407_without_credential_is_final_response() -> crate::Result<()> {
    assert_challenge_returned_without_credential(StatusCode::ProxyAuthenticationRequired).await
}

/// The deprecated `ClientInviteDialog::process_invite` has the same contract.
#[tokio::test]
async fn test_legacy_client_dialog_401_without_credential_is_final_response() -> crate::Result<()> {
    let (p, uas_incoming) = peers().await?;
    let mut seen = spawn_uas(uas_incoming, StatusCode::Unauthorized, p.uas_port, true);
    let (state_tx, _state_rx) = unbounded_channel();
    let opt = invite_option(&p, None);
    let (dialog, mut tx) = p.uac_layer.create_client_invite_dialog(opt, state_tx)?;
    let legacy = ClientInviteDialog::try_from(dialog)?;

    let (_, resp) = tokio::time::timeout(PROMPT, legacy.process_invite(&mut tx))
        .await
        .expect("process_invite did not return the 401 promptly")?;

    let resp = resp.expect("the 401 must be the final response");
    assert_eq!(resp.status_code, StatusCode::Unauthorized);
    assert!(is_auth_terminated(&legacy.state()));
    assert_eq!(seen.recv().await, Some(false));
    assert_no_more_invites(&mut seen).await;

    p.token.cancel();
    Ok(())
}

/// With a credential the challenge is still answered by one authenticated
/// retry, and the retry's response is what the caller gets.
async fn assert_challenge_retried_with_credential(status: StatusCode) -> crate::Result<()> {
    let (p, uas_incoming) = peers().await?;
    let mut seen = spawn_uas(uas_incoming, status.clone(), p.uas_port, true);
    let (state_tx, _state_rx) = unbounded_channel();
    let opt = invite_option(&p, Some(credential()));

    let (dialog, resp) = tokio::time::timeout(PROMPT, p.uac_layer.do_invite(opt, state_tx))
        .await
        .expect("authenticated INVITE did not complete")?;

    let resp: Response = resp.expect("final response after the authenticated retry");
    assert_eq!(resp.status_code, StatusCode::OK);
    assert!(dialog.inner.is_confirmed());
    assert_eq!(
        seen.recv().await,
        Some(false),
        "first INVITE is unauthenticated"
    );
    assert_eq!(seen.recv().await, Some(true), "retry answers the challenge");
    assert_no_more_invites(&mut seen).await;

    p.token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_invite_401_with_credential_retries() -> crate::Result<()> {
    assert_challenge_retried_with_credential(StatusCode::Unauthorized).await
}

#[tokio::test]
async fn test_invite_407_with_credential_retries() -> crate::Result<()> {
    assert_challenge_retried_with_credential(StatusCode::ProxyAuthenticationRequired).await
}

/// A challenge to the authenticated retry is final: no second retry.
#[tokio::test]
async fn test_invite_challenge_after_authenticated_retry_is_final_response() -> crate::Result<()> {
    let status = StatusCode::Unauthorized;
    let (p, uas_incoming) = peers().await?;
    let mut seen = spawn_uas(uas_incoming, status.clone(), p.uas_port, false);
    let (state_tx, _state_rx) = unbounded_channel();
    let opt = invite_option(&p, Some(credential()));

    let (dialog, resp) = tokio::time::timeout(PROMPT, p.uac_layer.do_invite(opt, state_tx))
        .await
        .expect("challenged retry did not complete")?;

    let resp = resp.expect("the second challenge must be the final response");
    assert_eq!(resp.status_code, status);
    assert!(is_auth_terminated(&dialog.state()));
    assert_eq!(
        seen.recv().await,
        Some(false),
        "first INVITE is unauthenticated"
    );
    assert_eq!(seen.recv().await, Some(true), "retry answers the challenge");
    assert_no_more_invites(&mut seen).await;

    p.token.cancel();
    Ok(())
}
