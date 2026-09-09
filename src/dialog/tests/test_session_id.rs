//! Session-ID (RFC 7989) and History-Info (RFC 7044) dialog behavior tests.

use crate::dialog::{
    dialog::{DialogInner, SessionIdState},
    tests::test_dialog_states::{create_invite_request, create_test_endpoint},
    DialogId,
};
use crate::sip::{
    headers::{make_header, SessionId, SessionId as SessionIdHeader},
    prelude::HeadersExt,
    Header, StatusCode,
};
use crate::transaction::key::TransactionRole;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;

const UUID_A: &str = "ab30317f1a784dc48ff824d0d3715d86";
const UUID_B: &str = "47755a9de7794ba387653f2099600ef2";
const NIL: &str = "00000000000000000000000000000000";

async fn dialog_inner(
    role: TransactionRole,
    invite: crate::sip::Request,
) -> crate::Result<Arc<DialogInner>> {
    let endpoint = create_test_endpoint().await?;
    let (tu_sender, _tu_rx) = unbounded_channel();
    let (state_sender, _state_rx) = unbounded_channel();
    let id = DialogId {
        call_id: "session-id-test".to_string(),
        local_tag: if role == TransactionRole::Client {
            "alice-tag".to_string()
        } else {
            "bob-tag".to_string()
        },
        remote_tag: String::new(),
    };
    Ok(Arc::new(DialogInner::new(
        role,
        id,
        invite,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:ua@example.com:5060")?),
        tu_sender,
    )?))
}

fn request_with_session_id(local: &str, remote: Option<&str>) -> crate::sip::Request {
    let mut req = create_invite_request("alice-tag", "", "session-id-test");
    let sid = match remote {
        Some(r) => SessionId::from_pair(local, r).unwrap(),
        None => SessionId::from_local(local).unwrap(),
    };
    req.headers.push(Header::SessionId(sid));
    req
}

fn session_header_value(msg: &impl HeadersExt) -> Option<String> {
    msg.session_id_header().map(|s| s.value().to_string())
}

#[tokio::test]
async fn golden_default_no_session_id_anywhere() -> crate::Result<()> {
    // Neither side opted in: zero Session-ID footprint on any message.
    let req = create_invite_request("alice-tag", "", "session-id-test");
    assert!(session_header_value(&req).is_none());

    let client = dialog_inner(TransactionRole::Client, req.clone()).await?;
    let bye = client.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    assert!(session_header_value(&bye).is_none());

    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    let resp = server.make_response(&req, StatusCode::OK, None, None);
    assert!(session_header_value(&resp).is_none());
    let bye = server.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    assert!(session_header_value(&bye).is_none());
    Ok(())
}

#[tokio::test]
async fn uac_opt_in_sends_local_with_nil_remote() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, None);
    let sid = req.session_id_header().unwrap();
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid(), None, "initial request remote is nil");

    let client = dialog_inner(TransactionRole::Client, req.clone()).await?;
    let state = client.session_id_state().expect("participating");
    assert_eq!(state.local, UUID_A);

    let bye = client.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    let bye_sid = bye
        .session_id_header()
        .expect("in-dialog carries session-id");
    assert_eq!(bye_sid.local_uuid().as_deref(), Some(UUID_A));
    Ok(())
}

#[tokio::test]
async fn uas_mirrors_swapped_uuid_in_response() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, Some(NIL));
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;

    let state = server.session_id_state().expect("participating");
    assert_eq!(
        state.remote.as_deref(),
        Some(UUID_A),
        "server learned the peer uuid"
    );
    let local = state.local.clone();
    assert_ne!(local, UUID_A);

    // UAS-generated UUID is stable across responses/requests.
    let resp = server.make_response(&req, StatusCode::Ringing, None, None);
    let resp_sid = resp.session_id_header().expect("mirrored");
    assert_eq!(resp_sid.local_uuid().as_deref(), Some(local.as_str()));
    assert_eq!(resp_sid.remote_uuid().as_deref(), Some(UUID_A));

    let resp200 = server.make_response(&req, StatusCode::OK, None, None);
    assert_eq!(
        resp200.session_id_header().unwrap().local_uuid().as_deref(),
        Some(local.as_str())
    );

    let bye = server.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    let bye_sid = bye
        .session_id_header()
        .expect("in-dialog carries session-id");
    assert_eq!(bye_sid.local_uuid().as_deref(), Some(local.as_str()));
    assert_eq!(bye_sid.remote_uuid().as_deref(), Some(UUID_A));
    Ok(())
}

#[tokio::test]
async fn uas_ignores_requests_without_session_id() -> crate::Result<()> {
    let req = create_invite_request("alice-tag", "", "session-id-test");
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    assert!(server.session_id_state().is_none());
    let resp = server.make_response(&req, StatusCode::OK, None, None);
    assert!(session_header_value(&resp).is_none());
    Ok(())
}

#[tokio::test]
async fn malformed_session_id_discarded() -> crate::Result<()> {
    let mut req = create_invite_request("alice-tag", "", "session-id-test");
    req.headers.push(Header::SessionId(SessionIdHeader::new(
        "not-a-uuid;remote=zzz",
    )));
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    assert!(
        server.session_id_state().is_none(),
        "invalid header must be discarded"
    );
    let resp = server.make_response(&req, StatusCode::OK, None, None);
    assert!(session_header_value(&resp).is_none());
    Ok(())
}

#[tokio::test]
async fn trying_response_has_no_session_id() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, Some(NIL));
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    let resp = server.make_response(&req, StatusCode::Trying, None, None);
    assert!(
        session_header_value(&resp).is_none(),
        "100 Trying carries no Session-ID"
    );
    Ok(())
}

#[tokio::test]
async fn client_learns_remote_uuid_from_response() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, Some(NIL));
    let client = dialog_inner(TransactionRole::Client, req).await?;

    // Simulate receiving 200 OK from the peer carrying {B, A}.
    let resp_header = make_header("Session-ID", format!("{};remote={}", UUID_B, UUID_A));
    let mut resp = crate::sip::Response {
        status_code: StatusCode::OK,
        version: crate::sip::Version::V2,
        headers: Default::default(),
        body: vec![],
    };
    resp.headers.push(resp_header);

    let peer = resp.session_id_header().and_then(|s| s.local_uuid());
    client.observe_peer_session_uuid(peer);

    let state = client.session_id_state().unwrap();
    assert_eq!(
        state.remote.as_deref(),
        Some(UUID_B),
        "client learned peer uuid from response"
    );

    let bye = client.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    let sid = bye.session_id_header().unwrap();
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid().as_deref(), Some(UUID_B));
    Ok(())
}

#[tokio::test]
async fn caller_supplied_session_id_wins_over_injection() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, None);
    let client = dialog_inner(TransactionRole::Client, req).await?;

    let custom = SessionIdHeader::from_pair(UUID_A, UUID_B).unwrap();
    let req = client.make_request(
        crate::sip::Method::Info,
        None,
        None,
        None,
        Some(vec![Header::SessionId(custom)]),
        None,
    )?;
    let headers: Vec<_> = req
        .headers
        .iter()
        .filter(|h| matches!(h, Header::SessionId(_)))
        .collect();
    assert_eq!(headers.len(), 1, "no duplicate session-id headers");
    assert_eq!(headers[0].value(), format!("{};remote={}", UUID_A, UUID_B));
    Ok(())
}

#[tokio::test]
async fn history_info_mirrored_to_responses() -> crate::Result<()> {
    let mut req = create_invite_request("alice-tag", "", "session-id-test");
    req.headers.push(make_header(
        "History-Info",
        "<sip:bob@example.com>;index=1".to_string(),
    ));
    req.headers.push(make_header(
        "History-Info",
        "<sip:voicemail@example.com>;index=1.1;mp=1".to_string(),
    ));

    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    let resp = server.make_response(&req, StatusCode::OK, None, None);

    let mirrored = resp.history_info_entries()?;
    assert_eq!(mirrored.len(), 2, "both hi-entries mirrored");
    assert_eq!(mirrored[0].index, "1");
    assert_eq!(mirrored[1].index, "1.1");
    assert_eq!(mirrored[1].mp.as_deref(), Some("1"));
    Ok(())
}

#[tokio::test]
async fn history_info_not_mirrored_when_request_has_none() -> crate::Result<()> {
    let req = create_invite_request("alice-tag", "", "session-id-test");
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    let resp = server.make_response(&req, StatusCode::OK, None, None);
    assert!(resp.history_info_headers().is_empty());
    Ok(())
}

#[tokio::test]
async fn make_ack_swaps_remote_uuid_from_response() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let mut invite = request_with_session_id(UUID_A, Some(NIL));
    invite
        .via_header_mut()?
        .replace("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds");

    let resp = crate::sip::Response {
        status_code: StatusCode::OK,
        version: crate::sip::Version::V2,
        headers: vec![
            make_header("Session-ID", format!("{};remote={}", UUID_B, UUID_A)),
            crate::sip::headers::Via::new(
                "SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds",
            )
            .into(),
            crate::sip::headers::From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
            crate::sip::headers::To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
            crate::sip::headers::CallId::new("session-id-test").into(),
            crate::sip::headers::CSeq::new("1 INVITE").into(),
            crate::sip::headers::Contact::new("<sip:bob@bob.example.com:5060>").into(),
        ]
        .into(),
        body: vec![],
    };

    let ack = endpoint.inner.make_ack(&invite, &resp)?;
    let sid = ack.session_id_header().expect("ack carries session-id");
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid().as_deref(), Some(UUID_B));
    Ok(())
}

#[tokio::test]
async fn make_ack_without_session_id_untouched() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let invite = create_invite_request("alice-tag", "", "ack-test");
    let resp = crate::sip::Response {
        status_code: StatusCode::OK,
        version: crate::sip::Version::V2,
        headers: vec![crate::sip::headers::Contact::new("<sip:bob@bob.example.com:5060>").into()]
            .into(),
        body: vec![],
    };
    let ack = endpoint.inner.make_ack(&invite, &resp)?;
    assert!(session_header_value(&ack).is_none());
    Ok(())
}

#[tokio::test]
async fn session_id_survives_snapshot_restore() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let req = request_with_session_id(UUID_A, None);
    let client = dialog_inner(TransactionRole::Client, req).await?;

    let peer = make_header("Session-ID", format!("{};remote={}", UUID_B, UUID_A));
    let mut resp = crate::sip::Response {
        status_code: StatusCode::OK,
        version: crate::sip::Version::V2,
        headers: Default::default(),
        body: vec![],
    };
    resp.headers.push(peer);
    client.observe_peer_session_uuid(resp.session_id_header().and_then(|s| s.local_uuid()));

    // Restore only accepts confirmed dialogs.
    *client.state.lock() = crate::dialog::dialog::DialogState::Confirmed(
        client.id.lock().clone(),
        crate::sip::Response::default(),
    );

    let snapshot = client.snapshot();
    let restored = DialogInner::try_restore_from_snapshot(
        snapshot,
        endpoint.inner.clone(),
        {
            let (tx, _rx) = unbounded_channel();
            tx
        },
        {
            let (tx, _rx) = unbounded_channel();
            tx
        },
    )?
    .expect("confirmed snapshot restored");

    let state = restored.session_id_state().expect("session-id restored");
    assert_eq!(state.local, UUID_A);
    assert_eq!(state.remote.as_deref(), Some(UUID_B));

    let bye = restored.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    let sid = bye.session_id_header().unwrap();
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid().as_deref(), Some(UUID_B));
    Ok(())
}

#[test]
fn session_id_state_shape() {
    let s = SessionIdState {
        local: UUID_A.to_string(),
        remote: None,
    };
    assert_eq!(s.local, UUID_A);
    assert!(s.remote.is_none());
}

// ── make_invite_request E2E (InviteOption.session_id / histinfo) ──────────

fn invite_option(session_id: Option<String>) -> crate::dialog::invitation::InviteOption {
    crate::dialog::invitation::InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com").unwrap(),
        callee: crate::sip::Uri::try_from("sip:bob@example.com").unwrap(),
        contact: crate::sip::Uri::try_from("sip:alice@192.168.1.10:5060").unwrap(),
        session_id,
        ..Default::default()
    }
}

async fn test_layer(
    history_info_enabled: bool,
) -> crate::Result<crate::dialog::dialog_layer::DialogLayer> {
    use tokio_util::sync::CancellationToken;
    let token = CancellationToken::new();
    let tl = crate::transport::TransportLayer::new(token.child_token());
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let addr = crate::transport::SipAddr::from(sock.local_addr()?);
    let conn = crate::transport::udp::UdpConnection::attach(
        crate::transport::udp::UdpInner { conn: sock, addr },
        None,
        Some(token.child_token()),
    )
    .await;
    tl.inner.add_listener(conn.into());

    let endpoint = crate::transaction::endpoint::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_option(crate::transaction::endpoint::EndpointOption {
            history_info_enabled,
            ..Default::default()
        })
        .with_transport_layer(tl)
        .build();
    Ok(crate::dialog::dialog_layer::DialogLayer::new(
        endpoint.inner.clone(),
    ))
}

#[tokio::test]
async fn invite_opt_in_normalizes_dashed_uuid() -> crate::Result<()> {
    let layer = test_layer(false).await?;

    let mut opt = invite_option(Some("AB30317F-1A78-4DC4-8FF8-24D0D3715D86".to_string()));
    opt.headers = Some(vec![Header::Subject("test".into())]);
    let request = layer.make_invite_request(&opt)?;

    let sid = request.session_id_header().expect("session-id injected");
    assert_eq!(
        sid.value(),
        format!("{};remote={}", UUID_A, NIL),
        "dashed uuid normalized, remote=nil appended"
    );
    // no duplicates when app also passes headers
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|h| matches!(h, Header::SessionId(_)))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn invite_opt_in_invalid_uuid_rejected() {
    let layer = test_layer(false).await.unwrap();

    let opt = invite_option(Some("not-a-uuid".to_string()));
    assert!(layer.make_invite_request(&opt).is_err());
}

#[tokio::test]
async fn invite_without_opt_has_no_session_id() -> crate::Result<()> {
    let layer = test_layer(false).await?;

    let request = layer.make_invite_request(&invite_option(None))?;
    assert!(session_header_value(&request).is_none());
    Ok(())
}

#[tokio::test]
async fn invite_histinfo_flag_adds_supported_once() -> crate::Result<()> {
    let layer = test_layer(true).await?;

    let request = layer.make_invite_request(&invite_option(None))?;
    let supported: Vec<_> = request
        .headers
        .iter()
        .filter(|h| matches!(h, Header::Supported(_)))
        .collect();
    assert_eq!(supported.len(), 1);
    assert_eq!(supported[0].value(), "histinfo");
    Ok(())
}

#[tokio::test]
async fn invite_histinfo_not_duplicated_when_app_supplies() -> crate::Result<()> {
    let layer = test_layer(true).await?;

    let mut opt = invite_option(None);
    opt.headers = Some(vec![Header::Supported("histinfo".into())]);
    let request = layer.make_invite_request(&opt)?;
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|h| matches!(h, Header::Supported(_)))
            .count(),
        1,
        "app-supplied histinfo not duplicated"
    );
    Ok(())
}

#[tokio::test]
async fn invite_histinfo_disabled_by_default() -> crate::Result<()> {
    let layer = test_layer(false).await?;

    let request = layer.make_invite_request(&invite_option(None))?;
    assert!(
        !request
            .headers
            .iter()
            .any(|h| matches!(h, Header::Supported(_))),
        "no histinfo advertisement by default"
    );
    Ok(())
}

// ── generated uuid format ────────────────────────────────────────────────

#[test]
fn generated_uuid_is_valid_32hex_v4() {
    for _ in 0..16 {
        let u = crate::dialog::dialog::make_dialog_session_uuid();
        assert_eq!(u.len(), 32);
        assert!(u
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_ne!(u, NIL);
        assert_eq!(u.as_bytes()[12], b'4', "version nibble is 4");
    }
    let a = crate::dialog::dialog::make_dialog_session_uuid();
    let b = crate::dialog::dialog::make_dialog_session_uuid();
    assert_ne!(a, b);
}

// ── RFC 7989 §8: mid-dialog peer uuid change ─────────────────────────────

#[tokio::test]
async fn response_mirrors_new_peer_uuid_from_request() -> crate::Result<()> {
    const UUID_C: &str = "11aa22bb33cc44dd55ee66ff77889900";
    let req = request_with_session_id(UUID_A, Some(NIL));
    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    assert_eq!(
        server.session_id_state().unwrap().remote.as_deref(),
        Some(UUID_A)
    );

    // Peer changed its uuid mid-dialog: the new request carries local=C.
    let changed = request_with_session_id(UUID_C, None);
    let resp = server.make_response(&changed, StatusCode::OK, None, None);
    let sid = resp.session_id_header().expect("participating");
    assert_eq!(
        sid.remote_uuid().as_deref(),
        Some(UUID_C),
        "response to the request must mirror the NEW uuid (§8)"
    );

    // After observe(), subsequent messages also use the new uuid.
    server.observe_peer_session_uuid(changed.session_id_header().and_then(|s| s.local_uuid()));
    let bye = server.make_request(crate::sip::Method::Bye, None, None, None, None, None)?;
    assert_eq!(
        bye.session_id_header().unwrap().remote_uuid().as_deref(),
        Some(UUID_C)
    );
    Ok(())
}

#[tokio::test]
async fn observe_is_idempotent_and_ignores_nil() -> crate::Result<()> {
    let req = request_with_session_id(UUID_A, Some(NIL));
    let server = dialog_inner(TransactionRole::Server, req).await?;

    server.observe_peer_session_uuid(None);
    assert_eq!(
        server.session_id_state().unwrap().remote.as_deref(),
        Some(UUID_A)
    );

    server.observe_peer_session_uuid(Some(NIL.to_string()));
    assert_eq!(
        server.session_id_state().unwrap().remote.as_deref(),
        Some(UUID_A)
    );

    server.observe_peer_session_uuid(Some(UUID_B.to_string()));
    server.observe_peer_session_uuid(Some(UUID_B.to_string()));
    assert_eq!(
        server.session_id_state().unwrap().remote.as_deref(),
        Some(UUID_B)
    );

    // A non-participating dialog never starts participating via observe.
    let plain = create_invite_request("alice-tag", "", "session-id-test");
    let detached = dialog_inner(TransactionRole::Server, plain).await?;
    detached.observe_peer_session_uuid(Some(UUID_B.to_string()));
    assert!(detached.session_id_state().is_none());
    Ok(())
}

// ── make_ack remaining branches ──────────────────────────────────────────

fn ok_response_with(headers: Vec<Header>) -> crate::sip::Response {
    let mut headers = headers;
    headers.push(crate::sip::headers::Contact::new("<sip:bob@bob.example.com:5060>").into());
    crate::sip::Response {
        status_code: StatusCode::OK,
        version: crate::sip::Version::V2,
        headers: headers.into(),
        body: vec![],
    }
}

#[tokio::test]
async fn make_ack_injects_nil_remote_when_response_has_none() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let mut invite = request_with_session_id(UUID_A, Some(NIL));
    invite
        .via_header_mut()?
        .replace("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds");

    let resp = ok_response_with(vec![
        crate::sip::headers::Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds")
            .into(),
        crate::sip::headers::From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
        crate::sip::headers::To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
        crate::sip::headers::CallId::new("session-id-test").into(),
        crate::sip::headers::CSeq::new("1 INVITE").into(),
    ]);

    let ack = endpoint.inner.make_ack(&invite, &resp)?;
    let sid = ack.session_id_header().expect("ack keeps session-id");
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid(), None, "remote stays nil");
    Ok(())
}

#[tokio::test]
async fn make_ack_passthrough_when_invite_not_participating() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let mut invite = create_invite_request("alice-tag", "", "session-id-test");
    invite
        .via_header_mut()?
        .replace("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds");

    let resp = ok_response_with(vec![
        make_header("Session-ID", format!("{};remote={}", UUID_B, NIL)),
        crate::sip::headers::Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds")
            .into(),
        crate::sip::headers::From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
        crate::sip::headers::To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
        crate::sip::headers::CallId::new("session-id-test").into(),
        crate::sip::headers::CSeq::new("1 INVITE").into(),
    ]);

    let ack = endpoint.inner.make_ack(&invite, &resp)?;
    let sid = ack
        .session_id_header()
        .expect("response header passed through");
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_B));
    Ok(())
}

#[tokio::test]
async fn make_ack_for_failure_response_keeps_local() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let mut invite = request_with_session_id(UUID_A, Some(NIL));
    invite
        .via_header_mut()?
        .replace("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds");

    let mut resp = ok_response_with(vec![
        make_header("Session-ID", format!("{};remote={}", UUID_B, UUID_A)),
        crate::sip::headers::Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds")
            .into(),
        crate::sip::headers::From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
        crate::sip::headers::To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
        crate::sip::headers::CallId::new("session-id-test").into(),
        crate::sip::headers::CSeq::new("1 INVITE").into(),
    ]);
    resp.status_code = StatusCode::BusyHere;

    let ack = endpoint.inner.make_ack(&invite, &resp)?;
    let sid = ack.session_id_header().expect("ack carries session-id");
    assert_eq!(sid.local_uuid().as_deref(), Some(UUID_A));
    assert_eq!(sid.remote_uuid().as_deref(), Some(UUID_B));
    Ok(())
}

// ── History-Info: user supply suppresses mirror ──────────────────────────

#[tokio::test]
async fn history_info_user_supply_suppresses_mirror() -> crate::Result<()> {
    let mut req = create_invite_request("alice-tag", "", "session-id-test");
    req.headers.push(make_header(
        "History-Info",
        "<sip:bob@example.com>;index=1".to_string(),
    ));
    req.headers.push(make_header(
        "History-Info",
        "<sip:voicemail@example.com>;index=1.1".to_string(),
    ));

    let server = dialog_inner(TransactionRole::Server, req.clone()).await?;
    let user_history = Header::HistoryInfo(crate::sip::headers::HistoryInfo::new(
        "<sip:rewritten@example.com>;index=1".to_string(),
    ));
    let resp = server.make_response(&req, StatusCode::OK, Some(vec![user_history]), None);

    let entries = resp.history_info_entries()?;
    assert_eq!(entries.len(), 1, "mirror suppressed, only user entry kept");
    assert_eq!(entries[0].uri.to_string(), "sip:rewritten@example.com");
    Ok(())
}
