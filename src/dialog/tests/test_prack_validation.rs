//! RFC 3262 §§3, 4, 7 and 10: sequence validation and truthful UAS behavior.
use super::test_dialog_states::{create_invite_request, create_test_endpoint};
use crate::dialog::{
    dialog::{DialogInner, DialogState},
    invite_dialog::InviteDialog,
    server_dialog::ServerInviteDialog,
    DialogId,
};
use crate::sip::{headers, Header, HeadersExt, Method, Response, SipMessage, StatusCode};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;

fn response(rseq: &str, cseq: u32, tag: &str) -> Response {
    format!("SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-rel\r\nFrom: <sip:a@example.com>;tag=alice\r\nTo: <sip:b@example.com>;tag={tag}\r\nCall-ID: reliable\r\nCSeq: {cseq} INVITE\r\nRequire: 100rel\r\nRSeq: {rseq}\r\nContact: <sip:b@127.0.0.1:5060>\r\nContent-Length: 0\r\n\r\n").try_into().unwrap()
}

#[test]
fn rseq_requires_one_nonzero_unsigned_number() {
    for (value, expected) in [
        ("1", Some(1)),
        ("4294967295", Some(u32::MAX)),
        ("0", None),
        ("+1", None),
        ("-1", None),
        ("", None),
        ("1 2", None),
        ("4294967296", None),
    ] {
        assert_eq!(response(value, 1, "bob").rseq_value(), expected, "{value}");
    }
    let mut resp = response("1", 1, "bob");
    resp.headers.push(Header::Other("rseq".into(), "1".into()));
    assert_eq!(resp.rseq_value(), None);
}
#[test]
fn rack_requires_exactly_two_numbers_and_case_sensitive_method() {
    for (value, valid) in [
        ("1 0 INVITE", true),
        ("4294967295 2147483647 INVITE", true),
        ("0 1 INVITE", false),
        ("+1 1 INVITE", false),
        ("1 +1 INVITE", false),
        ("1 2147483648 INVITE", false),
        ("1 1 invite", false),
        ("1 1 INVITE extra", false),
        ("1 1", false),
    ] {
        let mut resp = response("1", 1, "bob");
        resp.headers.push(Header::RAck(value.into()));
        assert_eq!(resp.rack_value().is_some(), valid, "{value}");
    }
}
#[test]
fn rack_duplicate_is_invalid_and_generic_header_is_supported() {
    let mut resp = response("1", 1, "bob");
    resp.headers
        .push(Header::Other("rack".into(), "1 1 INVITE".into()));
    assert_eq!(resp.rack_value(), Some((1, 1, Method::Invite)));
    resp.headers.push(Header::RAck("1 1 INVITE".into()));
    assert_eq!(resp.rack_value(), None);
}

async fn client() -> crate::Result<Arc<DialogInner>> {
    let endpoint = create_test_endpoint().await?;
    let mut request = create_invite_request("alice", "", "reliable");
    request
        .headers
        .unique_push(headers::To::new("<sip:b@example.com>").into());
    let (states, _) = unbounded_channel();
    let (tu, _) = unbounded_channel();
    Ok(Arc::new(DialogInner::new(
        TransactionRole::Client,
        DialogId {
            call_id: "reliable".into(),
            local_tag: "alice".into(),
            remote_tag: "".into(),
        },
        request,
        endpoint.inner.clone(),
        states,
        None,
        None,
        tu,
    )?))
}
#[tokio::test]
async fn gaps_are_discarded_without_advancing_rseq() -> crate::Result<()> {
    let inner = client().await?;
    assert!(inner
        .prepare_prack_request(&response("20", 1, "bob"))?
        .is_some());
    assert!(inner
        .prepare_prack_request(&response("22", 1, "bob"))?
        .is_none());
    assert!(inner
        .prepare_prack_request(&response("21", 1, "bob"))?
        .is_some());
    assert!(inner
        .prepare_prack_request(&response("22", 1, "bob"))?
        .is_some());
    Ok(())
}
#[tokio::test]
async fn duplicates_and_old_responses_do_not_create_prack() -> crate::Result<()> {
    let inner = client().await?;
    let first = inner
        .prepare_prack_request(&response("20", 1, "bob"))?
        .unwrap();
    for rseq in ["20", "19"] {
        let mut retransmission = response(rseq, 1, "bob");
        retransmission.body = b"different SDP".to_vec();
        assert!(inner.prepare_prack_request(&retransmission)?.is_none());
    }
    let next = inner
        .prepare_prack_request(&response("21", 1, "bob"))?
        .unwrap();
    assert_eq!(next.cseq_header()?.seq()?, first.cseq_header()?.seq()? + 1);
    Ok(())
}
#[tokio::test]
async fn each_invite_and_early_dialog_has_its_own_rseq_space() -> crate::Result<()> {
    let inner = client().await?;
    for (rseq, cseq, tag) in [
        ("20", 1, "bob"),
        ("1", 2, "bob"),
        ("5", 1, "carol"),
        ("21", 1, "bob"),
        ("6", 1, "carol"),
    ] {
        let prack = inner
            .prepare_prack_request(&response(rseq, cseq, tag))?
            .unwrap();
        assert_eq!(
            prack.rack_value(),
            Some((rseq.parse().unwrap(), cseq, Method::Invite))
        );
        assert_eq!(prack.to_header()?.tag()?.unwrap().value(), tag);
    }
    Ok(())
}
#[tokio::test]
async fn first_rseq_is_limited_and_100_or_final_never_pracked() -> crate::Result<()> {
    let inner = client().await?;
    assert!(inner
        .prepare_prack_request(&response("2147483648", 1, "bob"))?
        .is_none());
    assert!(inner
        .prepare_prack_request(&response("2147483647", 1, "bob"))?
        .is_some());
    let mut next = response("2147483648", 1, "bob");
    next.headers
        .unique_push(Header::Contact("<sip:refreshed@127.0.0.1:5061>".into()));
    assert!(inner.prepare_prack_request(&next)?.is_some());
    assert_eq!(
        inner.remote_uri.lock().to_string(),
        "sip:refreshed@127.0.0.1:5061"
    );
    for status in [StatusCode::Trying, StatusCode::OK] {
        let mut resp = response("1", 2, "bob");
        resp.status_code = status;
        assert!(inner.prepare_prack_request(&resp)?.is_none());
    }
    Ok(())
}
#[tokio::test]
async fn unrelated_responses_cannot_change_reliable_sequence() -> crate::Result<()> {
    let inner = client().await?;
    for header in [
        Header::CallId("other".into()),
        Header::From("<sip:a@example.com>;tag=other".into()),
        Header::CSeq("1 UPDATE".into()),
    ] {
        let mut resp = response("1", 1, "bob");
        resp.headers.unique_push(header);
        assert!(inner.prepare_prack_request(&resp)?.is_none());
    }
    assert!(inner
        .prepare_prack_request(&response("1", 1, "bob"))?
        .is_some());
    Ok(())
}
#[tokio::test]
async fn invalid_reliable_provisional_is_not_delivered_or_applied() -> crate::Result<()> {
    let inner = client().await?;
    let req = inner.initial_request.lock().clone();
    inner.prepare_prack_request(&response("20", 1, "bob"))?;
    for rseq in ["20", "22", "0", "+21"] {
        assert!(
            !inner
                .handle_provisional_response(&response(rseq, 1, "bob"), &req)
                .await?
        );
    }
    assert!(
        !inner
            .handle_provisional_response(&response("1", 2, "bob"), &req)
            .await?
    );
    assert!(inner.id.lock().remote_tag.is_empty());
    Ok(())
}

async fn uas(
    required: bool,
    confirmed: bool,
    legacy: bool,
    rack: Option<&str>,
) -> crate::Result<(Response, DialogState)> {
    let endpoint = create_test_endpoint().await?;
    let (out, mut outgoing) = unbounded_channel();
    let addr: SipAddr = "127.0.0.1:5060".parse::<std::net::SocketAddr>()?.into();
    let conn: SipConnection =
        ChannelConnection::create_connection(unbounded_channel().1, out, addr, None)
            .await?
            .into();
    let (states, _) = unbounded_channel();
    let (tu, _) = unbounded_channel();
    let mut request = create_invite_request("alice", "", "reliable");
    request
        .headers
        .unique_push(headers::To::new("<sip:b@example.com>").into());
    let id = DialogId {
        call_id: "reliable".into(),
        local_tag: "bob".into(),
        remote_tag: "alice".into(),
    };
    let inner = Arc::new(DialogInner::new(
        TransactionRole::Server,
        id.clone(),
        request.clone(),
        endpoint.inner.clone(),
        states,
        None,
        None,
        tu,
    )?);
    if confirmed {
        request.to_header_mut()?.mut_tag("bob".into())?;
        *inner.state.lock() = DialogState::Confirmed(id, Response::default());
    }
    if required {
        request
            .headers
            .push(Header::Require("timer, 100rel".into()));
    }
    if let Some(rack) = rack {
        request.method = Method::PRack;
        request.headers.unique_push(Header::CSeq("2 PRACK".into()));
        request.to_header_mut()?.mut_tag("bob".into())?;
        if rack != "missing" {
            request.headers.push(Header::RAck(rack.into()));
        }
    }
    let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
    let mut tx = Transaction::new_server(key, request, endpoint.inner.clone(), Some(conn));
    tokio::time::timeout(std::time::Duration::from_millis(200), async {
        if legacy {
            ServerInviteDialog::from_inner(inner.clone())
                .handle(&mut tx)
                .await
        } else {
            InviteDialog::from_inner(inner.clone())
                .handle(&mut tx)
                .await
        }
    })
    .await
    .expect("UAS should answer immediately")?;
    let TransportEvent::Incoming(SipMessage::Response(response), _, _) =
        outgoing.try_recv().unwrap()
    else {
        panic!("no response")
    };
    let state = inner.state.lock().clone();
    Ok((response, state))
}
#[tokio::test]
async fn required_100rel_gets_420_and_unsupported() -> crate::Result<()> {
    for legacy in [false, true] {
        let (response, state) = uas(true, false, legacy, None).await?;
        assert_eq!(response.status_code, StatusCode::BadExtension);
        assert_eq!(
            response.header_value("Unsupported").as_deref(),
            Some("100rel")
        );
        assert!(state.is_terminated());
    }
    Ok(())
}
#[tokio::test]
async fn rejecting_required_100rel_reinvite_preserves_confirmed_dialog() -> crate::Result<()> {
    for legacy in [false, true] {
        let (response, state) = uas(true, true, legacy, None).await?;
        assert_eq!(response.status_code, StatusCode::BadExtension);
        assert!(state.is_confirmed());
    }
    Ok(())
}
#[tokio::test]
async fn prack_requires_a_real_outstanding_response_not_just_valid_rack() -> crate::Result<()> {
    for legacy in [false, true] {
        for rack in [
            "1 1 INVITE",
            "2 1 INVITE",
            "1 2 INVITE",
            "1 1 UPDATE",
            "1 1 X-EXT",
            "1 1 invite",
        ] {
            assert_eq!(
                uas(false, false, legacy, Some(rack)).await?.0.status_code,
                StatusCode::CallTransactionDoesNotExist
            );
        }
        for rack in ["missing", "0 1 INVITE", "1 1 INVITE extra", "1 1 INV/ITE"] {
            assert_eq!(
                uas(false, false, legacy, Some(rack)).await?.0.status_code,
                StatusCode::BadRequest
            );
        }
    }
    Ok(())
}
