//! Target-refresh regressions: exercise application replies and actual outgoing BYEs.
use crate::dialog::dialog::TransactionHandle;
use crate::dialog::{
    dialog::{DialogInner, DialogState},
    invite_dialog::InviteDialog,
    DialogId,
};
use crate::sip::{Header, HeadersExt, Method, Request, SipMessage, StatusCode};
use crate::transaction::endpoint::Endpoint;
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use crate::EndpointBuilder;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const OLD: &str = "sip:alice@192.0.2.10:5060";
const NEW: &str = "sip:alice@192.0.2.99:5090;transport=TCP;user=phone";
const ROUTE: &str = "<sip:proxy@192.0.2.50:5060;lr>";

fn wire(response: bool, cl: &str, body: &[u8]) -> Vec<u8> {
    let start = if response {
        "SIP/2.0 200 OK"
    } else {
        "INVITE sip:bob@127.0.0.1:5060 SIP/2.0"
    };
    let mut v = format!("{start}\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-audit\r\nFrom: <sip:alice@example.com>;tag=alice\r\nTo: <sip:bob@example.com>;tag=bob\r\nCall-ID: audit\r\nCSeq: 1 INVITE\r\nContact: <{OLD}>\r\nMax-Forwards: 70\r\nContent-Type: application/octet-stream\r\n{cl}\r\n").into_bytes();
    v.extend_from_slice(body);
    v
}
fn key(r: &Request) -> TransactionKey {
    TransactionKey::from_request(r, TransactionRole::Server).unwrap()
}
fn req() -> Request {
    Request::try_from(wire(false, "Content-Length: 0\r\n", b"").as_slice()).unwrap()
}
async fn channel() -> (SipConnection, UnboundedReceiver<TransportEvent>) {
    let (_, incoming) = unbounded_channel();
    let (outgoing, rx) = unbounded_channel();
    let addr: SipAddr = "127.0.0.1:5060"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();
    (
        ChannelConnection::create_connection(incoming, outgoing, addr, None)
            .await
            .unwrap()
            .into(),
        rx,
    )
}

async fn inbound_contact(
    method: Method,
    role: TransactionRole,
    status: StatusCode,
    has_contact: bool,
) {
    let ep = EndpointBuilder::new().build();
    let (conn, mut out) = channel().await;
    ep.inner.transport_layer.add_transport(conn.clone());
    let (states_tx, mut states) = unbounded_channel();
    let (tu, _) = unbounded_channel();
    let id = if role == TransactionRole::Server {
        DialogId {
            call_id: "audit".into(),
            local_tag: "bob".into(),
            remote_tag: "alice".into(),
        }
    } else {
        DialogId {
            call_id: "audit".into(),
            local_tag: "alice".into(),
            remote_tag: "bob".into(),
        }
    };
    let inner = Arc::new(
        DialogInner::new(
            role,
            id.clone(),
            req(),
            ep.inner.clone(),
            states_tx,
            None,
            Some("sip:bob@127.0.0.1:5060".try_into().unwrap()),
            tu,
        )
        .unwrap(),
    );
    inner.set_remote_target(OLD.try_into().unwrap(), Some(format!("<{OLD}>").into()));
    inner.route_set.lock().push(ROUTE.into());
    *inner.state.lock() = DialogState::Confirmed(id, Default::default());
    let mut dlg = InviteDialog::from_inner(inner.clone());
    let mut r = req();
    r.headers
        .unique_push(Header::CSeq(format!("2 {method}").into()));
    r.method = method.clone();
    if role == TransactionRole::Client {
        r.headers
            .unique_push(Header::From("<sip:bob@example.com>;tag=bob".into()));
        r.headers
            .unique_push(Header::To("<sip:alice@example.com>;tag=alice".into()));
    }
    r.headers.retain(|h| !matches!(h, Header::Contact(_)));
    if has_contact {
        r.headers.push(Header::Contact(format!("<{NEW}>").into()));
    }
    let mut ack = r.clone();
    ack.method = Method::Ack;
    ack.headers.unique_push(Header::CSeq("2 ACK".into()));
    let mut tx = Transaction::new_server(key(&r), r, ep.inner.clone(), Some(conn.clone()));
    let events = tx.tu_sender.clone();
    let successful = status == StatusCode::OK;
    let answer = async {
        let handle = match states.recv().await.unwrap() {
            DialogState::Updated(_, _, h) | DialogState::Info(_, _, h) => h,
            x => panic!("unexpected event: {x}"),
        };
        handle.reply(status).await.unwrap();
        loop {
            if let TransportEvent::Incoming(SipMessage::Response(resp), _, _) =
                out.recv().await.unwrap()
            {
                if u16::from(resp.status_code.clone()) >= 200 {
                    if method == Method::Invite {
                        events
                            .send(TransactionEvent::Received(ack.into(), None))
                            .unwrap();
                    }
                    break;
                }
            }
        }
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(dlg.handle(&mut tx), answer)
    })
    .await
    .unwrap();
    result.unwrap();
    let expected = if successful && has_contact && matches!(method, Method::Invite | Method::Update)
    {
        NEW
    } else {
        OLD
    };
    inner.set_server_connection(Some(conn.clone()));
    let next = next_bye_uri(&dlg, &ep, conn, &mut out).await;
    assert_eq!(
        next, expected,
        "next BYE still uses the stale remote target"
    );
}

#[tokio::test]
async fn contact_incoming_update_uas() {
    inbound_contact(
        Method::Update,
        TransactionRole::Server,
        StatusCode::OK,
        true,
    )
    .await;
}
#[tokio::test]
async fn contact_incoming_reinvite_uas() {
    inbound_contact(
        Method::Invite,
        TransactionRole::Server,
        StatusCode::OK,
        true,
    )
    .await;
}
#[tokio::test]
async fn contact_incoming_update_uac_leg() {
    inbound_contact(
        Method::Update,
        TransactionRole::Client,
        StatusCode::OK,
        true,
    )
    .await;
}
#[tokio::test]
async fn contact_incoming_reinvite_uac_leg() {
    inbound_contact(
        Method::Invite,
        TransactionRole::Client,
        StatusCode::OK,
        true,
    )
    .await;
}
#[tokio::test]
async fn control_contact_rejected_update_keeps_old() {
    inbound_contact(
        Method::Update,
        TransactionRole::Server,
        StatusCode::NotAcceptableHere,
        true,
    )
    .await;
}
#[tokio::test]
async fn control_contact_rejected_reinvite_keeps_old() {
    inbound_contact(
        Method::Invite,
        TransactionRole::Server,
        StatusCode::NotAcceptableHere,
        true,
    )
    .await;
}
#[tokio::test]
async fn control_contact_absent_keeps_old() {
    inbound_contact(
        Method::Update,
        TransactionRole::Server,
        StatusCode::OK,
        false,
    )
    .await;
}
#[tokio::test]
async fn control_contact_in_info_keeps_old() {
    inbound_contact(Method::Info, TransactionRole::Server, StatusCode::OK, true).await;
}

async fn outgoing_contact(method: Method) {
    let ep = EndpointBuilder::new().build();
    let (conn, mut out) = channel().await;
    ep.inner.transport_layer.add_transport(conn.clone());
    let (states, _) = unbounded_channel();
    let (tu, _) = unbounded_channel();
    let id = DialogId {
        call_id: "audit".into(),
        local_tag: "alice".into(),
        remote_tag: "bob".into(),
    };
    let inner = Arc::new(
        DialogInner::new(
            TransactionRole::Client,
            id.clone(),
            req(),
            ep.inner.clone(),
            states,
            None,
            Some("sip:bob@127.0.0.1:5060".try_into().unwrap()),
            tu,
        )
        .unwrap(),
    );
    inner.set_remote_target(OLD.try_into().unwrap(), Some(format!("<{OLD}>").into()));
    inner.route_set.lock().push(ROUTE.into());
    inner.set_server_connection(Some(conn.clone()));
    *inner.state.lock() = DialogState::Confirmed(id, Default::default());
    let dlg = InviteDialog::from_inner(inner.clone());
    let peer = async {
        let TransportEvent::Incoming(SipMessage::Request(r), _, _) = out.recv().await.unwrap()
        else {
            panic!("missing outgoing request")
        };
        let mut response = ep.inner.make_response(&r, StatusCode::OK, None);
        response
            .headers
            .unique_push(Header::Contact(format!("<{NEW}>").into()));
        let addr = conn.get_addr().clone();
        ep.inner
            .on_received_message(response.into(), conn.clone(), &addr)
            .await
            .unwrap();
    };
    let send = async {
        if method == Method::Update {
            dlg.update(None, None).await
        } else {
            dlg.reinvite(None, None).await
        }
    };
    let (response, ()) =
        tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(send, peer) })
            .await
            .unwrap();
    assert_eq!(response.unwrap().unwrap().status_code, StatusCode::OK);
    assert_eq!(next_bye_uri(&dlg, &ep, conn, &mut out).await, NEW);
}
#[tokio::test]
async fn contact_response_to_outgoing_update() {
    outgoing_contact(Method::Update).await;
}
#[tokio::test]
async fn contact_response_to_outgoing_reinvite() {
    outgoing_contact(Method::Invite).await;
}

async fn next_bye_uri(
    dlg: &InviteDialog,
    ep: &crate::transaction::endpoint::Endpoint,
    conn: SipConnection,
    out: &mut UnboundedReceiver<TransportEvent>,
) -> String {
    let peer = async {
        loop {
            if let TransportEvent::Incoming(SipMessage::Request(r), _, _) =
                out.recv().await.unwrap()
            {
                if r.method != Method::Bye {
                    continue;
                }
                assert_eq!(r.route_header().unwrap().value(), ROUTE);
                let uri = r.uri.to_string();
                let response = ep.inner.make_response(&r, StatusCode::OK, None);
                let addr = conn.get_addr().clone();
                ep.inner
                    .on_received_message(response.into(), conn.clone(), &addr)
                    .await
                    .unwrap();
                break uri;
            }
        }
    };
    let (r, uri) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(dlg.bye(), peer)
    })
    .await
    .unwrap();
    r.unwrap();
    uri
}

async fn fixture() -> (
    Endpoint,
    Arc<DialogInner>,
    SipConnection,
    UnboundedReceiver<TransportEvent>,
) {
    let ep = EndpointBuilder::new().build();
    let (conn, out) = channel().await;
    ep.inner.transport_layer.add_transport(conn.clone());
    let (states, _) = unbounded_channel();
    let (tu, _) = unbounded_channel();
    let id = DialogId {
        call_id: "audit".into(),
        local_tag: "alice".into(),
        remote_tag: "bob".into(),
    };
    let inner = Arc::new(
        DialogInner::new(
            TransactionRole::Client,
            id.clone(),
            req(),
            ep.inner.clone(),
            states,
            None,
            Some("sip:local@127.0.0.1:5060".try_into().unwrap()),
            tu,
        )
        .unwrap(),
    );
    inner.set_remote_target(OLD.try_into().unwrap(), Some(format!("<{OLD}>").into()));
    inner.set_server_connection(Some(conn.clone()));
    inner.route_set.lock().push(ROUTE.into());
    *inner.state.lock() = DialogState::Confirmed(id, Default::default());
    (ep, inner, conn, out)
}

fn refresh_request(method: Method, cseq: u32, contact: &str) -> Request {
    let mut r = req();
    r.headers
        .unique_push(Header::CSeq(format!("{cseq} {method}").into()));
    r.method = method.clone();
    r.headers.unique_push(Header::Contact(contact.into()));
    r.headers
        .unique_push(Header::From("<sip:bob@example.com>;tag=bob".into()));
    r.headers
        .unique_push(Header::To("<sip:alice@example.com>;tag=alice".into()));
    r
}

async fn apply_response(
    inner: &DialogInner,
    ep: &Endpoint,
    conn: &SipConnection,
    request: Request,
    status: StatusCode,
) -> crate::Result<()> {
    let mut tx =
        Transaction::new_server(key(&request), request, ep.inner.clone(), Some(conn.clone()));
    let (handle, receiver) = TransactionHandle::new();
    handle.reply(status).await.unwrap();
    inner.process_transaction_handle(&mut tx, receiver).await
}

#[tokio::test]
async fn incoming_reliable_provisional_commits_before_final_error() {
    for reliable in [false, true] {
        let (ep, inner, conn, mut out) = fixture().await;
        let request = refresh_request(Method::Invite, 2, &format!("<{NEW}>"));
        let mut tx =
            Transaction::new_server(key(&request), request, ep.inner.clone(), Some(conn.clone()));
        let (handle, receiver) = TransactionHandle::new();
        let headers =
            reliable.then(|| vec![Header::Require("100rel".into()), Header::RSeq("1".into())]);
        handle
            .respond(StatusCode::SessionProgress, headers, None)
            .await
            .unwrap();
        handle.reply(StatusCode::NotAcceptableHere).await.unwrap();
        inner
            .process_transaction_handle(&mut tx, receiver)
            .await
            .unwrap();
        assert_eq!(
            inner.remote_uri.lock().to_string(),
            if reliable { NEW } else { OLD }
        );
        assert_eq!(
            inner.snapshot().remote_uri.to_string(),
            if reliable { NEW } else { OLD }
        );
        let dlg = InviteDialog::from_inner(inner.clone());
        assert_eq!(
            next_bye_uri(&dlg, &ep, conn, &mut out).await,
            if reliable { NEW } else { OLD }
        );
    }
}

#[tokio::test]
async fn failed_response_send_does_not_accept_contact() {
    let (ep, inner, conn, out) = fixture().await;
    drop(out);
    let request = refresh_request(Method::Update, 2, &format!("<{NEW}>"));
    assert!(apply_response(&inner, &ep, &conn, request, StatusCode::OK)
        .await
        .is_err());
    assert_eq!(inner.remote_uri.lock().to_string(), OLD);
}

#[tokio::test]
async fn delayed_older_request_cannot_undo_newer_target_refresh() {
    let (ep, inner, conn, _out) = fixture().await;
    for (seq, contact) in [(3, NEW), (2, OLD), (3, OLD)] {
        let request = refresh_request(Method::Update, seq, &format!("<{contact}>"));
        apply_response(&inner, &ep, &conn, request, StatusCode::OK)
            .await
            .unwrap();
        assert_eq!(inner.remote_uri.lock().to_string(), NEW);
    }
}

#[tokio::test]
async fn invalid_incoming_contact_is_rejected_before_application_event() {
    for contact in [
        "*",
        "<sip:>",
        "<sip:alice@example.com",
        "<sip:a@example.com>, <sip:b@example.com>",
    ] {
        let (ep, inner, conn, mut out) = fixture().await;
        let mut dlg = InviteDialog::from_inner(inner.clone());
        let request = refresh_request(Method::Update, 2, contact);
        let mut tx = Transaction::new_server(key(&request), request, ep.inner.clone(), Some(conn));
        // The fixture drops the application's event receiver. Reaching Updated
        // would yield 501; an early validation failure must instead return 400.
        dlg.handle(&mut tx).await.unwrap();
        let TransportEvent::Incoming(SipMessage::Response(response), _, _) =
            out.recv().await.unwrap()
        else {
            panic!("missing rejection")
        };
        assert_eq!(response.status_code, StatusCode::BadRequest);
        assert!(inner.is_confirmed());
        assert_eq!(inner.remote_uri.lock().to_string(), OLD);
    }
}

#[tokio::test]
async fn reliable_response_duplicates_do_not_reapply_stale_contact() {
    let (ep, inner, _conn, _out) = fixture().await;
    let mut response = ep
        .inner
        .make_response(&req(), StatusCode::SessionProgress, None);
    response
        .headers
        .unique_push(Header::Contact(format!("<{NEW}>").into()));
    response.headers.push(Header::Require("100rel".into()));
    response.headers.push(Header::RSeq("5".into()));
    let prack = inner.prepare_prack_request(&response).unwrap().unwrap();
    assert_eq!(prack.uri.to_string(), NEW);
    assert_eq!(prack.route_header().unwrap().value(), ROUTE);
    inner.set_remote_target(OLD.try_into().unwrap(), Some(format!("<{OLD}>").into()));
    // RFC 3262 duplicates are discarded; the existing PRACK transaction
    // owns retransmission. Its old Contact must not be applied again.
    assert!(inner.prepare_prack_request(&response).unwrap().is_none());
    assert_eq!(inner.remote_uri.lock().to_string(), OLD);
    response.headers.unique_push(Header::RSeq("4".into()));
    assert!(inner.prepare_prack_request(&response).unwrap().is_none());
    assert_eq!(inner.remote_uri.lock().to_string(), OLD);
    // A new re-INVITE can start its reliable sequence below the previous one.
    response
        .headers
        .unique_push(Header::CSeq("3 INVITE".into()));
    assert_eq!(
        inner
            .prepare_prack_request(&response)
            .unwrap()
            .unwrap()
            .uri
            .to_string(),
        NEW
    );
}

#[tokio::test]
async fn outgoing_reliable_provisional_refreshes_prack_and_survives_488() {
    let (ep, inner, conn, mut out) = fixture().await;
    let dlg = InviteDialog::from_inner(inner.clone());
    let peer = async {
        let TransportEvent::Incoming(SipMessage::Request(invite), _, _) = out.recv().await.unwrap()
        else {
            panic!("missing INVITE")
        };
        let mut progress = ep
            .inner
            .make_response(&invite, StatusCode::SessionProgress, None);
        progress
            .headers
            .unique_push(Header::Contact(format!("<{NEW}>").into()));
        progress.headers.push(Header::Require("100rel".into()));
        progress.headers.push(Header::RSeq("1".into()));
        let addr = conn.get_addr().clone();
        ep.inner
            .on_received_message(progress.into(), conn.clone(), &addr)
            .await
            .unwrap();
        let TransportEvent::Incoming(SipMessage::Request(prack), _, _) = out.recv().await.unwrap()
        else {
            panic!("missing PRACK")
        };
        assert_eq!(prack.method, Method::PRack);
        assert_eq!(prack.uri.to_string(), NEW);
        assert_eq!(prack.route_header().unwrap().value(), ROUTE);
        let response = ep.inner.make_response(&prack, StatusCode::OK, None);
        ep.inner
            .on_received_message(response.into(), conn.clone(), &addr)
            .await
            .unwrap();
        let mut rejection = ep
            .inner
            .make_response(&invite, StatusCode::NotAcceptableHere, None);
        rejection
            .headers
            .unique_push(Header::Contact(format!("<{OLD}>").into()));
        ep.inner
            .on_received_message(rejection.into(), conn.clone(), &addr)
            .await
            .unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(dlg.reinvite(None, None), peer)
    })
    .await
    .unwrap();
    assert_eq!(
        result.unwrap().unwrap().status_code,
        StatusCode::NotAcceptableHere
    );
    assert_eq!(next_bye_uri(&dlg, &ep, conn, &mut out).await, NEW);
}

#[tokio::test]
async fn invalid_response_contact_preserves_both_target_fields() {
    let (ep, inner, conn, mut out) = fixture().await;
    let dlg = InviteDialog::from_inner(inner.clone());
    let peer = async {
        let TransportEvent::Incoming(SipMessage::Request(update), _, _) = out.recv().await.unwrap()
        else {
            panic!("missing UPDATE")
        };
        let mut response = ep.inner.make_response(&update, StatusCode::OK, None);
        response.headers.unique_push(Header::Contact("*".into()));
        let addr = conn.get_addr().clone();
        ep.inner
            .on_received_message(response.into(), conn.clone(), &addr)
            .await
            .unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(dlg.update(None, None), peer)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(inner.remote_uri.lock().to_string(), OLD);
    assert_eq!(
        inner.remote_contact.lock().as_ref().unwrap().value(),
        format!("<{OLD}>")
    );
}

#[tokio::test]
async fn response_without_contact_or_without_acceptance_keeps_target() {
    for (method, status, contact, foreign_tag) in [
        (Method::Update, StatusCode::OK, false, false),
        (Method::Update, StatusCode::NotAcceptableHere, true, false),
        (Method::Info, StatusCode::OK, true, false),
        (Method::Update, StatusCode::OK, true, true),
    ] {
        let (ep, inner, conn, mut out) = fixture().await;
        let dlg = InviteDialog::from_inner(inner.clone());
        let peer = async {
            let TransportEvent::Incoming(SipMessage::Request(request), _, _) =
                out.recv().await.unwrap()
            else {
                panic!("missing request")
            };
            let mut response = ep.inner.make_response(&request, status, None);
            if contact {
                response
                    .headers
                    .unique_push(Header::Contact(format!("<{NEW}>").into()));
            }
            if foreign_tag {
                response
                    .headers
                    .unique_push(Header::To("<sip:bob@example.com>;tag=other-dialog".into()));
            }
            let addr = conn.get_addr().clone();
            ep.inner
                .on_received_message(response.into(), conn.clone(), &addr)
                .await
                .unwrap();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(dlg.request(method, None, None), peer)
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(inner.remote_uri.lock().to_string(), OLD);
        assert_eq!(inner.id.lock().remote_tag, "bob");
    }
}

#[tokio::test]
async fn reliable_refresh_does_not_depend_on_confirmed_state_variant() {
    let (ep, inner, _conn, _out) = fixture().await;
    let (handle, _) = TransactionHandle::new();
    let id = inner.id.lock().clone();
    *inner.state.lock() = DialogState::Updated(id, req(), handle);
    let mut response = ep
        .inner
        .make_response(&req(), StatusCode::SessionProgress, None);
    response
        .headers
        .unique_push(Header::Contact(format!("<{NEW}>").into()));
    response.headers.push(Header::Require("100rel".into()));
    response.headers.push(Header::RSeq("1".into()));
    assert_eq!(
        inner
            .prepare_prack_request(&response)
            .unwrap()
            .unwrap()
            .uri
            .to_string(),
        NEW
    );
}
