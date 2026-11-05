//! RFC 3261 §§9.2, 17.1.3, 17.2.3, 19.1.4 and 20.42.
use crate::sip::{headers, prelude::HeadersExt, Method, Request, SipMessage, StatusCode};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::{Transaction, TransactionEvent},
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use crate::EndpointBuilder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::time::{timeout, Duration};

fn request(branch: &str) -> Request {
    let branch = if branch.is_empty() {
        String::new()
    } else {
        format!(";branch={branch}")
    };
    format!("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060{branch}\r\nFrom: <sip:a@example.com>;tag=alice\r\nTo: <sip:b@example.com>\r\nCall-ID: matching\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n").try_into().unwrap()
}
fn method(mut req: Request, method: Method) -> Request {
    req.headers
        .unique_push(headers::CSeq::new(format!("1 {method}")).into());
    req.method = method;
    req
}
fn server(req: &Request) -> TransactionKey {
    TransactionKey::from_request(req, TransactionRole::Server).unwrap()
}
fn client(req: &Request) -> TransactionKey {
    TransactionKey::from_request(req, TransactionRole::Client).unwrap()
}
fn via(req: &mut Request, value: &str) {
    req.headers.unique_push(headers::Via::new(value).into());
}
async fn channel() -> (SipConnection, SipAddr, UnboundedReceiver<TransportEvent>) {
    let (sender, receiver) = unbounded_channel();
    let addr = SipAddr::new(
        crate::sip::Transport::Udp,
        "127.0.0.1:5060"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    );
    (
        ChannelConnection::create_connection(unbounded_channel().1, sender, addr.clone(), None)
            .await
            .unwrap()
            .into(),
        addr,
        receiver,
    )
}

#[test]
fn server_key_includes_sent_by_host_and_port() {
    let a = request("z9hG4bK-x");
    for address in ["192.0.2.2:5060", "192.0.2.1:5070"] {
        let mut b = a.clone();
        via(&mut b, &format!("SIP/2.0/UDP {address};branch=z9hG4bK-x"));
        assert_ne!(server(&a), server(&b));
    }
}
#[test]
fn cookie_branch_collision_cannot_cross_field_boundaries() {
    let mut a = request("z9hG4bK-y");
    a.headers
        .unique_push(headers::From::new("<sip:a@example.com>;tag=alice_z9hG4bK-x").into());
    let b = request("z9hG4bK-x_z9hG4bK-y");
    assert_ne!(server(&a), server(&b));
    assert_ne!(client(&a), client(&b));
}
#[test]
fn modern_matching_does_not_add_non_rfc_fields() {
    let a = request("z9hG4bK-x");
    let mut b = a.clone();
    b.uri = "sip:other@example.com".try_into().unwrap();
    b.headers.unique_push(headers::CallId::new("other").into());
    b.headers
        .unique_push(headers::From::new("<sip:c@example.com>;tag=other").into());
    b.headers.unique_push(headers::CSeq::new("2 INVITE").into());
    b.to_header_mut().unwrap().mut_tag("other".into()).unwrap();
    assert_eq!(server(&a), server(&b));
    assert_eq!(client(&a), client(&b));
}
#[test]
fn modern_sent_by_ignores_transport_and_other_via_parameters() {
    let a = request("z9hG4bK-x");
    let mut b = a.clone();
    via(
        &mut b,
        "SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK-x;received=192.0.2.9;rport=6000",
    );
    assert_eq!(server(&a), server(&b));
}
#[test]
fn sent_by_host_case_and_default_port_are_normalized() {
    let mut a = request("z9hG4bK-x");
    let mut b = a.clone();
    via(&mut a, "SIP/2.0/UDP EXAMPLE.COM;branch=z9hG4bK-x");
    via(&mut b, "SIP/2.0/UDP example.com:5060;branch=z9hG4bK-x");
    assert_eq!(server(&a), server(&b));
}
#[test]
fn branch_is_case_sensitive() {
    assert_ne!(server(&request("z9hG4bK-X")), server(&request("z9hG4bK-x")));
}
#[test]
fn ack_matches_invite_but_cancel_has_its_own_key() {
    let req = request("z9hG4bK-x");
    assert_eq!(server(&req), server(&method(req.clone(), Method::Ack)));
    assert_ne!(server(&req), server(&method(req.clone(), Method::Cancel)));
    assert_ne!(client(&req), client(&method(req, Method::Cancel)));
}
#[test]
fn client_responses_use_branch_and_cseq_method_only() {
    let req = request("z9hG4bK-x");
    let endpoint = EndpointBuilder::new().build();
    let mut resp = endpoint.inner.make_response(&req, StatusCode::OK, None);
    resp.headers.unique_push(headers::Via::new("SIP/2.0/TCP other.example:5099;branch=z9hG4bK-x, SIP/2.0/UDP ignored.example;branch=z9hG4bK-other").into());
    resp.headers
        .unique_push(headers::CallId::new("changed").into());
    resp.headers
        .unique_push(headers::CSeq::new("99 INVITE").into());
    resp.headers
        .unique_push(headers::From::new("<sip:c@example.com>;tag=changed").into());
    assert_eq!(
        client(&req),
        TransactionKey::from_response(&resp, TransactionRole::Client).unwrap()
    );
    resp.headers
        .unique_push(headers::CSeq::new("99 CANCEL").into());
    assert_ne!(
        client(&req),
        TransactionKey::from_response(&resp, TransactionRole::Client).unwrap()
    );
}
#[test]
fn missing_or_non_cookie_branch_requires_all_legacy_fields() {
    for branch in ["", "old-branch", "Z9hG4bK-wrong-case"] {
        let a = request(branch);
        let mut changes = vec![];
        let mut b = a.clone();
        b.uri = "sip:else@example.com".try_into().unwrap();
        changes.push(b);
        let mut b = a.clone();
        b.to_header_mut()
            .unwrap()
            .mut_tag("different".into())
            .unwrap();
        changes.push(b);
        let mut b = a.clone();
        b.headers
            .unique_push(headers::From::new("<sip:a@example.com>;tag=other").into());
        changes.push(b);
        let mut b = a.clone();
        b.headers.unique_push(headers::CallId::new("other").into());
        changes.push(b);
        let mut b = a.clone();
        b.headers.unique_push(headers::CSeq::new("2 INVITE").into());
        changes.push(b);
        let mut b = a.clone();
        let v = b.via_header().unwrap().value().to_owned() + ";rport";
        via(&mut b, &v);
        changes.push(b);
        for b in changes {
            assert_ne!(server(&a), server(&b), "branch={branch}");
        }
    }
}
#[test]
fn legacy_tagless_request_is_supported() {
    let mut req = request("");
    req.headers
        .unique_push(headers::From::new("<sip:a@example.com>").into());
    assert!(TransactionKey::from_request(&req, TransactionRole::Server).is_ok());
}
#[test]
fn legacy_server_key_cannot_be_reconstructed_from_response() {
    let resp =
        EndpointBuilder::new()
            .build()
            .inner
            .make_response(&request("old"), StatusCode::OK, None);
    assert!(TransactionKey::from_response(&resp, TransactionRole::Server).is_err());
}
#[test]
fn legacy_via_parameter_order_and_token_case_do_not_matter() {
    let mut a = request("old");
    let mut b = a.clone();
    via(
        &mut a,
        "SIP/2.0/UDP example.com:5060;branch=old;received=192.0.2.1;foo=BAR",
    );
    via(
        &mut b,
        "SIP/2.0/UDP EXAMPLE.COM:5060;FOO=bar;RECEIVED=192.0.2.1;BRANCH=old",
    );
    assert_eq!(server(&a), server(&b));
    via(
        &mut b,
        "SIP/2.0/TCP example.com:5060;branch=old;received=192.0.2.1;foo=bar",
    );
    assert_ne!(server(&a), server(&b));
}

async fn dispatch(a: Request, b: Request, should_match: bool) {
    let endpoint = EndpointBuilder::new().build();
    let mut incoming = endpoint.incoming_transactions().unwrap();
    let (conn, addr, _out) = channel().await;
    let mut tx = Transaction::new_server(server(&a), a, endpoint.inner.clone(), Some(conn.clone()));
    endpoint
        .inner
        .on_received_message(b.into(), conn, &addr)
        .await
        .unwrap();
    assert_eq!(
        matches!(
            tx.tu_receiver.try_recv(),
            Ok(TransactionEvent::Received(_, _))
        ),
        should_match
    );
    assert_eq!(incoming.try_recv().is_ok(), !should_match);
}
#[tokio::test]
async fn endpoint_never_delivers_colliding_branch_to_other_transaction() {
    let mut a = request("z9hG4bK-y");
    a.headers
        .unique_push(headers::From::new("<sip:a@example.com>;tag=alice_z9hG4bK-x").into());
    dispatch(a, request("z9hG4bK-x_z9hG4bK-y"), false).await;
}
#[tokio::test]
async fn endpoint_distinguishes_sent_by() {
    let a = request("z9hG4bK-x");
    let mut b = a.clone();
    via(&mut b, "SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bK-x");
    dispatch(a, b, false).await;
}
#[tokio::test]
async fn legacy_request_uri_matching_uses_rfc_uri_comparison() {
    for (a, b, same) in [
        (
            "sip:%62ob@EXAMPLE.com;transport=UDP",
            "sip:bob@example.com;Transport=udp",
            true,
        ),
        ("sip:bob@example.com;foo=one", "sip:bob@example.com", true),
        (
            "sip:bob@example.com;foo=one",
            "sip:bob@example.com;foo=two",
            false,
        ),
        ("sip:bob@example.com", "sip:BOB@example.com", false),
        ("sip:bob@example.com", "sips:bob@example.com", false),
        ("sip:bob@example.com", "sip:bob@example.com:5060", false),
        (
            "sip:bob@example.com",
            "sip:bob@example.com;transport=udp",
            false,
        ),
        ("sip:bob@example.com", "sip:bob@example.com;user=ip", false),
        (
            "sip:bob@example.com",
            "sip:bob@example.com;maddr=192.0.2.1",
            false,
        ),
        ("sip:bob@example.com", "sip:bob@example.com;ttl=1", false),
        (
            "sip:bob:secret@example.com",
            "sip:bob:Secret@example.com",
            false,
        ),
        (
            "sip:bob%2Fname@example.com",
            "sip:bob/name@example.com",
            false,
        ),
        (
            "sip:bob@example.com;a=1;b=2",
            "sip:bob@example.com;B=2;A=1",
            true,
        ),
    ] {
        let mut first = request("old");
        first.uri = a.try_into().unwrap();
        let mut second = request("old");
        second.uri = b.try_into().unwrap();
        dispatch(first, second, same).await;
    }
}
#[tokio::test]
async fn cached_legacy_response_uses_same_uri_comparison() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, mut out) = channel().await;
    let original = request("old");
    let key = server(&original);
    let resp = endpoint
        .inner
        .make_response(&original, StatusCode::BusyHere, None);
    endpoint
        .inner
        .finished_transactions
        .insert(key, Some(resp.into()));
    let mut retry = original;
    retry.uri = "sip:bob@example.com;extension=1".try_into().unwrap();
    endpoint
        .inner
        .on_received_message(retry.into(), conn, &addr)
        .await
        .unwrap();
    assert!(matches!(
        out.try_recv(),
        Ok(TransportEvent::Incoming(SipMessage::Response(_), _, _))
    ));
}
#[tokio::test]
async fn legacy_ack_checks_request_fields_and_response_to_tag() {
    for branch in ["", "old"] {
        let endpoint = EndpointBuilder::new().build();
        let (conn, addr, _out) = channel().await;
        let req = request(branch);
        let mut tx = Transaction::new_server(
            server(&req),
            req.clone(),
            endpoint.inner.clone(),
            Some(conn.clone()),
        );
        let mut response = endpoint
            .inner
            .make_response(&req, StatusCode::BusyHere, None);
        response
            .to_header_mut()
            .unwrap()
            .mut_tag("server-tag".into())
            .unwrap();
        tx.respond(response).await.unwrap();
        let mut ack = method(req, Method::Ack);
        ack.to_header_mut()
            .unwrap()
            .mut_tag("wrong-tag".into())
            .unwrap();
        endpoint
            .inner
            .on_received_message(ack.clone().into(), conn.clone(), &addr)
            .await
            .unwrap();
        assert!(tx.tu_receiver.try_recv().is_err());
        ack.to_header_mut()
            .unwrap()
            .mut_tag("server-tag".into())
            .unwrap();
        let mut wrong_uri = ack.clone();
        wrong_uri.uri = "sip:wrong@example.com".try_into().unwrap();
        endpoint
            .inner
            .on_received_message(wrong_uri.into(), conn.clone(), &addr)
            .await
            .unwrap();
        assert!(tx.tu_receiver.try_recv().is_err());
        endpoint
            .inner
            .on_received_message(ack.into(), conn, &addr)
            .await
            .unwrap();
        assert!(matches!(
            tx.tu_receiver.try_recv(),
            Ok(TransactionEvent::Received(_, _))
        ));
    }
}
#[tokio::test]
async fn cancel_cannot_cancel_a_different_sent_by() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, mut out) = channel().await;
    let req = request("z9hG4bK-x");
    let mut tx = Transaction::new_server(
        server(&req),
        req.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut cancel = method(req, Method::Cancel);
    via(&mut cancel, "SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bK-x");
    endpoint
        .inner
        .on_received_message(cancel.into(), conn, &addr)
        .await
        .unwrap();
    assert!(tx.tu_receiver.try_recv().is_err());
    let TransportEvent::Incoming(SipMessage::Response(resp), _, _) = out.try_recv().unwrap() else {
        panic!()
    };
    assert_eq!(resp.status_code, StatusCode::CallTransactionDoesNotExist);
}
#[tokio::test]
async fn queued_cancel_retransmissions_only_reach_invite_tu_once() {
    for branch in ["z9hG4bK-x", "old", ""] {
        let endpoint = EndpointBuilder::new().build();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = SipAddr::new(
            crate::sip::Transport::Udp,
            peer.local_addr().unwrap().into(),
        );
        let conn: SipConnection = crate::transport::udp::UdpConnection::create_connection(
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
        )
        .await
        .unwrap()
        .into();
        let mut req = request(branch);
        let branch_param = if branch.is_empty() {
            String::new()
        } else {
            format!(";branch={branch}")
        };
        via(
            &mut req,
            &format!("SIP/2.0/UDP {}{branch_param}", peer.local_addr().unwrap()),
        );
        let mut tx = Transaction::new_server(
            server(&req),
            req.clone(),
            endpoint.inner.clone(),
            Some(conn.clone()),
        );
        let cancel = method(req, Method::Cancel);
        let mut second = cancel.clone();
        if branch != "z9hG4bK-x" {
            second.uri = "sip:bob@example.com;extension=1".try_into().unwrap();
        }
        for request in [&cancel, &second] {
            endpoint
                .inner
                .on_received_message(request.clone().into(), conn.clone(), &addr)
                .await
                .unwrap();
        }
        let first = timeout(Duration::from_secs(1), tx.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, SipMessage::Request(r) if r.method == Method::Cancel));
        assert!(timeout(Duration::from_millis(20), tx.receive())
            .await
            .is_err());
        let mut buf = [0; 4096];
        for _ in 0..2 {
            let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let resp = crate::sip::Response::try_from(&buf[..n]).unwrap();
            assert_eq!(resp.status_code, StatusCode::OK);
            assert_eq!(
                resp.cseq_header().unwrap().method().unwrap(),
                Method::Cancel
            );
        }
        endpoint
            .inner
            .on_received_message(second.into(), conn, &addr)
            .await
            .unwrap();
        assert!(tx.tu_receiver.try_recv().is_err());
        assert!(timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
            .await
            .is_ok());
    }
}
#[tokio::test]
async fn cancel_can_match_non_invite_without_cancelling_it() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, mut out) = channel().await;
    let req = method(request("z9hG4bK-x"), Method::Options);
    let mut tx = Transaction::new_server(
        server(&req),
        req.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    endpoint
        .inner
        .on_received_message(method(req, Method::Cancel).into(), conn, &addr)
        .await
        .unwrap();
    assert!(timeout(Duration::from_millis(20), tx.receive())
        .await
        .is_err());
    let TransportEvent::Incoming(SipMessage::Response(resp), _, _) = out.try_recv().unwrap() else {
        panic!()
    };
    assert_eq!(resp.status_code, StatusCode::OK);
}

#[tokio::test]
async fn legacy_2xx_ack_uses_dialog_cseq_instead_of_old_branch() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, _out) = channel().await;
    let req = request("old");
    let mut tx = Transaction::new_server(
        server(&req),
        req.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut response = endpoint.inner.make_response(&req, StatusCode::OK, None);
    response
        .to_header_mut()
        .unwrap()
        .mut_tag("server".into())
        .unwrap();
    tx.respond(response).await.unwrap();
    let mut ack = method(req, Method::Ack);
    ack.to_header_mut()
        .unwrap()
        .mut_tag("server".into())
        .unwrap();
    ack.uri = "sip:new-target@example.com".try_into().unwrap();
    via(
        &mut ack,
        "SIP/2.0/UDP 192.0.2.9:5099;branch=z9hG4bK-new-ack",
    );
    endpoint
        .inner
        .on_received_message(ack.into(), conn, &addr)
        .await
        .unwrap();
    assert!(matches!(
        tx.tu_receiver.try_recv(),
        Ok(TransactionEvent::Received(_, _))
    ));
}

#[tokio::test]
async fn legacy_cancel_checks_original_request_uri() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, mut out) = channel().await;
    let req = request("old");
    let mut tx = Transaction::new_server(
        server(&req),
        req.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut cancel = method(req, Method::Cancel);
    cancel.uri = "sip:another@example.com".try_into().unwrap();
    endpoint
        .inner
        .on_received_message(cancel.into(), conn, &addr)
        .await
        .unwrap();
    assert!(tx.tu_receiver.try_recv().is_err());
    let TransportEvent::Incoming(SipMessage::Response(resp), _, _) = out.try_recv().unwrap() else {
        panic!()
    };
    assert_eq!(resp.status_code, StatusCode::CallTransactionDoesNotExist);
    assert!(resp.to_header().unwrap().tag().unwrap().is_some());
}

#[tokio::test]
async fn legacy_lookup_ignores_unrelated_calls_sequences_and_tags() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, _out) = channel().await;
    let req = request("old");
    let mut tx = Transaction::new_server(
        server(&req),
        req.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut unrelated = vec![];
    for header in [
        headers::CallId::new("aaa").into(),
        headers::CallId::new("zzz").into(),
        headers::CSeq::new("0 INVITE").into(),
        headers::CSeq::new("2 INVITE").into(),
        headers::From::new("<sip:a@example.com>;tag=aaa").into(),
        headers::From::new("<sip:a@example.com>;tag=zzz").into(),
    ] {
        let mut other = req.clone();
        other.headers.unique_push(header);
        unrelated.push(Transaction::new_server(
            server(&other),
            other,
            endpoint.inner.clone(),
            Some(conn.clone()),
        ));
    }
    let mut retry = req;
    retry.uri = "sip:bob@example.com;extension=1".try_into().unwrap();
    endpoint
        .inner
        .on_received_message(retry.into(), conn, &addr)
        .await
        .unwrap();
    assert!(matches!(
        tx.tu_receiver.try_recv(),
        Ok(TransactionEvent::Received(_, _))
    ));
    assert!(unrelated
        .iter_mut()
        .all(|tx| tx.tu_receiver.try_recv().is_err()));
}

#[tokio::test]
async fn endpoint_routes_cancel_response_to_client_cancel_only() {
    let endpoint = EndpointBuilder::new().build();
    let (conn, addr, _out) = channel().await;
    let invite = request("z9hG4bK-x");
    let cancel = method(invite.clone(), Method::Cancel);
    let mut invite_tx = Transaction::new_client(
        client(&invite),
        invite,
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut cancel_tx = Transaction::new_client(
        client(&cancel),
        cancel.clone(),
        endpoint.inner.clone(),
        Some(conn.clone()),
    );
    let mut response = endpoint.inner.make_response(&cancel, StatusCode::OK, None);
    response.headers.unique_push(
        headers::Via::new("SIP/2.0/UDP different.example:5099;branch=z9hG4bK-x").into(),
    );
    endpoint
        .inner
        .on_received_message(response.into(), conn, &addr)
        .await
        .unwrap();
    assert!(invite_tx.tu_receiver.try_recv().is_err());
    assert!(matches!(
        cancel_tx.tu_receiver.try_recv(),
        Ok(TransactionEvent::Received(_, _))
    ));
}
