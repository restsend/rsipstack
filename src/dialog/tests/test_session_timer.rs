//! RFC 4028 wire regressions. SIP intervals stay >= 90 seconds; only the
//! Tokio clock used by the session scheduler is advanced between exchanges.
use super::test_in_dialog_provisional::{recv_request, response};
use crate::{
    dialog::{
        dialog::{DialogState, DialogStateSender},
        dialog_layer::DialogLayer,
        invitation::InviteOption,
        invite_dialog::InviteDialog,
        session_timer::{RefreshMethod, SessionTimerConfig},
    },
    sip::{
        Header, HeadersExt, Method, Request, Response, SipMessage, StatusCode, ToTypedHeader, Uri,
    },
    transport::{udp::UdpConnection, TransportLayer},
    EndpointBuilder,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=inactive\r\n";

fn config() -> SessionTimerConfig {
    SessionTimerConfig {
        expires: 90,
        ..Default::default()
    }
}

struct Node {
    token: CancellationToken,
    layer: Arc<DialogLayer>,
    uri: Uri,
    sender: DialogStateSender,
    incoming: mpsc::UnboundedReceiver<InviteDialog>,
    errors: Arc<std::sync::Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        for id in self.layer.all_dialog_ids() {
            if let Some(d) = self.layer.get_dialog_with(&id) {
                self.layer.remove_dialog(&d.id());
            }
        }
        self.token.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Node {
    async fn new(config: Option<SessionTimerConfig>) -> crate::Result<Self> {
        let token = CancellationToken::new();
        let transport = TransportLayer::new(token.child_token());
        let udp = UdpConnection::create_connection(
            "127.0.0.1:0".parse().unwrap(),
            None,
            Some(token.child_token()),
        )
        .await?;
        let uri: Uri = format!("sip:timer@{}", udp.get_addr().addr).parse()?;
        transport.add_transport(udp.into());
        let endpoint = EndpointBuilder::new()
            .with_transport_layer(transport)
            .with_cancel_token(token.child_token())
            .build();
        let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        layer.set_session_timer(config)?;
        let (sender, mut states) = layer.new_dialog_state_channel();
        let mut transactions = endpoint.incoming_transactions()?;
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        let errors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let serve = tokio::spawn(async move {
            endpoint.inner.serve().await.ok();
        });
        let router = layer.clone();
        let events = sender.clone();
        let local = uri.clone();
        let diagnostics = errors.clone();
        let request_task = tokio::spawn(async move {
            while let Some(mut tx) = transactions.recv().await {
                let dialog = router.match_dialog(&tx).or_else(|| {
                    if tx.original.method != Method::Invite {
                        return None;
                    }
                    let dialog = router
                        .get_or_create_server_invite(&tx, events.clone(), None, Some(local.clone()))
                        .ok()?;
                    incoming_tx.send(dialog.clone()).ok();
                    Some(crate::dialog::dialog::Dialog::Invite(dialog))
                });
                if let Some(mut dialog) = dialog {
                    let diagnostics = diagnostics.clone();
                    tokio::spawn(async move {
                        if let Err(error) = dialog.handle(&mut tx).await {
                            diagnostics.lock().unwrap().push(error.to_string());
                        }
                        while tx.receive().await.is_some() {}
                    });
                } else {
                    tx.reply(StatusCode::CallTransactionDoesNotExist).await.ok();
                }
            }
        });
        let registry = layer.clone();
        let state_task = tokio::spawn(async move {
            while let Some(state) = states.recv().await {
                if let DialogState::Terminated(id, _) = state {
                    registry.remove_dialog(&id);
                }
            }
        });
        Ok(Self {
            token,
            layer,
            uri,
            sender,
            incoming,
            errors,
            tasks: vec![serve, request_task, state_task],
        })
    }
    fn invite(
        &self,
        peer: &UdpSocket,
    ) -> JoinHandle<crate::Result<(InviteDialog, Option<Response>)>> {
        let layer = self.layer.clone();
        let sender = self.sender.clone();
        let opt = InviteOption {
            caller: self.uri.clone(),
            contact: self.uri.clone(),
            callee: format!("sip:peer@{}", peer.local_addr().unwrap())
                .parse()
                .unwrap(),
            offer: Some(SDP.into()),
            ..Default::default()
        };
        tokio::spawn(async move { layer.do_invite(opt, sender).await })
    }
    fn clean(&self) {
        assert!(
            self.errors.lock().unwrap().is_empty(),
            "{:?}",
            self.errors.lock().unwrap()
        );
    }
}

async fn answer(
    peer: &UdpSocket,
    addr: SocketAddr,
    request: &Request,
    code: u16,
    timer: Option<&str>,
    update: bool,
) -> Response {
    let mut r = Response::try_from(
        response(
            request,
            code,
            "Test",
            &format!("sip:peer@{}", peer.local_addr().unwrap()),
        )
        .as_str(),
    )
    .unwrap();
    if let Some(timer) = timer {
        r.headers.unique_push(Header::SessionExpires(timer.into()));
    }
    if update {
        r.headers.push(Header::Allow("INVITE, UPDATE, BYE".into()));
    }
    if code == 200 && request.method == Method::Invite {
        r.body = SDP.into();
        r.headers
            .unique_push(Header::ContentType("application/sdp".into()));
        r.headers
            .unique_push(Header::ContentLength((SDP.len() as u32).into()));
    }
    peer.send_to(r.to_string().as_bytes(), addr).await.unwrap();
    r
}

async fn established(
    timer: &str,
    update: bool,
    cfg: SessionTimerConfig,
) -> (Node, InviteDialog, UdpSocket, Request, SocketAddr) {
    let node = Node::new(Some(cfg)).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let future = node.invite(&peer);
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    assert!(request.header_contains_token("Supported", "timer"));
    answer(&peer, addr, &request, 200, Some(timer), update).await;
    recv_request(&peer, Method::Ack).await;
    let (dialog, _) = future.await.unwrap().unwrap();
    (node, dialog, peer, request, addr)
}

async fn advance(seconds: u64) {
    // Keep an executor task runnable so Tokio cannot automatically jump beyond
    // the requested instant while real UDP peers are between packets.
    let busy = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(seconds)).await;
    tokio::time::resume();
    busy.abort();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
}

async fn finished(dialog: &InviteDialog) {
    for _ in 0..100 {
        if !dialog.session_timer_status().unwrap().worker_running {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session timer task did not stop");
}

#[tokio::test]
async fn session_timer_update_refresh_resets_only_on_success() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Update).await;
    assert!(request.body.is_empty());
    assert_eq!(
        request.session_expires_header().unwrap().value(),
        "90;refresher=uac"
    );
    answer(&peer, addr, &request, 200, Some("90;refresher=uac"), true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(dialog.session_timer_status().unwrap().remaining > Duration::from_secs(89));
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Update).await;
    answer(&peer, addr, &request, 488, None, true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(dialog.state().is_confirmed());
    advance(46).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    assert_eq!(dialog.session_timer_status().unwrap().refreshes, 2);
    assert_eq!(dialog.session_timer_status().unwrap().expirations, 1);
    node.clean();
}

#[tokio::test]
async fn session_timer_reinvite_reuses_negotiated_sdp_and_ack() {
    let (node, dialog, peer, initial, _) = established("90;refresher=uac", false, config()).await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    assert_eq!(request.body, SDP);
    assert_eq!(
        request.call_id_header().unwrap(),
        initial.call_id_header().unwrap()
    );
    assert!(
        request.cseq_header().unwrap().seq().unwrap()
            > initial.cseq_header().unwrap().seq().unwrap()
    );
    answer(&peer, addr, &request, 200, Some("90;refresher=uac"), false).await;
    recv_request(&peer, Method::Ack).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_remote_expiration_uses_rfc_grace_period() {
    let (node, dialog, peer, _, _) = established("90;refresher=uas", true, config()).await;
    advance(59).await;
    assert!(dialog.state().is_confirmed());
    advance(2).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_422_retries_with_new_transaction_and_preserves_dialog() {
    let node = Node::new(Some(config())).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let future = node.invite(&peer);
    let (first, addr) = recv_request(&peer, Method::Invite).await;
    let mut challenge = Response::try_from(
        response(
            &first,
            422,
            "Session Interval Too Small",
            &format!("sip:peer@{}", peer.local_addr().unwrap()),
        )
        .as_str(),
    )
    .unwrap();
    challenge.headers.push(Header::MinSE("120".into()));
    peer.send_to(challenge.to_string().as_bytes(), addr)
        .await
        .unwrap();
    recv_request(&peer, Method::Ack).await;
    let (second, addr) = recv_request(&peer, Method::Invite).await;
    assert_eq!(
        second.call_id_header().unwrap(),
        first.call_id_header().unwrap()
    );
    assert_eq!(
        second.cseq_header().unwrap().seq().unwrap(),
        first.cseq_header().unwrap().seq().unwrap() + 1
    );
    assert_ne!(second.via_header().unwrap(), first.via_header().unwrap());
    assert_eq!(second.body, first.body);
    assert!(second.to_header().unwrap().tag().unwrap().is_none());
    assert_eq!(
        second.session_expires_header().unwrap().value(),
        "120;refresher=uac"
    );
    answer(&peer, addr, &second, 200, Some("120;refresher=uac"), true).await;
    recv_request(&peer, Method::Ack).await;
    let (dialog, _) = future.await.unwrap().unwrap();
    assert_eq!(dialog.session_timer_status().unwrap().interval, Some(120));
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_missing_response_header_disables_timer() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Update).await;
    answer(&peer, addr, &request, 200, None, true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(dialog.session_timer_status().unwrap().interval, None);
    advance(100).await;
    assert!(dialog.state().is_confirmed());
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_481_refresh_ends_session_immediately() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Update).await;
    answer(&peer, addr, &request, 481, None, true).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_duplicate_200_does_not_extend_deadline() {
    let (node, dialog, peer, request, addr) = established("90;refresher=uas", true, config()).await;
    advance(30).await;
    answer(&peer, addr, &request, 200, Some("90;refresher=uas"), true).await;
    recv_request(&peer, Method::Ack).await;
    assert!(dialog.session_timer_status().unwrap().remaining < Duration::from_secs(61));
    advance(31).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    node.clean();
}

async fn recv_response(peer: &UdpSocket, code: u16) -> Response {
    let mut data = [0; 8192];
    loop {
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        if let SipMessage::Response(response) =
            SipMessage::try_from(std::str::from_utf8(&data[..n]).unwrap()).unwrap()
        {
            if response.status_code.code() == 100 {
                continue;
            }
            assert_eq!(response.status_code.code(), code, "{response}");
            return response;
        }
    }
}
fn incoming(node: &Node, peer: &UdpSocket, headers: &str) -> Request {
    format!("INVITE {} SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bK-timer-initial;rport\r\nFrom: <sip:peer@localhost>;tag=caller\r\nTo: <{}>\r\nCall-ID: session-timer-test\r\nCSeq: 1 INVITE\r\nContact: <sip:peer@{}>\r\nMax-Forwards: 70\r\n{}Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
        node.uri, peer.local_addr().unwrap(), node.uri, peer.local_addr().unwrap(), headers, SDP.len(), std::str::from_utf8(SDP).unwrap()).as_str().try_into().unwrap()
}
async fn send(peer: &UdpSocket, node: &Node, request: &Request) {
    peer.send_to(
        request.to_string().as_bytes(),
        node.uri.host_with_port.to_string(),
    )
    .await
    .unwrap();
}
fn followup(
    initial: &Request,
    response: &Response,
    method: Method,
    seq: u32,
    timer: Option<&str>,
) -> Request {
    let mut request = initial.clone();
    request.method = method.clone();
    request
        .headers
        .unique_push(Header::CSeq(format!("{seq} {method}").into()));
    request
        .headers
        .unique_push(Header::To(response.to_header().unwrap().clone()));
    request.headers.unique_push(Header::Via(
        format!(
            "SIP/2.0/UDP {};branch=z9hG4bK-next-{seq}-{method};rport",
            request
                .contact_header()
                .unwrap()
                .typed()
                .unwrap()
                .uri
                .host_with_port
        )
        .into(),
    ));
    request.headers.retain(|h| {
        !matches!(
            h,
            Header::SessionExpires(_)
                | Header::MinSE(_)
                | Header::ContentType(_)
                | Header::Require(_)
        )
    });
    if let Some(timer) = timer {
        request.headers.push(Header::SessionExpires(timer.into()));
    }
    request.body.clear();
    request.headers.unique_push(Header::ContentLength(0.into()));
    request
}
async fn uas(headers: &str) -> (Node, InviteDialog, UdpSocket, Request, Response) {
    let mut node = Node::new(Some(config())).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = incoming(&node, &peer, headers);
    send(&peer, &node, &request).await;
    let dialog = node.incoming.recv().await.unwrap();
    dialog
        .accept(
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(SDP.into()),
        )
        .unwrap();
    let response = recv_response(&peer, 200).await;
    send(
        &peer,
        &node,
        &followup(&request, &response, Method::Ack, 1, None),
    )
    .await;
    for _ in 0..100 {
        if dialog.state().is_confirmed() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(dialog.state().is_confirmed());
    (node, dialog, peer, request, response)
}

#[tokio::test]
async fn session_timer_uas_negotiates_both_roles_and_peer_without_support() {
    for (headers, expected) in [
        (
            "Supported: timer\r\nSession-Expires: 180;refresher=uac\r\n",
            "90;refresher=uac",
        ),
        (
            "Supported: timer\r\nSession-Expires: 180;refresher=uas\r\n",
            "90;refresher=uas",
        ),
        (
            "Supported: timer\r\nSession-Expires: 180\r\nMin-SE: 120\r\n",
            "120;refresher=uas",
        ),
        ("Session-Expires: 90\r\n", "90;refresher=uas"),
        ("", "90;refresher=uas"),
    ] {
        let (node, dialog, _, _, response) = uas(headers).await;
        assert_eq!(response.session_expires_header().unwrap().value(), expected);
        assert_eq!(
            response.header_contains_token("Require", "timer"),
            headers.contains("Supported")
        );
        node.layer.remove_dialog(&dialog.id());
        finished(&dialog).await;
        node.clean();
    }
}

#[tokio::test]
async fn session_timer_uas_rejects_small_and_malformed_intervals() {
    for (headers, code) in [
        ("Supported: timer\r\nSession-Expires: 60\r\n", 422),
        (
            "Supported: timer\r\nSession-Expires: 90;refresher=bad\r\n",
            400,
        ),
        (
            "Supported: timer\r\nSession-Expires: 90\r\nSession-Expires: 120\r\n",
            400,
        ),
        ("Supported: timer\r\nSession-Expires: 4294967296\r\n", 400),
        (
            "Supported: timer\r\nSession-Expires: 90;refresher=uac;refresher=uas\r\n",
            400,
        ),
        (
            "Supported: timer\r\nSession-Expires: 90\r\nMin-SE: 1\r\n",
            400,
        ),
    ] {
        let node = Node::new(Some(config())).await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send(&peer, &node, &incoming(&node, &peer, headers)).await;
        let response = recv_response(&peer, code).await;
        if code == 422 {
            assert!(response
                .headers
                .iter()
                .any(|h| matches!(h, Header::MinSE(s) if s.value()=="90")));
        }
        node.clean();
    }
}

#[tokio::test]
async fn session_timer_disabled_does_not_advertise_and_rejects_require() {
    let node = Node::new(None).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let outbound = node.invite(&peer);
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    assert!(request.session_expires_header().is_none());
    assert!(!request.header_contains_token("Supported", "timer"));
    answer(&peer, addr, &request, 486, None, false).await;
    outbound.await.unwrap().unwrap();
    send(
        &peer,
        &node,
        &incoming(&node, &peer, "Require: timer\r\nSession-Expires: 90\r\n"),
    )
    .await;
    let response = recv_response(&peer, 420).await;
    assert_eq!(
        response.header_value("Unsupported").as_deref(),
        Some("timer")
    );
    node.clean();
}

#[tokio::test]
async fn session_timer_uas_update_refresh_and_bye_stop_worker() {
    let (node, dialog, peer, initial, response) =
        uas("Supported: timer\r\nSession-Expires: 90;refresher=uac\r\nAllow: UPDATE\r\n").await;
    advance(50).await;
    let request = followup(
        &initial,
        &response,
        Method::Update,
        2,
        Some("90;refresher=uac"),
    );
    send(&peer, &node, &request).await;
    let updated = recv_response(&peer, 200).await;
    assert_eq!(
        updated.cseq_header().unwrap().method().unwrap(),
        Method::Update
    );
    assert_eq!(
        updated.session_expires_header().unwrap().value(),
        "90;refresher=uac"
    );
    assert!(
        dialog.session_timer_status().unwrap().remaining > Duration::from_secs(89),
        "{:?}",
        dialog.session_timer_status()
    );
    advance(20).await;
    assert!(dialog.state().is_confirmed());
    send(
        &peer,
        &node,
        &followup(&initial, &response, Method::Bye, 3, None),
    )
    .await;
    recv_response(&peer, 200).await;
    finished(&dialog).await;
    advance(100).await;
    assert!(dialog.state().is_terminated());
    assert_eq!(dialog.session_timer_status().unwrap().refreshes, 0);
    node.clean();
}

#[tokio::test]
async fn session_timer_uas_can_refresh_as_uac_using_update() {
    let (node, dialog, peer, _, _) =
        uas("Supported: timer\r\nSession-Expires: 90;refresher=uas\r\nAllow: UPDATE\r\n").await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Update).await;
    // uac/uas refers to THIS request's transaction, not the original INVITE.
    assert_eq!(
        request.session_expires_header().unwrap().value(),
        "90;refresher=uac"
    );
    answer(&peer, addr, &request, 200, Some("90;refresher=uac"), true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(dialog.session_timer_status().unwrap().local_refresher);
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_explicit_reinvite_even_when_peer_supports_update() {
    let (node, dialog, peer, _, _) = established(
        "90;refresher=uac",
        true,
        SessionTimerConfig {
            refresh_method: RefreshMethod::Reinvite,
            ..config()
        },
    )
    .await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    answer(&peer, addr, &request, 200, Some("90;refresher=uac"), true).await;
    recv_request(&peer, Method::Ack).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[test]
fn session_timer_config_respects_rfc_minimum() {
    assert!(SessionTimerConfig::default().validate().is_ok());
    assert!(SessionTimerConfig {
        min_se: 89,
        ..Default::default()
    }
    .validate()
    .is_err());
    assert!(SessionTimerConfig {
        min_se: 120,
        expires: 90,
        ..Default::default()
    }
    .validate()
    .is_err());
}

async fn challenge(peer: &UdpSocket, addr: SocketAddr, request: &Request, min: &str) {
    let mut r = Response::try_from(
        response(
            request,
            422,
            "Session Interval Too Small",
            &format!("sip:peer@{}", peer.local_addr().unwrap()),
        )
        .as_str(),
    )
    .unwrap();
    r.headers.push(Header::MinSE(min.into()));
    peer.send_to(r.to_string().as_bytes(), addr).await.unwrap();
}

#[tokio::test]
async fn session_timer_update_422_retry_preserves_expiration_until_200() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    let (first, addr) = recv_request(&peer, Method::Update).await;
    challenge(&peer, addr, &first, "120").await;
    let (retry, addr) = recv_request(&peer, Method::Update).await;
    assert_eq!(
        retry.session_expires_header().unwrap().value(),
        "120;refresher=uac"
    );
    assert_eq!(
        retry.cseq_header().unwrap().seq().unwrap(),
        first.cseq_header().unwrap().seq().unwrap() + 1
    );
    assert!(dialog.session_timer_status().unwrap().remaining < Duration::from_secs(46));
    answer(&peer, addr, &retry, 200, Some("120;refresher=uac"), true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(dialog.session_timer_status().unwrap().interval, Some(120));
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_422_retries_are_bounded() {
    let node = Node::new(Some(config())).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let future = node.invite(&peer);
    for min in [120, 180, 240, 300] {
        let (request, addr) = recv_request(&peer, Method::Invite).await;
        challenge(&peer, addr, &request, &min.to_string()).await;
        recv_request(&peer, Method::Ack).await;
    }
    let (dialog, response) = future.await.unwrap().unwrap();
    assert_eq!(response.unwrap().status_code.code(), 422);
    assert!(dialog.state().is_terminated());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_invalid_initial_agreement_is_acked_before_bye() {
    for value in ["60;refresher=uac", "90", "90;refresher=invalid"] {
        let node = Node::new(Some(config())).await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let future = node.invite(&peer);
        let (request, addr) = recv_request(&peer, Method::Invite).await;
        answer(&peer, addr, &request, 200, Some(value), true).await;
        recv_request(&peer, Method::Ack).await;
        let (bye, addr) = recv_request(&peer, Method::Bye).await;
        answer(&peer, addr, &bye, 200, None, false).await;
        assert!(future.await.unwrap().is_err());
        node.clean();
    }
}

#[tokio::test]
async fn session_timer_reinvite_invalid_agreement_still_sends_ack() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", false, config()).await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    answer(&peer, addr, &request, 200, Some("60;refresher=uac"), false).await;
    recv_request(&peer, Method::Ack).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    assert!(dialog.state().is_terminated());
    node.clean();
}

#[tokio::test]
async fn session_timer_lost_update_response_cannot_extend_session() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    recv_request(&peer, Method::Update).await;
    advance(46).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    assert_eq!(dialog.session_timer_status().unwrap().expirations, 1);
    node.clean();
}

#[tokio::test]
async fn session_timer_glare_retry_keeps_original_deadline() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    let (first, addr) = recv_request(&peer, Method::Update).await;
    answer(&peer, addr, &first, 491, None, false).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    advance(5).await;
    let (retry, addr) = recv_request(&peer, Method::Update).await;
    assert!(
        retry.cseq_header().unwrap().seq().unwrap() > first.cseq_header().unwrap().seq().unwrap()
    );
    assert!(dialog.session_timer_status().unwrap().remaining < Duration::from_secs(41));
    answer(&peer, addr, &retry, 200, Some("90;refresher=uac"), true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_termination_cancels_pending_refresh() {
    let (node, dialog, peer, _, _) = established("90;refresher=uac", true, config()).await;
    advance(45).await;
    recv_request(&peer, Method::Update).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    let count = dialog.session_timer_status().unwrap().refreshes;
    advance(180).await;
    assert_eq!(dialog.session_timer_status().unwrap().refreshes, count);
    assert_eq!(dialog.session_timer_status().unwrap().expirations, 0);
    node.clean();
}

#[tokio::test]
async fn session_timer_preserves_initial_option_tags_on_refresh() {
    let node = Node::new(Some(config())).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (dialog, task) = node
        .layer
        .do_invite_async(
            InviteOption {
                caller: node.uri.clone(),
                contact: node.uri.clone(),
                callee: format!("sip:peer@{}", peer.local_addr().unwrap())
                    .parse()
                    .unwrap(),
                offer: Some(SDP.into()),
                headers: Some(vec![
                    Header::Require("timer".into()),
                    Header::Supported("example".into()),
                    Header::ProxyRequire("example".into()),
                ]),
                ..Default::default()
            },
            node.sender.clone(),
        )
        .unwrap();
    let (initial, addr) = recv_request(&peer, Method::Invite).await;
    answer(&peer, addr, &initial, 200, Some("90;refresher=uac"), true).await;
    recv_request(&peer, Method::Ack).await;
    task.await.unwrap().unwrap();
    advance(45).await;
    let (refresh, addr) = recv_request(&peer, Method::Update).await;
    for header in ["Supported", "Require", "Proxy-Require"] {
        assert_eq!(refresh.header_value(header), initial.header_value(header));
    }
    answer(&peer, addr, &refresh, 200, Some("90;refresher=uac"), true).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
}

#[tokio::test]
async fn session_timer_provider_rejection_after_200_ends_session() {
    struct Media;
    #[async_trait::async_trait]
    impl crate::dialog::session_timer::RefreshSdp for Media {
        async fn offer(&self) -> crate::Result<crate::dialog::reinvite::AckBody> {
            Ok(crate::dialog::reinvite::AckBody::sdp(SDP))
        }
        async fn answer(&self, _: &Response) -> crate::Result<()> {
            Err(crate::Error::Error("unusable media answer".into()))
        }
    }
    let (node, dialog, peer, _, _) = established(
        "90;refresher=uac",
        false,
        SessionTimerConfig {
            sdp: Some(Arc::new(Media)),
            ..config()
        },
    )
    .await;
    advance(45).await;
    let (request, addr) = recv_request(&peer, Method::Invite).await;
    answer(&peer, addr, &request, 200, Some("90;refresher=uac"), false).await;
    recv_request(&peer, Method::Ack).await;
    let (bye, addr) = recv_request(&peer, Method::Bye).await;
    answer(&peer, addr, &bye, 200, None, false).await;
    finished(&dialog).await;
    assert!(dialog.state().is_terminated());
    node.clean();
}

#[tokio::test]
async fn session_timer_incoming_refresh_updates_pending_watchdog() {
    let (node, dialog, peer, initial, response) =
        uas("Supported: timer\r\nSession-Expires: 90;refresher=uas\r\nAllow: UPDATE\r\n").await;
    advance(45).await;
    let (pending, addr) = recv_request(&peer, Method::Update).await;
    advance(10).await;
    send(
        &peer,
        &node,
        &followup(
            &initial,
            &response,
            Method::Update,
            2,
            Some("90;refresher=uac"),
        ),
    )
    .await;
    recv_response(&peer, 200).await;
    advance(36).await; // Beyond the old deadline, before the renewed one.
    assert!(dialog.state().is_confirmed());
    assert!(!dialog.session_timer_status().unwrap().local_refresher);
    answer(&peer, addr, &pending, 200, Some("90;refresher=uas"), true).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    node.layer.remove_dialog(&dialog.id());
    finished(&dialog).await;
    node.clean();
}

#[tokio::test]
async fn session_timer_endpoint_shutdown_stops_worker_with_live_dialog_handle() {
    let (node, dialog, _, _, _) = established("90;refresher=uac", true, config()).await;
    node.token.cancel();
    finished(&dialog).await;
    assert_eq!(dialog.session_timer_status().unwrap().refreshes, 0);
}
