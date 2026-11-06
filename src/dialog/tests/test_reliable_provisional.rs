use super::test_dialog_states::create_invite_request;
use crate::dialog::{
    dialog::{DialogState, TransactionHandle},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
    reliable::{
        IncomingPrack, PrackBody, PrackHandler, ReliableProvisionalConfig, ReliableResponse,
        SdpKind,
    },
};
use crate::sip::{Header, HeadersExt, Method, Request, Response, SipMessage, StatusCode};
use crate::transaction::{
    endpoint::{Endpoint, EndpointOption},
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use crate::{EndpointBuilder, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::time::{timeout, Duration};

const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
const ANSWER: &str = "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4002 RTP/AVP 0\r\n";

#[derive(Default)]
struct Media {
    events: parking_lot::Mutex<Vec<SdpKind>>,
    results: parking_lot::Mutex<Vec<Option<Response>>>,
    errors: parking_lot::Mutex<Vec<String>>,
    new_offer: bool,
}
#[async_trait]
impl PrackHandler for Media {
    async fn on_reliable_response(&self, event: ReliableResponse) -> Result<Option<PrackBody>> {
        self.events.lock().push(event.sdp_kind);
        Ok(match event.sdp_kind {
            SdpKind::Offer => Some(PrackBody::sdp(ANSWER)),
            SdpKind::Answer if self.new_offer => Some(PrackBody::sdp(OFFER)),
            _ => None,
        })
    }
    async fn on_prack(&self, event: IncomingPrack) -> Result<Option<PrackBody>> {
        self.events.lock().push(event.sdp_kind);
        Ok((event.sdp_kind == SdpKind::Offer).then(|| PrackBody::sdp(ANSWER)))
    }
    async fn on_prack_result(&self, _: Request, response: Option<Response>) {
        self.results.lock().push(response);
    }
    async fn on_error(&self, _: crate::dialog::DialogId, error: String) {
        self.errors.lock().push(error);
    }
}

struct Server {
    endpoint: Endpoint,
    layer: DialogLayer,
    dialog: InviteDialog,
    tx: Transaction,
    outgoing: UnboundedReceiver<TransportEvent>,
    conn: SipConnection,
    media: Arc<Media>,
    events: UnboundedReceiver<DialogState>,
}
impl Server {
    async fn new(offer: bool) -> Result<Self> {
        Self::with_peer(offer, Some(Header::Require("100rel".into()))).await
    }
    async fn with_peer(offer: bool, option: Option<Header>) -> Result<Self> {
        let endpoint = EndpointBuilder::new()
            .with_option(EndpointOption {
                t1: Duration::from_millis(20),
                t2: Duration::from_millis(40),
                t1x64: Duration::from_millis(1280),
                ..Default::default()
            })
            .build();
        let (out, outgoing) = unbounded_channel();
        let addr: SipAddr = "127.0.0.1:5060".parse::<std::net::SocketAddr>()?.into();
        let conn: SipConnection =
            ChannelConnection::create_connection(unbounded_channel().1, out, addr, None)
                .await?
                .into();
        endpoint.inner.transport_layer.add_transport(conn.clone());
        let mut request = create_invite_request("alice", "", "reliable-full");
        request
            .headers
            .unique_push(Header::To("<sip:b@example.com>".into()));
        if let Some(option) = option {
            request.headers.push(option);
        }
        request.body.clear();
        if offer {
            request.body = OFFER.as_bytes().to_vec();
            request
                .headers
                .unique_push(Header::ContentType("application/sdp".into()));
        }
        request
            .headers
            .unique_push(Header::ContentLength((request.body.len() as u32).into()));
        let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
        let tx = Transaction::new_server(key, request, endpoint.inner.clone(), Some(conn.clone()));
        let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        let media = Arc::new(Media::default());
        layer.set_reliable_provisional(Some(ReliableProvisionalConfig::new(media.clone())));
        let (states, events) = unbounded_channel();
        let dialog = layer.get_or_create_server_invite(
            &tx,
            states,
            None,
            Some("sip:b@127.0.0.1:5060".try_into()?),
        )?;
        Ok(Self {
            endpoint,
            layer: Arc::try_unwrap(layer).ok().unwrap(),
            dialog,
            tx,
            outgoing,
            conn,
            media,
            events,
        })
    }
    fn response(&self, status: StatusCode, body: Option<&str>) -> Response {
        self.dialog.inner.make_response(
            &self.tx.original,
            status,
            body.map(|_| vec![Header::ContentType("application/sdp".into())]),
            body.map(|s| s.as_bytes().to_vec()),
        )
    }
    async fn send(&mut self, status: StatusCode, body: Option<&str>) -> Result<()> {
        self.tx.respond(self.response(status, body)).await
    }
    fn wire(&mut self) -> Response {
        match self.outgoing.try_recv().expect("response on wire") {
            TransportEvent::Incoming(SipMessage::Response(r), _, _) => r,
            _ => panic!("not a response"),
        }
    }
    fn prack(&self, response: &Response, body: Option<&str>) -> Result<Transaction> {
        let mut request = self.tx.original.clone();
        request.method = Method::PRack;
        request.headers.unique_push(Header::CSeq("2 PRACK".into()));
        request.headers.unique_push(Header::Via(
            format!(
                "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{}",
                crate::transaction::make_uuid_v4()
            )
            .into(),
        ));
        request
            .headers
            .unique_push(Header::To(response.to_header()?.clone()));
        request.headers.unique_push(Header::RAck(
            format!(
                "{} {} INVITE",
                response.rseq_value().unwrap(),
                self.tx.original.cseq_header()?.seq()?
            )
            .into(),
        ));
        request.body = body.unwrap_or("").as_bytes().to_vec();
        request
            .headers
            .retain(|h| !matches!(h, Header::Require(_) | Header::ContentType(_)));
        if body.is_some() {
            request
                .headers
                .push(Header::ContentType("application/sdp".into()));
        }
        request
            .headers
            .unique_push(Header::ContentLength((request.body.len() as u32).into()));
        let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
        Ok(Transaction::new_server(
            key,
            request,
            self.endpoint.inner.clone(),
            Some(self.conn.clone()),
        ))
    }
    async fn ack(&mut self, response: &Response, body: Option<&str>) -> Result<Response> {
        let mut tx = self.prack(response, body)?;
        self.dialog.inner.receive_prack(&mut tx).await?;
        Ok(self.wire())
    }
    async fn pump(&mut self) {
        let event = self
            .tx
            .tu_receiver
            .try_recv()
            .expect("queued transaction event");
        self.tx.dispatch_event(event).await;
    }
}

#[tokio::test]
async fn reliable_uas_waits_for_sdp_prack_before_final_200() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    assert!(first.header_contains_token("Require", "100rel"));
    assert!((1..=i32::MAX as u32).contains(&first.rseq_value().unwrap()));
    s.send(StatusCode::OK, None).await?;
    assert!(s.outgoing.try_recv().is_err());
    assert!(matches!(
        *s.dialog.inner.state.lock(),
        DialogState::Early(..)
    ));
    assert_eq!(s.ack(&first, None).await?.status_code, StatusCode::OK);
    s.pump().await;
    assert_eq!(s.wire().status_code, StatusCode::OK);
    assert!(s.dialog.inner.waiting_ack());
    Ok(())
}

#[tokio::test]
async fn reliable_uas_offerless_invite_gets_answer_in_prack() -> Result<()> {
    let mut s = Server::new(false).await?;
    s.send(StatusCode::SessionProgress, Some(OFFER)).await?;
    let first = s.wire();
    assert_eq!(
        s.ack(&first, None).await?.status_code,
        StatusCode::BadRequest
    );
    assert_eq!(
        s.ack(&first, Some(ANSWER)).await?.status_code,
        StatusCode::OK
    );
    assert_eq!(*s.media.events.lock(), vec![SdpKind::Answer]);
    Ok(())
}

#[tokio::test]
async fn reliable_uas_answers_new_offer_in_prack_200() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    let response = s.ack(&first, Some(OFFER)).await?;
    assert_eq!(response.status_code, StatusCode::OK);
    assert_eq!(response.body, ANSWER.as_bytes());
    assert_eq!(*s.media.events.lock(), vec![SdpKind::Offer]);
    Ok(())
}

#[tokio::test]
async fn reliable_uas_serializes_provisional_responses_and_increments_rseq() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::Ringing, None).await?;
    let first = s.wire();
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    assert!(s.outgoing.try_recv().is_err());
    s.ack(&first, None).await?;
    s.pump().await;
    let second = s.wire();
    assert_eq!(second.rseq_value(), first.rseq_value().map(|n| n + 1));
    assert_eq!(second.body, ANSWER.as_bytes());
    Ok(())
}

#[tokio::test]
async fn reliable_uas_checks_dialog_and_entire_rack() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    for header in [
        Header::RAck(format!("{} 99 INVITE", first.rseq_value().unwrap()).into()),
        Header::RAck(format!("{} 1 UPDATE", first.rseq_value().unwrap()).into()),
        Header::From("<sip:a@example.com>;tag=wrong".into()),
        Header::To("<sip:b@example.com>;tag=wrong".into()),
        Header::CallId("wrong".into()),
    ] {
        let mut tx = s.prack(&first, None)?;
        tx.original.headers.unique_push(header);
        s.dialog.inner.receive_prack(&mut tx).await?;
        assert_eq!(
            s.wire().status_code,
            StatusCode::CallTransactionDoesNotExist
        );
    }
    assert_eq!(s.ack(&first, None).await?.status_code, StatusCode::OK);
    assert_eq!(
        s.ack(&first, None).await?.status_code,
        StatusCode::CallTransactionDoesNotExist
    );
    Ok(())
}

#[tokio::test]
async fn reliable_uas_cancel_discards_deferred_200_but_accepts_late_prack() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    s.send(StatusCode::OK, None).await?;
    s.send(StatusCode::RequestTerminated, None).await?;
    assert_eq!(s.wire().status_code, StatusCode::RequestTerminated);
    s.layer.remove_dialog(&s.dialog.id());
    let mut prack = s.prack(&first, None)?;
    let mut retired = s
        .layer
        .match_dialog(&prack)
        .expect("late PRACK route retained");
    retired.handle(&mut prack).await?;
    assert_eq!(s.wire().status_code, StatusCode::OK);
    assert!(s.tx.tu_receiver.try_recv().is_err());
    assert!(s.dialog.inner.is_terminated());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reliable_uas_retransmits_without_t2_cap_and_times_out_at_64_t1() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    s.send(StatusCode::OK, None).await?;
    tokio::task::yield_now().await;
    for delay in [20, 40, 80, 160, 320, 640] {
        tokio::time::advance(Duration::from_millis(delay - 1)).await;
        tokio::task::yield_now().await;
        assert!(s.tx.tu_receiver.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        s.pump().await;
        assert_eq!(s.wire(), first);
    }
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    s.pump().await;
    assert_eq!(s.wire().status_code, StatusCode::ServerTimeOut);
    assert_eq!(s.media.errors.lock().len(), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reliable_uas_prack_stops_already_queued_retransmission() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    s.ack(&first, None).await?;
    s.pump().await;
    assert!(s.outgoing.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(s.tx.tu_receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn reliable_reinvite_command_loop_drives_queued_final() -> Result<()> {
    let mut s = Server::new(true).await?;
    *s.dialog.inner.state.lock() = DialogState::Confirmed(s.dialog.id(), Response::default());
    let mut reinvite = s.tx.original.clone();
    reinvite
        .to_header_mut()?
        .mut_tag(s.dialog.id().local_tag.into())?;
    reinvite
        .headers
        .unique_push(Header::CSeq("3 INVITE".into()));
    reinvite.headers.unique_push(Header::Via(
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reinvite".into(),
    ));
    let key = TransactionKey::from_request(&reinvite, TransactionRole::Server)?;
    s.tx = Transaction::new_server(
        key,
        reinvite,
        s.endpoint.inner.clone(),
        Some(s.conn.clone()),
    );
    s.dialog.inner.attach_reliable_server(&s.tx)?;
    let (handle, rx) = TransactionHandle::new();
    handle
        .respond(
            StatusCode::SessionProgress,
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(ANSWER.as_bytes().to_vec()),
        )
        .await
        .unwrap();
    handle.respond(StatusCode::OK, None, None).await.unwrap();
    let inner = s.dialog.inner.clone();
    let task = tokio::spawn(async move {
        inner
            .process_transaction_handle(&mut s.tx, rx)
            .await
            .map(|_| s.tx)
    });
    let TransportEvent::Incoming(SipMessage::Response(first), _, _) =
        timeout(Duration::from_secs(1), s.outgoing.recv())
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("no provisional");
    };
    assert!(!task.is_finished());
    let mut request = create_invite_request("alice", "", "reliable-full");
    request.body.clear();
    request.method = Method::PRack;
    request
        .headers
        .unique_push(Header::To(first.to_header()?.clone()));
    request.headers.unique_push(Header::CSeq("2 PRACK".into()));
    request.headers.push(Header::RAck(
        format!("{} 3 INVITE", first.rseq_value().unwrap()).into(),
    ));
    let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
    let mut prack = Transaction::new_server(key, request, s.endpoint.inner.clone(), Some(s.conn));
    s.dialog.inner.receive_prack(&mut prack).await?;
    let tx = timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()?;
    assert_eq!(
        tx.last_response.as_ref().unwrap().status_code,
        StatusCode::OK
    );
    assert!(s.dialog.inner.is_confirmed());
    Ok(())
}

struct Client {
    token: tokio_util::sync::CancellationToken,
    peer: tokio::net::UdpSocket,
    invite: Request,
    uac: std::net::SocketAddr,
    call: tokio::task::JoinHandle<Result<(crate::dialog::DialogId, Option<Response>)>>,
    media: Arc<Media>,
    dialog: InviteDialog,
    states: UnboundedReceiver<DialogState>,
}
async fn receive_request(peer: &tokio::net::UdpSocket, method: Method) -> Request {
    let mut bytes = vec![0; 8192];
    timeout(Duration::from_secs(2), async {
        loop {
            let (len, _) = peer.recv_from(&mut bytes).await.unwrap();
            if let SipMessage::Request(req) =
                SipMessage::try_from(std::str::from_utf8(&bytes[..len]).unwrap()).unwrap()
            {
                if req.method == method {
                    return req;
                }
            }
        }
    })
    .await
    .expect("SIP request")
}
fn reply(
    request: &Request,
    status: StatusCode,
    tag: &str,
    contact: std::net::SocketAddr,
    rseq: Option<u32>,
    body: Option<&str>,
) -> Response {
    let mut to = request.to_header().unwrap().clone();
    to.mut_tag(tag.into()).unwrap();
    let mut headers = vec![
        Header::Via(request.via_header().unwrap().clone()),
        Header::From(request.from_header().unwrap().clone()),
        Header::To(to),
        Header::CallId(request.call_id_header().unwrap().clone()),
        Header::CSeq(request.cseq_header().unwrap().clone()),
        Header::Contact(format!("<sip:peer@{contact}>").into()),
        Header::ContentLength((body.unwrap_or("").len() as u32).into()),
    ];
    if let Some(rseq) = rseq {
        headers.push(Header::RSeq(rseq.to_string().into()));
        headers.push(Header::Require("100rel".into()));
    }
    if body.is_some() {
        headers.push(Header::ContentType("application/sdp".into()));
    }
    Response {
        status_code: status,
        wire_reason: None,
        headers: headers.into(),
        body: body.unwrap_or("").as_bytes().to_vec(),
        version: crate::sip::Version::V2,
    }
}
impl Client {
    async fn new(offer: bool, new_offer: bool, require: bool) -> Result<Self> {
        use crate::dialog::invitation::InviteOption;
        use crate::transport::{udp::UdpConnection, TransportLayer};
        let token = tokio_util::sync::CancellationToken::new();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let transport = TransportLayer::new(token.child_token());
        let udp = UdpConnection::create_connection(
            "127.0.0.1:0".parse().unwrap(),
            None,
            Some(token.child_token()),
        )
        .await?;
        let uac = udp.get_addr().addr.to_string().parse().unwrap();
        transport.add_transport(udp.into());
        let endpoint = EndpointBuilder::new()
            .with_transport_layer(transport)
            .with_cancel_token(token.child_token())
            .with_option(EndpointOption {
                t1: Duration::from_millis(40),
                t1x64: Duration::from_millis(2560),
                ..Default::default()
            })
            .build();
        let serve = endpoint.inner.clone();
        tokio::spawn(async move { serve.serve().await });
        let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        let media = Arc::new(Media {
            new_offer,
            ..Default::default()
        });
        layer.set_reliable_provisional(Some(ReliableProvisionalConfig {
            handler: media.clone(),
            require,
        }));
        let opt = InviteOption {
            caller: "sip:alice@example.com".try_into()?,
            callee: format!("sip:b@{}", peer.local_addr()?)
                .as_str()
                .try_into()?,
            contact: format!("sip:a@{uac}").as_str().try_into()?,
            offer: offer.then(|| OFFER.as_bytes().to_vec()),
            ..Default::default()
        };
        let (sender, states) = unbounded_channel();
        let (dialog, call) = layer.do_invite_async(opt, sender)?;
        let invite = receive_request(&peer, Method::Invite).await;
        Ok(Self {
            token,
            peer,
            invite,
            uac,
            call,
            media,
            dialog,
            states,
        })
    }
    async fn send(&self, response: Response) {
        self.peer
            .send_to(response.to_string().as_bytes(), self.uac)
            .await
            .unwrap();
    }
    fn progress(&self, tag: &str, rseq: u32, body: Option<&str>) -> Response {
        reply(
            &self.invite,
            StatusCode::SessionProgress,
            tag,
            self.peer.local_addr().unwrap(),
            Some(rseq),
            body,
        )
    }
    async fn acknowledge(&self, prack: &Request, body: Option<&str>) {
        self.send(reply(
            prack,
            StatusCode::OK,
            prack.to_header().unwrap().tag().unwrap().unwrap().value(),
            self.peer.local_addr().unwrap(),
            None,
            body,
        ))
        .await;
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.call.abort();
        self.token.cancel();
    }
}

#[tokio::test]
async fn reliable_uac_offerless_invite_answers_in_prack_and_handles_required_mode() -> Result<()> {
    let mut c = Client::new(false, false, true).await?;
    assert!(c.invite.header_contains_token("Supported", "100rel"));
    assert!(c.invite.header_contains_token("Require", "100rel"));
    c.send(c.progress("bob", 1, Some(OFFER))).await;
    let prack = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(prack.body, ANSWER.as_bytes());
    assert_eq!(
        crate::dialog::dialog::Dialog::Invite(c.dialog.clone()).remote_contact(),
        Some(prack.uri.clone())
    );
    assert_eq!(
        prack.rack_value(),
        Some((1, c.invite.cseq_header()?.seq()?, Method::Invite))
    );
    assert_eq!(*c.media.events.lock(), vec![SdpKind::Offer]);
    assert!(matches!(
        *c.dialog.inner.state.lock(),
        DialogState::Early(_, _)
    ));
    assert!(std::iter::from_fn(|| c.states.try_recv().ok())
        .any(|s| matches!(s, DialogState::Early(_, _))));
    c.acknowledge(&prack, None).await;
    Ok(())
}

#[tokio::test]
async fn reliable_reinvite_prack_preserves_or_refreshes_target_from_contact() -> Result<()> {
    reinvite_prack_target(false).await
}
#[tokio::test]
async fn controlled_reinvite_prack_preserves_or_refreshes_target_from_contact() -> Result<()> {
    reinvite_prack_target(true).await
}
async fn reinvite_prack_target(controlled: bool) -> Result<()> {
    let mut c = Client::new(true, false, false).await?;
    c.send(reply(
        &c.invite,
        StatusCode::OK,
        "bob",
        c.peer.local_addr()?,
        None,
        Some(ANSWER),
    ))
    .await;
    let (_, _) = timeout(Duration::from_secs(1), &mut c.call)
        .await
        .unwrap()
        .unwrap()?;
    let dialog = c.dialog.clone();
    let target = dialog.inner.remote_uri.lock().clone();
    let sender = dialog.clone();
    let reinvite_task = tokio::spawn(async move {
        let headers = Some(vec![Header::ContentType("application/sdp".into())]);
        let body = Some(OFFER.as_bytes().to_vec());
        if controlled {
            let request = sender.prepare_reinvite(headers, body)?;
            sender.send_reinvite(request, Default::default()).await
        } else {
            sender.reinvite(headers, body).await
        }
    });
    let reinvite = receive_request(&c.peer, Method::Invite).await;
    assert!(reinvite.header_contains_token("Supported", "100rel"));
    let mut progress = reply(
        &reinvite,
        StatusCode::SessionProgress,
        "bob",
        c.peer.local_addr()?,
        Some(1),
        Some(ANSWER),
    );
    progress
        .headers
        .retain(|h| !matches!(h, Header::Contact(_)));
    c.send(progress.clone()).await;
    let first = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(first.uri, target);
    c.acknowledge(&first, None).await;
    progress.headers.unique_push(Header::RSeq("2".into()));
    let refreshed_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let refreshed_target = format!("sip:refreshed@{}", refreshed_peer.local_addr()?);
    progress
        .headers
        .push(Header::Contact(format!("<{refreshed_target}>").into()));
    c.send(progress).await;
    let second = receive_request(&refreshed_peer, Method::PRack).await;
    assert_eq!(second.uri.to_string(), refreshed_target);
    assert_eq!(dialog.inner.remote_uri.lock().to_string(), refreshed_target);
    let ok = reply(
        &second,
        StatusCode::OK,
        "bob",
        refreshed_peer.local_addr()?,
        None,
        None,
    );
    refreshed_peer
        .send_to(ok.to_string().as_bytes(), c.uac)
        .await?;
    c.send(reply(
        &reinvite,
        StatusCode::OK,
        "bob",
        c.peer.local_addr()?,
        None,
        Some(ANSWER),
    ))
    .await;
    assert_eq!(
        timeout(Duration::from_secs(1), reinvite_task)
            .await
            .unwrap()
            .unwrap()?
            .unwrap()
            .status_code,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn reliable_uac_new_offer_in_prack_delivers_the_answer() -> Result<()> {
    let c = Client::new(true, true, false).await?;
    c.send(c.progress("bob", 10, Some(ANSWER))).await;
    let prack = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(prack.body, OFFER.as_bytes());
    c.acknowledge(&prack, Some(ANSWER)).await;
    timeout(Duration::from_secs(1), async {
        while c.media.results.lock().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        c.media.results.lock()[0].as_ref().unwrap().body,
        ANSWER.as_bytes()
    );
    Ok(())
}

#[tokio::test]
async fn reliable_uac_invite_final_does_not_wait_for_prack_transaction() -> Result<()> {
    let mut c = Client::new(true, false, false).await?;
    c.send(c.progress("bob", 1, Some(ANSWER))).await;
    let prack = receive_request(&c.peer, Method::PRack).await;
    c.send(reply(
        &c.invite,
        StatusCode::OK,
        "bob",
        c.peer.local_addr()?,
        None,
        Some(ANSWER),
    ))
    .await;
    let (_, response) = timeout(Duration::from_millis(500), &mut c.call)
        .await
        .expect("INVITE must not wait for PRACK's 200")
        .unwrap()?;
    assert_eq!(response.unwrap().status_code, StatusCode::OK);
    c.acknowledge(&prack, None).await;
    Ok(())
}

#[tokio::test]
async fn reliable_uac_prack_retransmission_is_owned_by_its_transaction() -> Result<()> {
    let c = Client::new(true, false, false).await?;
    let progress = c.progress("bob", 1, Some(ANSWER));
    c.send(progress.clone()).await;
    let first = receive_request(&c.peer, Method::PRack).await;
    c.send(progress).await; // retransmitted 183 must not create another transaction
    let repeated = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(first, repeated);
    assert_eq!(c.media.events.lock().len(), 1);
    c.acknowledge(&first, None).await;
    Ok(())
}

#[tokio::test]
async fn reliable_uac_forks_have_independent_rseq_and_contact() -> Result<()> {
    let c = Client::new(true, false, false).await?;
    let other = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    c.send(c.progress("bob", 9, Some(ANSWER))).await;
    let bob = receive_request(&c.peer, Method::PRack).await;
    c.acknowledge(&bob, None).await;
    c.send(reply(
        &c.invite,
        StatusCode::SessionProgress,
        "carol",
        other.local_addr()?,
        Some(9),
        Some(ANSWER),
    ))
    .await;
    let carol = receive_request(&other, Method::PRack).await;
    assert_eq!(carol.to_header()?.tag()?.unwrap().value(), "carol");
    assert_eq!(
        carol.uri.to_string(),
        format!("sip:peer@{}", other.local_addr()?)
    );
    assert_ne!(bob.via_header()?, carol.via_header()?);
    c.acknowledge(&carol, None).await;
    assert_eq!(c.media.events.lock().len(), 2);
    Ok(())
}

#[tokio::test]
async fn reliable_uac_strict_route_rewrites_uri_and_preserves_target() -> Result<()> {
    let c = Client::new(true, false, false).await?;
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let mut response = c.progress("bob", 1, Some(ANSWER));
    response.headers.push(Header::RecordRoute(
        format!(
            "<sip:loose@127.0.0.1:5099;lr>, <sip:strict@{}>",
            proxy.local_addr()?
        )
        .into(),
    ));
    c.send(response).await;
    let prack = receive_request(&proxy, Method::PRack).await;
    assert_eq!(
        prack.uri.to_string(),
        format!("sip:strict@{}", proxy.local_addr()?)
    );
    let routes: Vec<_> = prack.route_headers().iter().map(|r| r.value()).collect();
    assert_eq!(
        routes,
        vec![
            "<sip:loose@127.0.0.1:5099;lr>".to_string(),
            format!("<sip:peer@{}>", c.peer.local_addr()?)
        ]
    );
    c.acknowledge(&prack, None).await;
    Ok(())
}

#[tokio::test]
async fn reliable_negotiation_supported_only_and_no_peer_support() -> Result<()> {
    let mut supported =
        Server::with_peer(true, Some(Header::Supported("timer, 100rel".into()))).await?;
    supported.send(StatusCode::Ringing, None).await?;
    assert!(supported.wire().rseq_value().is_some());
    let mut plain = Server::with_peer(true, None).await?;
    plain.dialog.ringing(None, None)?;
    plain.pump().await;
    let response = plain.wire();
    assert!(response.rseq_value().is_none());
    assert!(!response.header_contains_token("Require", "100rel"));
    plain.dialog.accept(None, None)?;
    plain.pump().await;
    assert_eq!(plain.wire().status_code, StatusCode::OK);
    assert!(plain.dialog.inner.waiting_ack());
    Ok(())
}

#[tokio::test]
async fn reliable_missing_offer_rejects_invite_instead_of_hanging() -> Result<()> {
    let mut s = Server::new(false).await?;
    assert!(s.send(StatusCode::Ringing, None).await.is_err());
    s.pump().await;
    assert_eq!(s.wire().status_code, StatusCode::ServerInternalError);
    assert!(s.dialog.inner.is_terminated());
    Ok(())
}

#[tokio::test]
async fn reliable_no_sdp_provisional_does_not_delay_final() -> Result<()> {
    let mut s = Server::new(true).await?;
    s.send(StatusCode::Ringing, None).await?;
    let provisional = s.wire();
    s.send(StatusCode::OK, Some(ANSWER)).await?;
    assert_eq!(s.wire().status_code, StatusCode::OK);
    assert_eq!(s.ack(&provisional, None).await?.status_code, StatusCode::OK);
    assert!(s.dialog.inner.waiting_ack());
    Ok(())
}

#[tokio::test]
async fn reliable_lost_prack_200_replays_transaction_response_without_media_callback() -> Result<()>
{
    let mut s = Server::new(true).await?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp = crate::transport::udp::UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        None,
    )
    .await?;
    let connection: SipConnection = udp.into();
    let mut request = s.prack(&first, None)?.original.clone();
    request.headers.unique_push(Header::Via(
        format!(
            "SIP/2.0/UDP {};branch=z9hG4bK-prack-cache",
            peer.local_addr()?
        )
        .into(),
    ));
    let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
    let mut prack = Transaction::new_server(
        key,
        request.clone(),
        s.endpoint.inner.clone(),
        Some(connection.clone()),
    );
    s.dialog.inner.receive_prack(&mut prack).await?;
    let mut bytes = [0; 8192];
    let (len, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut bytes))
        .await
        .unwrap()?;
    let response = bytes[..len].to_vec(); // Treat the first 200 as lost.
    drop(prack);
    let from: SipAddr = peer.local_addr()?.into();
    s.endpoint
        .inner
        .on_received_message(request.into(), connection, &from)
        .await?;
    let (len, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut bytes))
        .await
        .unwrap()?;
    assert_eq!(&bytes[..len], response.as_slice());
    assert_eq!(s.media.events.lock().len(), 1);
    Ok(())
}

#[tokio::test]
async fn reliable_incoming_reinvite_prack_on_locally_originated_dialog() -> Result<()> {
    for legacy in [false, true] {
        let mut s = Server::new(true).await?;
        let inner = Arc::new(crate::dialog::dialog::DialogInner::new(
            TransactionRole::Client,
            s.dialog.id(),
            s.tx.original.clone(),
            s.endpoint.inner.clone(),
            unbounded_channel().0,
            None,
            Some("sip:local@127.0.0.1:5060".try_into()?),
            s.tx.tu_sender.clone(),
        )?);
        *inner.reliable_config.lock() = Some(ReliableProvisionalConfig::new(s.media.clone()));
        inner.attach_reliable_server(&s.tx)?;
        s.dialog = InviteDialog::from_inner(inner.clone());
        s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
        let first = s.wire();
        // Re-INVITE is waiting on the application while its PRACK arrives.
        *inner.state.lock() = DialogState::Updated(
            s.dialog.id(),
            s.tx.original.clone(),
            TransactionHandle::new().0,
        );
        let mut prack = s.prack(&first, None)?;
        if legacy {
            crate::dialog::client_dialog::ClientInviteDialog::from_inner(inner)
                .handle(&mut prack)
                .await?;
        } else {
            s.dialog.handle(&mut prack).await?;
        }
        assert_eq!(s.wire().status_code, StatusCode::OK);
        assert_eq!(s.media.events.lock().len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn reliable_legacy_server_uses_the_same_engine() -> Result<()> {
    use crate::dialog::server_dialog::ServerInviteDialog;
    let mut s = Server::new(true).await?;
    let mut legacy = ServerInviteDialog::from_inner(s.dialog.inner.clone());
    legacy.ringing(
        Some(vec![Header::ContentType("application/sdp".into())]),
        Some(ANSWER.as_bytes().to_vec()),
    )?;
    legacy.accept(None, None)?;
    s.pump().await;
    let first = s.wire();
    s.pump().await;
    assert!(s.outgoing.try_recv().is_err());
    let mut prack = s.prack(&first, None)?;
    legacy.handle(&mut prack).await?;
    assert_eq!(s.wire().status_code, StatusCode::OK);
    s.pump().await;
    assert_eq!(s.wire().status_code, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn reliable_uac_discards_gaps_and_ignores_subsequent_sdp() -> Result<()> {
    let c = Client::new(true, false, false).await?;
    c.send(c.progress("bob", 1, Some(ANSWER))).await;
    let first = receive_request(&c.peer, Method::PRack).await;
    c.acknowledge(&first, None).await;
    c.send(c.progress("bob", 3, None)).await;
    c.send(c.progress("bob", 2, None)).await;
    let next = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(next.rack_value().unwrap().0, 2);
    c.acknowledge(&next, None).await;
    c.send(c.progress("bob", 3, Some(OFFER))).await; // not a new offer
    let last = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(last.rack_value().unwrap().0, 3);
    assert!(last.body.is_empty());
    c.acknowledge(&last, None).await;
    assert_eq!(
        *c.media.events.lock(),
        vec![SdpKind::Answer, SdpKind::None, SdpKind::Ignored]
    );
    Ok(())
}

#[tokio::test]
async fn reliable_bad_media_handler_fails_both_transactions_cleanly() -> Result<()> {
    struct Broken;
    #[async_trait]
    impl PrackHandler for Broken {
        async fn on_reliable_response(&self, _: ReliableResponse) -> Result<Option<PrackBody>> {
            Ok(None)
        }
        async fn on_prack(&self, _: IncomingPrack) -> Result<Option<PrackBody>> {
            Err(crate::Error::Error("media failure".into()))
        }
    }
    let mut s = Server::new(true).await?;
    s.dialog
        .set_reliable_provisional(Some(ReliableProvisionalConfig::new(Arc::new(Broken))));
    s.dialog.inner.reliable_servers.lock().clear();
    s.dialog.inner.attach_reliable_server(&s.tx)?;
    s.send(StatusCode::SessionProgress, Some(ANSWER)).await?;
    let first = s.wire();
    s.send(StatusCode::OK, None).await?;
    assert_eq!(
        s.ack(&first, Some(OFFER)).await?.status_code,
        StatusCode::ServerInternalError
    );
    s.pump().await;
    assert_eq!(s.wire().status_code, StatusCode::ServerInternalError);
    assert!(s.dialog.inner.is_terminated());
    Ok(())
}

async fn udp_endpoint(
    token: &tokio_util::sync::CancellationToken,
) -> Result<(Endpoint, std::net::SocketAddr)> {
    use crate::transport::{udp::UdpConnection, TransportLayer};
    let transport = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let addr = udp.get_addr().addr.to_string().parse().unwrap();
    transport.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_transport_layer(transport)
        .with_cancel_token(token.child_token())
        .build();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { inner.serve().await });
    Ok((endpoint, addr))
}

#[tokio::test]
async fn reliable_udp_stack_to_stack_all_three_sdp_patterns_and_bye() -> Result<()> {
    use crate::dialog::invitation::InviteOption;
    for (invite_offer, prack_offer) in [(true, false), (false, false), (true, true)] {
        let token = tokio_util::sync::CancellationToken::new();
        let (server, server_addr) = udp_endpoint(&token).await?;
        let mut incoming = server.incoming_transactions()?;
        let server_layer = Arc::new(DialogLayer::new(server.inner.clone()));
        let server_media = Arc::new(Media::default());
        server_layer
            .set_reliable_provisional(Some(ReliableProvisionalConfig::new(server_media.clone())));
        let (states, mut events) = unbounded_channel();
        let router = tokio::spawn(async move {
            while let Some(mut tx) = incoming.recv().await {
                if let Some(mut dialog) = server_layer.match_dialog(&tx) {
                    tokio::spawn(async move { dialog.handle(&mut tx).await });
                } else if tx.original.method == Method::Invite {
                    let mut dialog = server_layer
                        .get_or_create_server_invite(
                            &tx,
                            states.clone(),
                            None,
                            Some(format!("sip:b@{server_addr}").as_str().try_into().unwrap()),
                        )
                        .unwrap();
                    dialog
                        .ringing(
                            Some(vec![Header::ContentType("application/sdp".into())]),
                            Some(
                                if invite_offer { ANSWER } else { OFFER }
                                    .as_bytes()
                                    .to_vec(),
                            ),
                        )
                        .unwrap();
                    dialog.accept(None, None).unwrap();
                    tokio::spawn(async move { dialog.handle(&mut tx).await });
                }
            }
        });
        let (client, client_addr) = udp_endpoint(&token).await?;
        let client_layer = DialogLayer::new(client.inner.clone());
        let client_media = Arc::new(Media {
            new_offer: prack_offer,
            ..Default::default()
        });
        client_layer.set_reliable_provisional(Some(ReliableProvisionalConfig {
            handler: client_media.clone(),
            require: true,
        }));
        let opt = InviteOption {
            caller: "sip:a@example.com".try_into()?,
            callee: format!("sip:b@{server_addr}").as_str().try_into()?,
            contact: format!("sip:a@{client_addr}").as_str().try_into()?,
            offer: invite_offer.then(|| OFFER.as_bytes().to_vec()),
            ..Default::default()
        };
        let (dialog, final_response) = timeout(
            Duration::from_secs(2),
            client_layer.do_invite(opt, unbounded_channel().0),
        )
        .await
        .unwrap()?;
        assert_eq!(final_response.unwrap().status_code, StatusCode::OK);
        timeout(Duration::from_secs(2), async {
            while !matches!(events.recv().await, Some(DialogState::Confirmed(..))) {}
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(2), async {
            while client_media.results.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            *client_media.events.lock(),
            vec![if invite_offer {
                SdpKind::Answer
            } else {
                SdpKind::Offer
            }]
        );
        assert_eq!(
            *server_media.events.lock(),
            vec![if prack_offer {
                SdpKind::Offer
            } else if invite_offer {
                SdpKind::None
            } else {
                SdpKind::Answer
            }]
        );
        timeout(Duration::from_secs(2), dialog.bye())
            .await
            .unwrap()?;
        assert!(client_media.errors.lock().is_empty());
        assert!(server_media.errors.lock().is_empty());
        token.cancel();
        router.abort();
    }
    Ok(())
}

#[tokio::test]
async fn reliable_reinvite_returns_after_consuming_transaction_termination() -> Result<()> {
    use crate::transaction::{transaction::TransactionEvent, TransactionState};
    let mut s = Server::new(true).await?;
    *s.dialog.inner.state.lock() = DialogState::Confirmed(s.dialog.id(), Response::default());
    let mut request = s.tx.original.clone();
    request
        .to_header_mut()?
        .mut_tag(s.dialog.id().local_tag.into())?;
    request.headers.unique_push(Header::CSeq("3 INVITE".into()));
    request.headers.unique_push(Header::Via(
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-ended-reinvite".into(),
    ));
    let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
    s.tx = Transaction::new_server(
        key.clone(),
        request,
        s.endpoint.inner.clone(),
        Some(s.conn.clone()),
    );
    // Model an already queued terminal event from the transaction's driver.
    // The command loop consumes it; the ACK loop must not wait for it again.
    s.tx.state = TransactionState::Terminated;
    s.tx.tu_sender.send(TransactionEvent::Terminate(key))?;
    timeout(Duration::from_secs(1), s.dialog.handle(&mut s.tx))
        .await
        .expect("re-INVITE handler must finish")?;
    assert!(matches!(s.events.try_recv(), Ok(DialogState::Updated(..))));
    Ok(())
}

#[tokio::test]
async fn controlled_offerless_reinvite_uses_prack_answer_and_empty_ack() -> Result<()> {
    use crate::dialog::reinvite::{AckBody, InviteAnswerHandler, ReinviteOptions};
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct FinalAnswer(AtomicUsize);
    #[async_trait]
    impl InviteAnswerHandler for FinalAnswer {
        async fn answer(&self, _: Response) -> Result<AckBody> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(AckBody::sdp(ANSWER))
        }
        fn fallback_answer(&self, _: &Response) -> AckBody {
            AckBody::sdp(ANSWER)
        }
    }
    let mut c = Client::new(true, false, false).await?;
    c.send(reply(
        &c.invite,
        StatusCode::OK,
        "bob",
        c.peer.local_addr()?,
        None,
        Some(ANSWER),
    ))
    .await;
    timeout(Duration::from_secs(1), &mut c.call)
        .await
        .unwrap()
        .unwrap()?;
    receive_request(&c.peer, Method::Ack).await;
    let final_answer = Arc::new(FinalAnswer(AtomicUsize::new(0)));
    let options = ReinviteOptions {
        answer_handler: Some(final_answer.clone()),
        ..Default::default()
    };
    let dialog = c.dialog.clone();
    let request = dialog.prepare_reinvite(None, None)?;
    let task = tokio::spawn(async move { dialog.send_reinvite(request, options).await });
    let invite = receive_request(&c.peer, Method::Invite).await;
    c.send(reply(
        &invite,
        StatusCode::SessionProgress,
        "bob",
        c.peer.local_addr()?,
        Some(1),
        Some(OFFER),
    ))
    .await;
    let prack = receive_request(&c.peer, Method::PRack).await;
    assert_eq!(prack.body, ANSWER.as_bytes());
    c.acknowledge(&prack, None).await;
    let final_response = reply(
        &invite,
        StatusCode::OK,
        "bob",
        c.peer.local_addr()?,
        None,
        Some(OFFER),
    );
    c.send(final_response.clone()).await;
    let ack = receive_request(&c.peer, Method::Ack).await;
    assert!(ack.body.is_empty());
    assert_eq!(final_answer.0.load(Ordering::SeqCst), 0);
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()?;
    c.send(final_response).await;
    assert_eq!(receive_request(&c.peer, Method::Ack).await, ack);
    Ok(())
}

#[tokio::test]
async fn controlled_incoming_reinvite_drives_prack_with_closed_command_channel() -> Result<()> {
    use crate::transaction::transaction::TransactionEvent;
    let mut s = Server::new(true).await?;
    *s.dialog.inner.state.lock() = DialogState::Confirmed(s.dialog.id(), Response::default());
    let mut request = s.tx.original.clone();
    request
        .to_header_mut()?
        .mut_tag(s.dialog.id().local_tag.into())?;
    request.headers.unique_push(Header::CSeq("3 INVITE".into()));
    request.headers.unique_push(Header::Via(
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-controlled-reliable".into(),
    ));
    let key = TransactionKey::from_request(&request, TransactionRole::Server)?;
    s.tx = Transaction::new_server(
        key,
        request.clone(),
        s.endpoint.inner.clone(),
        Some(s.conn.clone()),
    );
    s.dialog.inner.attach_reliable_server(&s.tx)?;
    let sender = s.tx.tu_sender.clone();
    let inner = s.dialog.inner.clone();
    let task = tokio::spawn(async move { inner.process_reinvite(&mut s.tx, true).await });
    let Some(DialogState::Updated(_, _, handle)) = s.events.recv().await else {
        panic!("missing re-INVITE event")
    };
    handle
        .respond(
            StatusCode::SessionProgress,
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(ANSWER.as_bytes().to_vec()),
        )
        .await?;
    handle.respond(StatusCode::OK, None, None).await?;
    drop(handle);
    let Some(TransportEvent::Incoming(SipMessage::Response(first), _, _)) = s.outgoing.recv().await
    else {
        panic!("missing 183")
    };
    assert_eq!(first.status_code, StatusCode::SessionProgress);
    let mut prack = request.clone();
    prack.method = Method::PRack;
    prack.headers.unique_push(Header::CSeq("4 PRACK".into()));
    prack.headers.unique_push(Header::RAck(
        format!("{} 3 INVITE", first.rseq_value().unwrap()).into(),
    ));
    prack.headers.unique_push(Header::Via(
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-controlled-prack".into(),
    ));
    prack.body.clear();
    let key = TransactionKey::from_request(&prack, TransactionRole::Server)?;
    let mut prack =
        Transaction::new_server(key, prack, s.endpoint.inner.clone(), Some(s.conn.clone()));
    s.dialog.inner.receive_prack(&mut prack).await?;
    // First 200 is PRACK, second is the previously queued INVITE final.
    s.outgoing.recv().await.unwrap();
    let Some(TransportEvent::Incoming(SipMessage::Response(final_response), _, _)) =
        s.outgoing.recv().await
    else {
        panic!("missing INVITE final")
    };
    assert_eq!(final_response.cseq_header()?.method()?, Method::Invite);
    assert_eq!(final_response.status_code, StatusCode::OK);
    let ack = s.endpoint.inner.make_ack(&request, &final_response)?;
    sender.send(TransactionEvent::Received(
        SipMessage::Request(ack),
        Some(s.conn),
    ))?;
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()?;
    Ok(())
}
