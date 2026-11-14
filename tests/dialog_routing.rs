//! Public-API routing regressions with a real UDP next hop.
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogSnapshot, DialogSnapshotState},
        dialog_layer::DialogLayer,
        invite_dialog::InviteDialog,
        reinvite::ReinviteOptions,
        DialogId,
    },
    sip::{HeadersExt, Method, Request, SipMessage, ToTypedHeader, Uri},
    transaction::{
        endpoint::{Endpoint, EndpointOption},
        key::TransactionRole,
        EndpointBuilder,
    },
    transport::{udp::UdpConnection, SipConnection, TransportLayer},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

const SDP: &str =
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=test\r\nt=0 0\r\nm=audio 19000 RTP/AVP 8\r\n";

struct Fixture {
    dialog: InviteDialog,
    endpoint: Arc<Endpoint>,
    peer: UdpSocket,
    proxy: Uri,
    target: Uri,
    stop: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Fixture {
    async fn new(strict: bool) -> Result<Self> {
        Self::with_role(strict, TransactionRole::Client).await
    }

    async fn with_role(strict: bool, role: TransactionRole) -> Result<Self> {
        Self::with_chain(strict, role, false).await
    }

    async fn with_chain(strict: bool, role: TransactionRole, multiple: bool) -> Result<Self> {
        let local = UdpSocket::bind("127.0.0.1:0").await?;
        let address = local.local_addr()?;
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let proxy = Uri::try_from(format!("sip:{}", peer.local_addr()?).as_str())?;
        let target = Uri::try_from("sip:callee@127.0.0.1:29901")?;
        let stop = CancellationToken::new();
        let connection =
            UdpConnection::from_socket(Arc::new(local), None, Some(stop.clone())).await?;
        let transport = TransportLayer::new(stop.clone());
        let connection = SipConnection::Udp(connection);
        transport.add_transport(connection.clone());
        let endpoint = Arc::new(
            EndpointBuilder::new()
                .with_transport_layer(transport)
                .with_cancel_token(stop.clone())
                .with_option(EndpointOption {
                    t1: Duration::from_millis(50),
                    t2: Duration::from_millis(200),
                    t1x64: Duration::from_millis(3200),
                    ..Default::default()
                })
                .build(),
        );
        let layer = DialogLayer::new(endpoint.inner.clone());
        let local_from = format!("<sip:caller@{address}>;tag=local");
        let remote_from = format!("<sip:callee@{}>;tag=remote", peer.local_addr()?);
        let (from, to) = if role == TransactionRole::Client {
            (local_from, remote_from)
        } else {
            (remote_from, local_from)
        };
        let snapshot = DialogSnapshot {
            id: DialogId {
                call_id: "route-contract".into(),
                local_tag: "local".into(),
                remote_tag: "remote".into(),
            },
            role,
            state: DialogSnapshotState::Confirmed,
            from: rsipstack::sip::headers::From::from(from).typed()?,
            to: rsipstack::sip::headers::To::from(to).typed()?,
            remote_uri: target.clone(),
            local_cseq: 1,
            remote_cseq: 10,
            local_contact: Some(Uri::try_from(format!("sip:caller@{address}").as_str())?),
            remote_contact: Some(format!("<{target}>").into()),
            route_set: vec![format!(
                "<{proxy}{}>{}",
                if strict { "" } else { ";lr" },
                if multiple {
                    ", <sip:second@127.0.0.1:29904;lr>;x=keep"
                } else {
                    ""
                }
            )
            .into()],
            supports_100rel: false,
            session_id: None,
        };
        let (states, _receiver) = mpsc::unbounded_channel();
        let id = snapshot.id.clone();
        assert!(layer.restore_from_snapshot_with_credential(
            snapshot,
            states,
            Some(rsipstack::dialog::authenticate::Credential {
                username: "caller".into(),
                password: "secret".into(),
                realm: None,
                auth_username: None,
            })
        )?);
        let Some(Dialog::Invite(dialog)) = layer.get_dialog(&id) else {
            return Err("expected confirmed dialog".into());
        };
        let serving = endpoint.clone();
        tokio::spawn(async move { serving.serve().await });
        Ok(Self {
            dialog,
            endpoint,
            peer,
            proxy,
            target,
            stop,
        })
    }

    async fn receive(&self, method: Method) -> Result<(Request, SocketAddr)> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut bytes = [0; 8192];
            loop {
                let (n, source) = self.peer.recv_from(&mut bytes).await?;
                if let SipMessage::Request(request) = SipMessage::try_from(&bytes[..n])? {
                    if request.method == method {
                        return Ok((request, source));
                    }
                }
            }
        })
        .await?
    }

    async fn refresh_ack(&self) -> Result<Request> {
        self.refresh_ack_with_challenge(false).await
    }

    async fn refresh_ack_with_challenge(&self, authenticate: bool) -> Result<Request> {
        let request = self.dialog.prepare_reinvite(
            Some(vec![rsipstack::sip::Header::ContentType(
                "application/sdp".into(),
            )]),
            Some(SDP.as_bytes().to_vec()),
        )?;
        let dialog = self.dialog.clone();
        let exchange = tokio::spawn(async move {
            dialog
                .send_reinvite(request, ReinviteOptions::default())
                .await
        });
        let (mut invite, mut source) = self.receive(Method::Invite).await?;
        if authenticate {
            let mut challenge = self.endpoint.inner.make_response(
                &invite,
                rsipstack::sip::StatusCode::Unauthorized,
                None,
            );
            challenge
                .headers
                .push(rsipstack::sip::Header::WwwAuthenticate(
                    "Digest realm=\"routing\", nonce=\"first\", algorithm=MD5".into(),
                ));
            self.peer
                .send_to(challenge.to_string().as_bytes(), source)
                .await?;
            let (ack, _) = self.receive(Method::Ack).await?;
            assert_eq!(ack.uri, invite.uri);
            assert_eq!(ack.route_headers(), invite.route_headers());
            let next = self.receive(Method::Invite).await?;
            assert_eq!(next.0.uri, invite.uri);
            assert!(next.0.authorization_header().is_some());
            assert!(next.0.cseq_header()?.seq()? > invite.cseq_header()?.seq()?);
            (invite, source) = next;
        }
        let response = format!(
            "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContact: <sip:refreshed@127.0.0.1:29902>\r\nRecord-Route: <sip:127.0.0.1:29903;lr>\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{SDP}",
            invite.via_header()?.value(),
            invite.from_header()?.value(),
            invite.to_header()?.value(),
            invite.call_id_header()?.value(),
            invite.cseq_header()?.value(),
            SDP.len(),
        );
        self.peer.send_to(response.as_bytes(), source).await?;
        let (ack, _) = self.receive(Method::Ack).await?;
        tokio::time::timeout(Duration::from_secs(2), exchange).await???;
        Ok(ack)
    }
}

#[tokio::test]
async fn strict_route_prepared_request_uses_proxy_uri_and_target_tail() -> Result<()> {
    let f = Fixture::new(true).await?;
    let request = f
        .dialog
        .prepare_reinvite(None, Some(SDP.as_bytes().to_vec()))?;
    assert_eq!(request.uri, f.proxy, "strict proxy must be the Request-URI");
    assert_eq!(
        request.route_header().unwrap().value(),
        format!("<{}>", f.target)
    );
    Ok(())
}

#[tokio::test]
async fn strict_route_ack_after_target_refresh_keeps_original_proxy() -> Result<()> {
    let f = Fixture::new(true).await?;
    let ack = f.refresh_ack().await?;
    assert_eq!(ack.uri, f.proxy, "ACK must traverse the strict proxy");
    assert_eq!(
        ack.route_header().unwrap().value(),
        "<sip:refreshed@127.0.0.1:29902>"
    );
    Ok(())
}

#[tokio::test]
async fn loose_route_ack_after_target_refresh_keeps_original_proxy() -> Result<()> {
    let f = Fixture::new(false).await?;
    let ack = f.refresh_ack().await?;
    assert_eq!(ack.uri, Uri::try_from("sip:refreshed@127.0.0.1:29902")?);
    assert_eq!(
        ack.route_header().unwrap().value(),
        format!("<{};lr>", f.proxy)
    );
    Ok(())
}

#[tokio::test]
async fn strict_route_chain_preserves_remaining_routes_and_refreshed_target() -> Result<()> {
    let f = Fixture::with_chain(true, TransactionRole::Server, true).await?;
    let ack = f.refresh_ack().await?;
    assert_eq!(ack.uri, f.proxy);
    let routes: Vec<_> = ack.route_headers().into_iter().map(|r| r.value()).collect();
    assert_eq!(
        routes,
        [
            "<sip:second@127.0.0.1:29904;lr>;x=keep",
            "<sip:refreshed@127.0.0.1:29902>"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn strict_reinvite_authentication_keeps_routing_context() -> Result<()> {
    let f = Fixture::new(true).await?;
    let ack = f.refresh_ack_with_challenge(true).await?;
    assert_eq!(ack.uri, f.proxy);
    assert_eq!(
        ack.route_header().unwrap().value(),
        "<sip:refreshed@127.0.0.1:29902>"
    );
    Ok(())
}

#[tokio::test]
async fn strict_next_hop_used_for_regular_requests_on_both_roles() -> Result<()> {
    for role in [TransactionRole::Client, TransactionRole::Server] {
        for method in [Method::Info, Method::Update, Method::Bye] {
            let f = Fixture::with_chain(true, role, true).await?;
            let dialog = f.dialog.clone();
            let sending = method.clone();
            let exchange = tokio::spawn(async move { dialog.request(sending, None, None).await });
            let (request, source) = f.receive(method).await?;
            assert_eq!(request.uri, f.proxy);
            assert_eq!(
                request.route_headers().last().unwrap().value(),
                format!("<{}>", f.target)
            );
            let response =
                f.endpoint
                    .inner
                    .make_response(&request, rsipstack::sip::StatusCode::OK, None);
            f.peer
                .send_to(response.to_string().as_bytes(), source)
                .await?;
            tokio::time::timeout(Duration::from_secs(2), exchange).await???;
        }
    }
    Ok(())
}

#[tokio::test]
async fn initial_ack_encodes_strict_routes_from_record_route() -> Result<()> {
    let endpoint = EndpointBuilder::new().build();
    let invite: Request = "INVITE sip:callee@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-route\r\nFrom: <sip:caller@127.0.0.1>;tag=local\r\nTo: <sip:callee@127.0.0.1>\r\nCall-ID: routes\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n".try_into()?;
    let mut response = endpoint
        .inner
        .make_response(&invite, rsipstack::sip::StatusCode::OK, None);
    use rsipstack::sip::Header;
    response
        .headers
        .unique_push(Header::To("<sip:callee@127.0.0.1>;tag=remote".into()));
    response
        .headers
        .push(Header::Contact("<sip:callee@127.0.0.1:29902>".into()));
    response.headers.push(Header::RecordRoute(
        "<sip:second@127.0.0.1:29904;lr>, <sip:first@127.0.0.1:29903>".into(),
    ));
    let ack = endpoint.inner.make_ack(&invite, &response)?;
    assert_eq!(ack.uri.to_string(), "sip:first@127.0.0.1:29903");
    let routes: Vec<_> = ack.route_headers().into_iter().map(|r| r.value()).collect();
    assert_eq!(
        routes,
        [
            "<sip:second@127.0.0.1:29904;lr>",
            "<sip:callee@127.0.0.1:29902>"
        ]
    );
    Ok(())
}

struct Answer;
#[async_trait::async_trait]
impl rsipstack::dialog::reinvite::InviteAnswerHandler for Answer {
    async fn answer(
        &self,
        _: rsipstack::sip::Response,
    ) -> rsipstack::Result<rsipstack::dialog::reinvite::AckBody> {
        Ok(rsipstack::dialog::reinvite::AckBody::sdp(SDP.as_bytes()))
    }
    fn fallback_answer(
        &self,
        _: &rsipstack::sip::Response,
    ) -> rsipstack::dialog::reinvite::AckBody {
        rsipstack::dialog::reinvite::AckBody::sdp(SDP.as_bytes())
    }
}

#[tokio::test]
async fn offerless_ack_keeps_strict_route_and_answer() -> Result<()> {
    let f = Fixture::new(true).await?;
    let request = f.dialog.prepare_reinvite(None, None)?;
    let dialog = f.dialog.clone();
    let exchange = tokio::spawn(async move {
        dialog
            .send_reinvite(
                request,
                ReinviteOptions {
                    answer_handler: Some(Arc::new(Answer)),
                    ..Default::default()
                },
            )
            .await
    });
    let (invite, source) = f.receive(Method::Invite).await?;
    let mut response = f.endpoint.inner.make_response(
        &invite,
        rsipstack::sip::StatusCode::OK,
        Some(SDP.as_bytes().to_vec()),
    );
    response.headers.push(rsipstack::sip::Header::Contact(
        "<sip:refreshed@127.0.0.1:29902>".into(),
    ));
    response.headers.push(rsipstack::sip::Header::ContentType(
        "application/sdp".into(),
    ));
    f.peer
        .send_to(response.to_string().as_bytes(), source)
        .await?;
    let (ack, _) = f.receive(Method::Ack).await?;
    assert_eq!(ack.uri, f.proxy);
    assert_eq!(
        ack.route_header().unwrap().value(),
        "<sip:refreshed@127.0.0.1:29902>"
    );
    assert_eq!(ack.body, SDP.as_bytes());
    tokio::time::timeout(Duration::from_secs(2), exchange).await???;
    f.peer
        .send_to(response.to_string().as_bytes(), source)
        .await?;
    let (repeated, _) = f.receive(Method::Ack).await?;
    assert_eq!(ack.to_string(), repeated.to_string());
    Ok(())
}

#[tokio::test]
async fn initial_ack_is_sent_to_first_strict_hop() -> Result<()> {
    use rsipstack::{
        sip::Header,
        transaction::{key::TransactionKey, transaction::Transaction},
    };
    let f = Fixture::new(true).await?;
    let mut request = f
        .dialog
        .prepare_reinvite(None, Some(SDP.as_bytes().to_vec()))?;
    request
        .headers
        .unique_push(Header::To("<sip:callee@127.0.0.1>".into()));
    request.headers.retain(|h| !matches!(h, Header::Route(_)));
    let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key, request, f.endpoint.inner.clone(), None);
    let exchange = tokio::spawn(async move {
        tx.send().await?;
        tokio::time::timeout(Duration::from_secs(2), tx.receive()).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (invite, source) = f.receive(Method::Invite).await?;
    let mut response =
        f.endpoint
            .inner
            .make_response(&invite, rsipstack::sip::StatusCode::OK, None);
    response
        .headers
        .unique_push(Header::To("<sip:callee@127.0.0.1>;tag=remote".into()));
    response
        .headers
        .push(Header::Contact("<sip:refreshed@127.0.0.1:29902>".into()));
    response.headers.push(Header::RecordRoute(
        format!("<sip:second@127.0.0.1:29904;lr>, <{}>", f.proxy).into(),
    ));
    f.peer
        .send_to(response.to_string().as_bytes(), source)
        .await?;
    let (ack, _) = f.receive(Method::Ack).await?;
    assert_eq!(ack.uri, f.proxy);
    assert_eq!(
        ack.route_headers().last().unwrap().value(),
        "<sip:refreshed@127.0.0.1:29902>"
    );
    exchange.await??;
    Ok(())
}
