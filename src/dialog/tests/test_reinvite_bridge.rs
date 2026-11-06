use super::test_in_dialog_provisional::{establish_with_options, recv_request, reply, response};
use crate::{
    dialog::{
        dialog::{DialogState, DialogStateReceiver, TransactionHandle},
        invite_dialog::InviteDialog,
        reinvite_bridge::{PassthroughSdp, ReinviteBridge, ReinviteBridgePolicy},
    },
    sip::{Header, HeadersExt, Method, Request, Response, SipMessage},
    transaction::endpoint::EndpointOption,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const OFFER: &[u8] = b"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=sendonly\r\n";
const ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=recvonly\r\n";

fn incoming(
    dialog: &InviteDialog,
    peer: &UdpSocket,
    offer: bool,
) -> crate::Result<(Request, SocketAddr)> {
    let local = dialog
        .inner
        .endpoint_inner
        .transport_layer
        .get_listen_addrs()[0]
        .get_socketaddr()?;
    let remote = peer.local_addr()?;
    let id = dialog.id();
    let mut request = Request::try_from(format!(
        "INVITE sip:alice@{local} SIP/2.0\r\nVia: SIP/2.0/UDP {remote};branch=z9hG4bK-bridge-10\r\nMax-Forwards: 70\r\nFrom: <sip:peer@{remote}>;tag={}\r\nTo: <sip:alice@{local}>;tag={}\r\nCall-ID: {}\r\nCSeq: 10 INVITE\r\nContact: <sip:peer@{remote}>\r\nContent-Length: 0\r\n\r\n", id.remote_tag, id.local_tag, id.call_id
    ).as_str())?;
    if offer {
        request.body = OFFER.to_vec();
        request
            .headers
            .unique_push(Header::ContentType("application/sdp".into()));
        request
            .headers
            .unique_push(Header::ContentLength((OFFER.len() as u32).into()));
    }
    Ok((request, local))
}

async fn updated(states: &mut DialogStateReceiver) -> TransactionHandle {
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(state) = states.recv().await {
            if let DialogState::Updated(_, _, handle) = state {
                return handle;
            }
        }
        panic!("missing re-INVITE event")
    })
    .await
    .unwrap()
}
async fn received(peer: &UdpSocket, method: Method, status: u16) -> crate::Result<Response> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut packet = [0; 8192];
        loop {
            let (len, _) = peer.recv_from(&mut packet).await?;
            if let SipMessage::Response(response) = SipMessage::try_from(&packet[..len])? {
                if response.cseq_header()?.method()? == method
                    && response.status_code.code() == status
                {
                    return Ok(response);
                }
            }
        }
    })
    .await
    .unwrap()
}
async fn ack(
    peer: &UdpSocket,
    address: SocketAddr,
    request: &Request,
    body: Option<&[u8]>,
) -> crate::Result<()> {
    let mut ack = request.clone();
    ack.method = Method::Ack;
    ack.cseq_header_mut()?.mut_method(Method::Ack)?;
    ack.body = body.unwrap_or_default().to_vec();
    ack.headers
        .unique_push(Header::ContentLength((ack.body.len() as u32).into()));
    if body.is_some() {
        ack.headers
            .unique_push(Header::ContentType("application/sdp".into()));
    } else {
        ack.headers.retain(|h| !matches!(h, Header::ContentType(_)));
    }
    peer.send_to(ack.to_string().as_bytes(), address).await?;
    Ok(())
}
async fn success(
    peer: &UdpSocket,
    address: SocketAddr,
    request: &Request,
    body: &[u8],
) -> crate::Result<Response> {
    let mut response = Response::try_from(
        response(
            request,
            200,
            "OK",
            &format!("sip:peer@{}", peer.local_addr()?),
        )
        .as_str(),
    )?;
    response.body = body.to_vec();
    response
        .headers
        .unique_push(Header::ContentType("application/sdp".into()));
    response
        .headers
        .unique_push(Header::ContentLength((body.len() as u32).into()));
    peer.send_to(response.to_string().as_bytes(), address)
        .await?;
    Ok(response)
}
async fn result(
    task: JoinHandle<crate::Result<crate::sip::StatusCode>>,
) -> crate::Result<crate::sip::StatusCode> {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
}

#[derive(Clone, Copy)]
enum Scenario {
    Offered,
    Offerless,
    Rejected,
    Cancelled,
    LateSuccess,
    MissingAck,
    Glare,
    Shutdown,
}

async fn scenario(reverse: bool, scenario: Scenario) -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let option = || EndpointOption {
        t1: Duration::from_millis(10),
        t1x64: Duration::from_millis(640),
        ..Default::default()
    };
    let (a, mut a_states, a_peer) = establish_with_options(&token, None, option()).await?;
    let (b, mut b_states, b_peer) = establish_with_options(&token, None, option()).await?;
    let bridge = ReinviteBridge::new(a.clone(), b.clone())?;
    let (source, destination, states, peer, other) = if reverse {
        (&b, &a, &mut b_states, &b_peer, &a_peer)
    } else {
        (&a, &b, &mut a_states, &a_peer, &b_peer)
    };
    let offer = !matches!(scenario, Scenario::Offerless | Scenario::MissingAck);
    let (request, address) = incoming(source, peer, offer)?;
    peer.send_to(request.to_string().as_bytes(), address)
        .await?;
    let handle = updated(states).await;
    let source_id = source.id();
    let original = request.clone();
    let pending_bridge = bridge.clone();
    let task =
        tokio::spawn(async move { pending_bridge.handle(source_id, original, handle).await });
    let (outgoing, other_address) = recv_request(other, Method::Invite).await;
    assert_ne!(outgoing.call_id_header()?, request.call_id_header()?);
    assert_ne!(
        outgoing.cseq_header()?.seq()?,
        request.cseq_header()?.seq()?
    );
    assert_eq!(outgoing.body, request.body);
    reply(other, other_address, &outgoing, 180, "Ringing").await;
    received(peer, Method::Invite, 180).await?;

    if matches!(scenario, Scenario::Shutdown) {
        let mut bye = request.clone();
        bye.method = Method::Bye;
        bye.cseq_header_mut()?
            .mut_seq(11)?
            .mut_method(Method::Bye)?;
        bye.body.clear();
        bye.headers.unique_push(Header::ContentLength(0.into()));
        peer.send_to(bye.to_string().as_bytes(), address).await?;
        received(peer, Method::Bye, 200).await?;
        bridge.shutdown();
        let (cancel, _) = recv_request(other, Method::Cancel).await;
        reply(other, other_address, &cancel, 200, "OK").await;
    }
    if matches!(scenario, Scenario::Glare) {
        let (collision, collision_address) = incoming(destination, other, true)?;
        other
            .send_to(collision.to_string().as_bytes(), collision_address)
            .await?;
        received(other, Method::Invite, 491).await?;
        ack(other, collision_address, &collision, None).await?;
    }
    if matches!(scenario, Scenario::Cancelled | Scenario::LateSuccess) {
        let mut cancel = request.clone();
        cancel.method = Method::Cancel;
        cancel.cseq_header_mut()?.mut_method(Method::Cancel)?;
        cancel.body.clear();
        cancel
            .headers
            .retain(|h| !matches!(h, Header::ContentType(_)));
        cancel.headers.unique_push(Header::ContentLength(0.into()));
        peer.send_to(cancel.to_string().as_bytes(), address).await?;
        received(peer, Method::Cancel, 200).await?;
        let (forwarded, _) = recv_request(other, Method::Cancel).await;
        assert_eq!(forwarded.via_header()?, outgoing.via_header()?);
        assert_eq!(
            forwarded.cseq_header()?.seq()?,
            outgoing.cseq_header()?.seq()?
        );
        reply(other, other_address, &forwarded, 200, "OK").await;
    }
    if matches!(
        scenario,
        Scenario::Rejected | Scenario::Cancelled | Scenario::Shutdown
    ) {
        let code = if matches!(scenario, Scenario::Rejected) {
            488
        } else {
            487
        };
        reply(other, other_address, &outgoing, code, "Rejected").await;
        let (out_ack, _) = recv_request(other, Method::Ack).await;
        assert_eq!(
            out_ack.cseq_header()?.seq()?,
            outgoing.cseq_header()?.seq()?
        );
        received(peer, Method::Invite, code).await?;
        ack(peer, address, &request, None).await?;
        assert_eq!(result(task).await?.code(), code);
    } else {
        let payload = if offer { ANSWER } else { OFFER };
        let final_response = success(other, other_address, &outgoing, payload).await?;
        if offer {
            recv_request(other, Method::Ack).await;
        }
        let incoming_response = received(peer, Method::Invite, 200).await?;
        assert_eq!(incoming_response.body, payload);
        if matches!(scenario, Scenario::MissingAck) {
            let (rejection, _) = recv_request(other, Method::Ack).await;
            assert!(String::from_utf8_lossy(&rejection.body).contains("m=audio 0 RTP/AVP 0"));
            let (bye, _) = recv_request(other, Method::Bye).await;
            reply(other, other_address, &bye, 200, "OK").await;
            let (bye, _) = recv_request(peer, Method::Bye).await;
            reply(peer, address, &bye, 200, "OK").await;
            assert!(result(task).await.is_err());
            assert!(a.state().is_terminated());
            assert!(b.state().is_terminated());
            return Ok(());
        }
        if !offer {
            let mut bytes = [0; 8192];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), other.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        }
        ack(peer, address, &request, (!offer).then_some(ANSWER)).await?;
        if !offer {
            let (answer, _) = recv_request(other, Method::Ack).await;
            assert_eq!(answer.body, ANSWER);
            other
                .send_to(final_response.to_string().as_bytes(), other_address)
                .await?;
            let (repeated, _) = recv_request(other, Method::Ack).await;
            assert_eq!(repeated, answer);
        }
        assert_eq!(result(task).await?.code(), 200);
    }
    if matches!(scenario, Scenario::Shutdown) {
        assert!(source.state().is_terminated());
        let closer = destination.clone();
        let closing = tokio::spawn(async move { closer.bye().await });
        let (bye, _) = recv_request(other, Method::Bye).await;
        reply(other, other_address, &bye, 200, "OK").await;
        closing.await.unwrap()?;
        assert!(destination.state().is_terminated());
    } else {
        assert!(a.state().is_confirmed());
        assert!(b.state().is_confirmed());
    }
    Ok(())
}

macro_rules! cases {
    ($($name:ident, $reverse:expr, $case:ident;)*) => {$(
        #[tokio::test]
        async fn $name() -> crate::Result<()> { scenario($reverse, Scenario::$case).await }
    )*};
}
cases! {
    a_to_b_offer, false, Offered; b_to_a_offer, true, Offered;
    a_to_b_offerless, false, Offerless; b_to_a_offerless, true, Offerless;
    a_to_b_rejected, false, Rejected; b_to_a_rejected, true, Rejected;
    a_to_b_cancelled, false, Cancelled; b_to_a_cancelled, true, Cancelled;
    a_to_b_late_success, false, LateSuccess; b_to_a_late_success, true, LateSuccess;
    a_to_b_missing_ack, false, MissingAck; b_to_a_missing_ack, true, MissingAck;
    a_to_b_glare, false, Glare; b_to_a_glare, true, Glare;
    a_to_b_shutdown, false, Shutdown; b_to_a_shutdown, true, Shutdown;
}

#[test]
fn rejecting_answer_preserves_media_order_and_disables_every_stream() {
    let mut offer = Response::default();
    offer.body = b"v=0\r\nm=audio 10000 RTP/AVP 0 8\r\nm=video 10002 RTP/SAVPF 96\r\nm=application 10004 UDP/DTLS/SCTP webrtc-datachannel\r\n".to_vec();
    let answer = PassthroughSdp.reject_offer(&offer);
    let text = String::from_utf8(answer.body).unwrap();
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("m="))
            .collect::<Vec<_>>(),
        vec![
            "m=audio 0 RTP/AVP 0 8",
            "m=video 0 RTP/SAVPF 96",
            "m=application 0 UDP/DTLS/SCTP webrtc-datachannel"
        ]
    );
}

#[tokio::test]
async fn cancel_before_application_dispatch_does_not_start_other_leg() -> crate::Result<()> {
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    let (a, mut states, peer) = establish_with_options(&token, None, Default::default()).await?;
    let (b, _other_states, other) =
        establish_with_options(&token, None, Default::default()).await?;
    let bridge = ReinviteBridge::new(a.clone(), b)?;
    let (request, address) = incoming(&a, &peer, true)?;
    peer.send_to(request.to_string().as_bytes(), address)
        .await?;
    let handle = updated(&mut states).await;
    let mut cancel = request.clone();
    cancel.method = Method::Cancel;
    cancel.cseq_header_mut()?.mut_method(Method::Cancel)?;
    cancel.body.clear();
    cancel.headers.unique_push(Header::ContentLength(0.into()));
    peer.send_to(cancel.to_string().as_bytes(), address).await?;
    received(&peer, Method::Cancel, 200).await?;
    received(&peer, Method::Invite, 487).await?;
    assert_eq!(
        bridge.handle(a.id(), request.clone(), handle).await?.code(),
        487
    );
    ack(&peer, address, &request, None).await?;
    let mut bytes = [0; 8192];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), other.recv_from(&mut bytes))
            .await
            .is_err()
    );
    Ok(())
}
