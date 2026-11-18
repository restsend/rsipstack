#![cfg(feature = "platform-tokio")]

use rsipstack::{
    dialog::{
        dialog::{DialogState, DialogStateReceiver},
        dialog_layer::DialogLayer,
        invitation::InviteOption,
    },
    sip::{HeadersExt, Method, Request, SipMessage, Transport},
    transaction::endpoint::{Endpoint, MessageInspector},
    transport::{
        channel::ChannelConnection, udp::UdpConnection, SipAddr, SipConnection, TransportEvent,
        TransportLayer,
    },
    EndpointBuilder,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Default)]
struct RecordedDestinations(Arc<Mutex<Vec<(Method, Option<SipAddr>)>>>);

impl MessageInspector for RecordedDestinations {
    fn before_send(&self, msg: SipMessage, destination: Option<&SipAddr>) -> SipMessage {
        if let SipMessage::Request(request) = &msg {
            if matches!(request.method, Method::Invite | Method::Cancel) {
                self.0
                    .lock()
                    .unwrap()
                    .push((request.method.clone(), destination.cloned()));
            }
        }
        msg
    }

    fn after_received(&self, msg: SipMessage, _from: Option<&SipAddr>) -> SipMessage {
        msg
    }
}

async fn endpoint(
    stop: &CancellationToken,
    outbound: Option<SipAddr>,
    inspector: Option<RecordedDestinations>,
) -> Result<Arc<Endpoint>> {
    let mut transport = TransportLayer::new(stop.child_token());
    transport.outbound = outbound;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local = UdpConnection::from_socket(Arc::new(socket), None, Some(stop.child_token())).await?;
    transport.add_transport(SipConnection::Udp(local));
    let mut builder = EndpointBuilder::new();
    builder
        .with_transport_layer(transport)
        .with_cancel_token(stop.child_token());
    if let Some(inspector) = inspector {
        builder.with_inspector(Box::new(inspector));
    }
    let endpoint = Arc::new(builder.build());
    let serving = endpoint.clone();
    tokio::spawn(async move { serving.serve().await });
    Ok(endpoint)
}

fn invite_options(destination: SipAddr) -> Result<InviteOption> {
    Ok(InviteOption {
        caller: "sip:alice@example.com".try_into()?,
        callee: "sip:bob@carrier.invalid".try_into()?,
        contact: "sip:alice@127.0.0.1".try_into()?,
        destination: Some(destination),
        ..Default::default()
    })
}

async fn wait_for_early(states: &mut DialogStateReceiver) -> Result {
    timeout(WAIT, async {
        while let Some(state) = states.recv().await {
            if matches!(state, DialogState::Early(..)) {
                return Ok(());
            }
        }
        Err("state channel closed before Early")
    })
    .await??;
    Ok(())
}

fn response(request: &Request, status: &str) -> Result<String> {
    Ok(format!(
        "SIP/2.0 {status}\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {};tag=peer\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <sip:bob@carrier.invalid>\r\n\
         Content-Length: 0\r\n\r\n",
        request.via_header()?.value(),
        request.from_header()?.value(),
        request.to_header()?.value(),
        request.call_id_header()?.value(),
        request.cseq_header()?.value(),
    ))
}

fn assert_cancel(invite: &Request, cancel: &Request) -> Result {
    assert_eq!(invite.method, Method::Invite);
    assert_eq!(cancel.method, Method::Cancel);
    assert_eq!(cancel.uri, invite.uri);
    assert_eq!(cancel.call_id_header()?, invite.call_id_header()?);
    assert_eq!(cancel.via_header()?, invite.via_header()?);
    assert_eq!(cancel.cseq_header()?.seq()?, invite.cseq_header()?.seq()?);
    Ok(())
}

async fn read_tcp_request(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Request> {
    timeout(WAIT, async {
        let mut wire = Vec::new();
        loop {
            let start = wire.len();
            if reader.read_until(b'\n', &mut wire).await? == 0 {
                return Err("TCP connection closed before SIP request".into());
            }
            if &wire[start..] == b"\r\n" {
                // The INVITE and CANCEL in this test have empty bodies.
                return Ok(SipMessage::try_from(wire.as_slice())?.try_into()?);
            }
        }
    })
    .await?
}

#[tokio::test]
async fn tcp_cancel_reuses_the_exact_invite_stream() -> Result {
    let stop = CancellationToken::new();
    let _stop = stop.clone().drop_guard();
    let endpoint = endpoint(&stop, None, None).await?;
    let peer = TcpListener::bind("127.0.0.1:0").await?;
    let destination = SipAddr::new(Transport::Tcp, peer.local_addr()?.into());
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (sender, mut states) = mpsc::unbounded_channel();
    let (dialog, invite_task) = layer.do_invite_async(invite_options(destination)?, sender)?;

    let (stream, _) = timeout(WAIT, peer.accept()).await??;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let invite = read_tcp_request(&mut reader).await?;
    write_half
        .write_all(response(&invite, "180 Ringing")?.as_bytes())
        .await?;
    wait_for_early(&mut states).await?;

    let cancel_task = tokio::spawn(async move { dialog.cancel().await });
    let cancel = read_tcp_request(&mut reader).await?;
    assert_cancel(&invite, &cancel)?;
    write_half
        .write_all(response(&cancel, "200 OK")?.as_bytes())
        .await?;
    write_half
        .write_all(response(&invite, "487 Request Terminated")?.as_bytes())
        .await?;
    assert_eq!(read_tcp_request(&mut reader).await?.method, Method::Ack);
    timeout(WAIT, cancel_task).await???;
    let (_, final_response) = timeout(WAIT, invite_task).await???;
    assert_eq!(final_response.unwrap().status_code.code(), 487);
    Ok(())
}

async fn read_channel_request(
    receiver: &mut mpsc::UnboundedReceiver<TransportEvent>,
) -> Result<Request> {
    let event = timeout(WAIT, receiver.recv())
        .await?
        .ok_or("Channel closed before SIP request")?;
    match event {
        TransportEvent::Incoming(SipMessage::Request(request), _, _) => Ok(request),
        _ => Err("expected an outgoing request on the Channel".into()),
    }
}

#[tokio::test]
async fn channel_cancel_reuses_the_exact_invite_flow_and_reports_its_peer() -> Result {
    let stop = CancellationToken::new();
    let _stop = stop.clone().drop_guard();
    let peer: SocketAddr = "127.0.0.1:42190".parse()?;
    let configured: SocketAddr = "127.0.0.1:42191".parse()?;
    let peer = SipAddr::new(Transport::Ws, peer.into());
    let configured = SipAddr::new(Transport::Ws, configured.into());
    let destinations = RecordedDestinations::default();
    let endpoint = endpoint(&stop, Some(peer.clone()), Some(destinations.clone())).await?;

    let (to_stack, incoming) = mpsc::unbounded_channel();
    let (outgoing, mut from_stack) = mpsc::unbounded_channel();
    let connection = SipConnection::Channel(
        ChannelConnection::create_connection(
            incoming,
            outgoing,
            peer.clone(),
            Some(stop.child_token()),
        )
        .await?,
    );
    endpoint.inner.transport_layer.add_connection(connection.clone());
    let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (sender, mut states) = mpsc::unbounded_channel();
    let (dialog, invite_task) = layer.do_invite_async(invite_options(configured)?, sender)?;

    let invite = read_channel_request(&mut from_stack).await?;
    let ringing = response(&invite, "180 Ringing")?;
    to_stack.send(TransportEvent::Incoming(
        SipMessage::try_from(ringing.as_str())?,
        connection.clone(),
        peer.clone(),
    ))?;
    wait_for_early(&mut states).await?;

    // A fresh lookup at the same address now selects a different Channel.
    let (_replacement_sender, replacement_incoming) = mpsc::unbounded_channel();
    let (replacement_outgoing, mut replacement_receiver) = mpsc::unbounded_channel();
    let replacement = SipConnection::Channel(
        ChannelConnection::create_connection(
            replacement_incoming,
            replacement_outgoing,
            peer.clone(),
            Some(stop.child_token()),
        )
        .await?,
    );
    endpoint.inner.transport_layer.add_connection(replacement);

    let cancel_task = tokio::spawn(async move { dialog.cancel().await });
    let cancel = read_channel_request(&mut from_stack).await?;
    assert_cancel(&invite, &cancel)?;
    assert!(replacement_receiver.try_recv().is_err());
    for message in [
        response(&cancel, "200 OK")?,
        response(&invite, "487 Request Terminated")?,
    ] {
        to_stack.send(TransportEvent::Incoming(
            SipMessage::try_from(message.as_str())?,
            connection.clone(),
            peer.clone(),
        ))?;
    }
    assert_eq!(read_channel_request(&mut from_stack).await?.method, Method::Ack);
    timeout(WAIT, cancel_task).await???;
    let (_, final_response) = timeout(WAIT, invite_task).await???;
    assert_eq!(final_response.unwrap().status_code.code(), 487);
    assert_eq!(
        *destinations.0.lock().unwrap(),
        [(Method::Invite, Some(peer.clone())), (Method::Cancel, Some(peer))],
    );
    Ok(())
}
