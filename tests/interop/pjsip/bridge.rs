//! Two independent PJSUA call state machines joined by ReinviteBridge.
use crate::interop::{bounded, log_dir, until, until_result, Peer, Required, Stack, TestResult};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption, reinvite_bridge::ReinviteBridge},
    sip::{Header, HeadersExt, Method, SipMessage},
};

async fn scenario(name: &str, transport: &str, reverse: bool) -> TestResult {
    let dir = log_dir(name)?;
    let a_dir = dir.join("a");
    let b_dir = dir.join("b");
    std::fs::create_dir_all(&a_dir).required()?;
    std::fs::create_dir_all(&b_dir).required()?;
    let mut a_stack = Stack::start(transport, &a_dir).await?;
    let b_stack = Stack::start(transport, &b_dir).await?;
    let mut a_peer = Peer::start(transport, &a_dir).await?;
    let mut b_peer = Peer::start(transport, &b_dir).await?;
    a_peer.command(&format!("m\n{}\n", a_stack.uri)).await?;
    let a = bounded("incoming A dialog", a_stack.incoming.recv())
        .await?
        .required()?;
    a.ringing(None, None).required()?;
    let initial = a_stack.wire.request(false, Method::Invite).await?;
    let (b, task) = b_stack
        .layer
        .do_invite_async(
            InviteOption {
                caller: b_stack.uri.clone(),
                callee: b_peer.uri.clone(),
                contact: b_stack.uri.clone(),
                offer: Some(initial.body.clone()),
                content_type: Some("application/sdp".into()),
                ..Default::default()
            },
            b_stack.sender.clone(),
        )
        .required()?;
    b_peer.wait_text("state changed to EARLY").await?;
    b_peer.command("a\n200\n").await?;
    let (_, response) = bounded("outgoing B dialog", task)
        .await?
        .required()?
        .required()?;
    let response = response.required()?;
    a.accept(
        Some(vec![Header::ContentType("application/sdp".into())]),
        Some(response.body),
    )
    .required()?;
    a_stack
        .state("A confirmed", |s| matches!(s, DialogState::Confirmed(..)))
        .await?;
    b_stack
        .state("B confirmed", |s| matches!(s, DialogState::Confirmed(..)))
        .await?;
    a_peer.wait_text("state changed to CONFIRMED").await?;
    b_peer.wait_text("state changed to CONFIRMED").await?;
    let bridge = ReinviteBridge::new(a.clone(), b.clone()).required()?;
    check!(
        a.id().call_id != b.id().call_id,
        "B2BUA legs must have independent Call-IDs"
    );
    let (source, destination, initiator) = if reverse {
        (&b_stack, &a_stack, &mut b_peer)
    } else {
        (&a_stack, &b_stack, &mut a_peer)
    };
    for command in ["H\n", "v\n"] {
        let source_offset = source.wire.checkpoint();
        let destination_offset = destination.wire.checkpoint();
        let state_offset = source
            .states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        initiator.command(command).await?;
        let (id, request, handle) = until("incoming bridge re-INVITE", || {
            source
                .states
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .skip(state_offset)
                .find_map(|s| {
                    if let DialogState::Updated(id, request, handle) = s {
                        (request.method == Method::Invite)
                            .then(|| (id.clone(), request.clone(), handle.clone()))
                    } else {
                        None
                    }
                })
        })
        .await?;
        let status = bounded(
            "bridged PJSUA re-INVITE",
            bridge.handle(id, request.clone(), handle),
        )
        .await?
        .required()?;
        check_eq!(status.code(), 200);
        let forwarded = destination
            .wire
            .request_after(true, Method::Invite, destination_offset)
            .await?;
        check_eq!(forwarded.body, request.body);
        check!(forwarded.call_id_header().required()? != request.call_id_header().required()?);
        let answer = until_result("relayed SDP answer", || {
            for packet in source
                .wire
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .skip(source_offset)
            {
                if let SipMessage::Response(r) = &packet.message {
                    if packet.sent
                        && r.status_code.code() == 200
                        && r.cseq_header().required()?.method().required()? == Method::Invite
                    {
                        return Ok(Some(r.clone()));
                    }
                }
            }
            Ok(None)
        })
        .await?;
        let text = String::from_utf8_lossy(&answer.body);
        check!(
            text.contains(if command == "H\n" {
                "a=recvonly"
            } else {
                "a=sendrecv"
            }),
            "Unexpected answer: {text}"
        );
        let incoming_ack = source
            .wire
            .request_after(false, Method::Ack, source_offset)
            .await?;
        let outgoing_ack = destination
            .wire
            .request_after(true, Method::Ack, destination_offset)
            .await?;
        check_eq!(
            incoming_ack.cseq_header().required()?.seq().required()?,
            request.cseq_header().required()?.seq().required()?
        );
        check_eq!(
            outgoing_ack.cseq_header().required()?.seq().required()?,
            forwarded.cseq_header().required()?.seq().required()?
        );
        check!(a.state().is_confirmed() && b.state().is_confirmed());
    }
    bridge.shutdown();
    a_peer.command("h\n").await?;
    a_stack
        .state("A ended", |s| matches!(s, DialogState::Terminated(..)))
        .await?;
    bounded("forward teardown to B", b.bye())
        .await?
        .required()?;
    b_stack
        .state("B ended", |s| matches!(s, DialogState::Terminated(..)))
        .await?;
    a_peer.wait_text("is DISCONNECTED").await?;
    b_peer.wait_text("is DISCONNECTED").await?;
    a_peer.stop().await?;
    b_peer.stop().await?;
    for (stack, path) in [(&a_stack, &a_dir), (&b_stack, &b_dir)] {
        until("empty bridge dialog registry", || {
            stack.layer.is_empty().then_some(())
        })
        .await?;
        let ended = stack
            .states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|s| matches!(s, DialogState::Terminated(..)))
            .count();
        check_eq!(ended, 1);
        stack
            .finish(path, format!("{name}: bridge hold/resume and teardown\n"))
            .await?;
    }
    Ok(())
}

macro_rules! cases {
    ($($name:ident, $transport:literal, $reverse:expr;)*) => {$(
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh pjsip bridge"]
        async fn $name() -> TestResult { scenario(stringify!($name), $transport, $reverse).await }
    )*};
}
cases! {
    udp_bridge_a_to_b_hold_resume, "udp", false;
    udp_bridge_b_to_a_hold_resume, "udp", true;
    tcp_bridge_a_to_b_hold_resume, "tcp", false;
    tcp_bridge_b_to_a_hold_resume, "tcp", true;
}
