//! Controlled offerless exchange between two independent SIPp peers.
use super::Sipp;
use crate::interop::{bounded, log_dir, sdp, until, Required, Stack, TestResult};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption, reinvite_bridge::ReinviteBridge},
    sip::{Header, HeadersExt, Method, SipMessage},
};

async fn scenario(name: &str, transport: &str, reverse: bool, lose_ack: bool) -> TestResult {
    let dir = log_dir(name)?;
    let origin_dir = dir.join("origin");
    let destination_dir = dir.join("destination");
    std::fs::create_dir_all(&origin_dir).required()?;
    std::fs::create_dir_all(&destination_dir).required()?;
    let origin = Stack::start(transport, &origin_dir).await?;
    let destination = if lose_ack {
        use crate::interop::faults::{Action, Direction, Rule};
        Stack::with_faults(
            &destination_dir,
            vec![Rule::new(
                "bridge_answer_ack",
                Direction::Send,
                Method::Ack,
                None,
                2,
                Action::Drop,
            )],
        )
        .await?
    } else {
        Stack::start(transport, &destination_dir).await?
    };
    let mut origin_peer = Sipp::start(
        "bridge_offerless_origin",
        transport,
        &origin_dir,
        &origin.uri,
    )
    .await?;
    let mut destination_peer = Sipp::start(
        "bridge_offerless_peer",
        transport,
        &destination_dir,
        &destination.uri,
    )
    .await?;
    let mut dialogs = Vec::new();
    for (stack, peer) in [(&origin, &origin_peer), (&destination, &destination_peer)] {
        let (dialog, task) = stack
            .layer
            .do_invite_async(
                InviteOption {
                    caller: stack.uri.clone(),
                    callee: peer.uri.clone(),
                    contact: stack.uri.clone(),
                    offer: Some(sdp()),
                    content_type: Some("application/sdp".into()),
                    ..Default::default()
                },
                stack.sender.clone(),
            )
            .required()?;
        bounded("initial SIPp dialog", task)
            .await?
            .required()?
            .required()?;
        stack.wire.request(true, Method::Ack).await?;
        dialogs.push(dialog);
    }
    let bridge = if reverse {
        ReinviteBridge::new(dialogs[1].clone(), dialogs[0].clone())
    } else {
        ReinviteBridge::new(dialogs[0].clone(), dialogs[1].clone())
    }
    .required()?;
    let source_offset = origin.wire.checkpoint();
    let target_offset = destination.wire.checkpoint();
    bounded(
        "start offerless re-INVITE",
        dialogs[0].request(Method::Options, None, None),
    )
    .await?
    .required()?;
    let (id, request, handle) = until("SIPp offerless re-INVITE", || {
        origin
            .states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
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
    check!(request.body.is_empty());
    let bridge_task = bridge.clone();
    let task = tokio::spawn(async move { bridge_task.handle(id, request, handle).await });
    origin_peer.marker("BRIDGE_OFFER_RECEIVED").await?;
    {
        let wire = destination.wire.0.lock().unwrap_or_else(|p| p.into_inner());
        check!(!wire.iter().skip(target_offset).any(|p| matches!(&p.message, SipMessage::Request(r) if p.sent && r.method == Method::Ack)), "ACK escaped before the other leg supplied its SDP answer");
    }
    bounded(
        "release ACK answer",
        dialogs[0].request(
            Method::Message,
            Some(vec![Header::ContentType("text/plain".into())]),
            Some(b"answer now".to_vec()),
        ),
    )
    .await?
    .required()?;
    check_eq!(
        bounded("bridge result", task)
            .await?
            .required()?
            .required()?
            .code(),
        200
    );
    destination_peer.marker("BRIDGE_ACK_REPEATED").await?;
    let received = origin
        .wire
        .request_after(false, Method::Ack, source_offset)
        .await?;
    let sent = destination
        .wire
        .request_after(true, Method::Ack, target_offset)
        .await?;
    check_eq!(received.body, sent.body);
    check!(received.call_id_header().required()? != sent.call_id_header().required()?);
    let wire = destination
        .wire
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let acks: Vec<_> = wire
        .iter()
        .skip(target_offset)
        .filter_map(|p| match &p.message {
            SipMessage::Request(r) if p.sent && r.method == Method::Ack => Some(r),
            _ => None,
        })
        .collect();
    check_eq!(acks.len(), if lose_ack { 3 } else { 2 });
    for ack in &acks {
        check_eq!(*ack, acks[0]);
    }
    if let Some(control) = &destination.faults {
        control.check_retransmissions().await?;
    }
    bridge.shutdown();
    for dialog in &dialogs {
        bounded("bridge BYE", dialog.bye()).await?.required()?;
    }
    origin_peer.finish().await?;
    destination_peer.finish().await?;
    for (stack, path) in [(&origin, &origin_dir), (&destination, &destination_dir)] {
        until("empty bridge registry", || {
            stack.layer.is_empty().then_some(())
        })
        .await?;
        stack
            .finish(
                path,
                format!("{name}: offerless bridge and repeated SDP ACK\n"),
            )
            .await?;
    }
    Ok(())
}
macro_rules! cases {
    ($($name:ident, $transport:literal, $reverse:expr;)*) => {$(
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp bridge"]
        async fn $name() -> TestResult { scenario(stringify!($name), $transport, $reverse, false).await }
    )*};
}
cases! {
    udp_bridge_a_to_b_offerless, "udp", false;
    udp_bridge_b_to_a_offerless, "udp", true;
    tcp_bridge_a_to_b_offerless, "tcp", false;
    tcp_bridge_b_to_a_offerless, "tcp", true;
}

mod faults {
    use super::*;
    #[tokio::test]
    #[ignore = "requires SIPp; use scripts/interop/run.sh faults bridge"]
    async fn udp_bridge_offerless_lost_answer_ack() -> TestResult {
        scenario("udp_bridge_offerless_lost_answer_ack", "udp", false, true).await
    }
}
