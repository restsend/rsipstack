use super::{bounded, log_dir, sdp, until, Peer, Stack};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption},
    sip::{prelude::HeadersExt, Header, Method, StatusCode},
};

#[derive(Clone, Copy, Debug)]
enum Outcome {
    LocalBye,
    PeerBye,
    Cancel,
    Busy,
}

async fn scenario(name: &str, transport: &str, rsip_calls: bool, outcome: Outcome) {
    let dir = log_dir(name);
    let mut peer = Peer::start(transport, &dir).await;
    let mut stack = Stack::start(transport, &dir).await;
    let (dialog, invite_task) = if rsip_calls {
        let (d, task) = stack
            .layer
            .do_invite_async(
                InviteOption {
                    caller: stack.uri.clone(),
                    callee: peer.uri.clone(),
                    contact: stack.uri.clone(),
                    offer: Some(sdp()),
                    ..Default::default()
                },
                stack.sender.clone(),
            )
            .unwrap();
        stack.wire.response(false, Method::Invite, 180).await;
        (d, Some(task))
    } else {
        peer.command(&format!("m\n{}\n", stack.uri)).await;
        let d = bounded("incoming dialog", stack.incoming.recv())
            .await
            .expect("incoming dialog channel");
        d.ringing(None, None).unwrap();
        (d, None)
    };
    peer.wait_text("state changed to EARLY").await;
    let invite = stack.wire.request(rsip_calls, Method::Invite).await;
    assert!(invite
        .via_header()
        .unwrap()
        .value()
        .contains(&format!("SIP/2.0/{}", transport.to_uppercase())));

    let established = matches!(outcome, Outcome::LocalBye | Outcome::PeerBye);
    if established {
        if rsip_calls {
            peer.command("a\n200\n").await;
        } else {
            dialog
                .accept(
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(sdp()),
                )
                .unwrap();
        }
        stack
            .state("confirmed dialog", |s| {
                matches!(s, DialogState::Confirmed(..))
            })
            .await;
        peer.wait_text("state changed to CONFIRMED").await;
    } else {
        match (rsip_calls, outcome) {
            (true, Outcome::Busy) => peer.command("a\n486\n").await,
            (false, Outcome::Busy) => dialog.reject(Some(StatusCode::BusyHere), None).unwrap(),
            (true, Outcome::Cancel) => bounded("send CANCEL", dialog.cancel()).await.unwrap(),
            (false, Outcome::Cancel) => peer.command("h\n").await,
            _ => unreachable!(),
        }
    }
    if let Some(task) = invite_task {
        bounded("INVITE driver", task)
            .await
            .expect("INVITE task panicked")
            .expect("INVITE failed");
    }

    let code = match outcome {
        Outcome::Busy => 486,
        Outcome::Cancel => 487,
        _ => 200,
    };
    let response = stack.wire.response(!rsip_calls, Method::Invite, code).await;
    let ack = stack.wire.request(rsip_calls, Method::Ack).await;
    assert_eq!(
        ack.call_id_header().unwrap(),
        invite.call_id_header().unwrap()
    );
    assert_eq!(
        ack.cseq_header().unwrap().seq().unwrap(),
        invite.cseq_header().unwrap().seq().unwrap()
    );
    assert_eq!(
        ack.from_header().unwrap().tag().unwrap(),
        invite.from_header().unwrap().tag().unwrap()
    );
    assert_eq!(
        ack.to_header().unwrap().tag().unwrap(),
        response.to_header().unwrap().tag().unwrap()
    );

    if established {
        assert!(!response.body.is_empty(), "2xx must carry the SDP answer");
        let local_bye = matches!(outcome, Outcome::LocalBye);
        if local_bye {
            bounded("send BYE", dialog.bye()).await.unwrap();
        } else {
            peer.command("h\n").await;
        }
        let bye = stack.wire.request(local_bye, Method::Bye).await;
        assert_eq!(
            bye.call_id_header().unwrap(),
            invite.call_id_header().unwrap()
        );
        let original_from = invite.from_header().unwrap().tag().unwrap();
        let original_to = response.to_header().unwrap().tag().unwrap();
        let (from, to) = if local_bye == rsip_calls {
            (original_from, original_to)
        } else {
            (original_to, original_from)
        };
        assert_eq!(bye.from_header().unwrap().tag().unwrap(), from);
        assert_eq!(bye.to_header().unwrap().tag().unwrap(), to);
        let bye_ok = stack.wire.response(!local_bye, Method::Bye, 200).await;
        assert_eq!(bye_ok.cseq_header().unwrap(), bye.cseq_header().unwrap());
    } else if matches!(outcome, Outcome::Cancel) {
        let cancel = stack.wire.request(rsip_calls, Method::Cancel).await;
        assert_eq!(
            cancel.call_id_header().unwrap(),
            invite.call_id_header().unwrap()
        );
        assert_eq!(
            cancel.cseq_header().unwrap().seq().unwrap(),
            invite.cseq_header().unwrap().seq().unwrap()
        );
        stack.wire.response(!rsip_calls, Method::Cancel, 200).await;
    }
    stack
        .state("terminated dialog", |s| {
            matches!(s, DialogState::Terminated(..))
        })
        .await;
    peer.wait_text("is DISCONNECTED").await;
    // PJSUA exits cleanly only after we have observed the expected SIP result.
    peer.stop().await;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await;
    let states = stack.states.lock().unwrap();
    assert_eq!(
        states
            .iter()
            .filter(|s| matches!(s, DialogState::Terminated(..)))
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|s| matches!(s, DialogState::Confirmed(..)))
            .count(),
        usize::from(established)
    );
    if !established {
        assert_eq!(stack.wire.requests(Method::Bye), 0);
    }
    std::fs::write(
        dir.join("PASS"),
        format!("{name}: {transport}, rsip_calls={rsip_calls}, {outcome:?}\n"),
    )
    .unwrap();
}

macro_rules! interop_case {
    ($name:ident, $transport:literal, $caller:literal, $outcome:ident) => {
        #[tokio::test]
        #[ignore = "requires a separate PJSUA process; use scripts/interop/run.sh"]
        async fn $name() {
            scenario(stringify!($name), $transport, $caller, Outcome::$outcome).await;
        }
    };
}

interop_case!(udp_uac_local_bye, "udp", true, LocalBye);
interop_case!(udp_uac_peer_bye, "udp", true, PeerBye);
interop_case!(udp_uas_local_bye, "udp", false, LocalBye);
interop_case!(udp_uas_peer_bye, "udp", false, PeerBye);
interop_case!(udp_uac_cancel, "udp", true, Cancel);
interop_case!(udp_uas_cancel, "udp", false, Cancel);
interop_case!(udp_uac_busy, "udp", true, Busy);
interop_case!(udp_uas_busy, "udp", false, Busy);
interop_case!(tcp_uac_local_bye, "tcp", true, LocalBye);
interop_case!(tcp_uac_peer_bye, "tcp", true, PeerBye);
interop_case!(tcp_uas_local_bye, "tcp", false, LocalBye);
interop_case!(tcp_uas_peer_bye, "tcp", false, PeerBye);
interop_case!(tcp_uac_cancel, "tcp", true, Cancel);
interop_case!(tcp_uas_cancel, "tcp", false, Cancel);
interop_case!(tcp_uac_busy, "tcp", true, Busy);
interop_case!(tcp_uas_busy, "tcp", false, Busy);
