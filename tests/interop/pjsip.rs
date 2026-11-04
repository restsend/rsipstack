mod faults;
mod mid_dialog;
use super::{bounded, log_dir, sdp, until, Peer, Stack};
use crate::interop::{Required, TestResult};
use mid_dialog::Activity;
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
    Activity(Activity),
}

async fn scenario(name: &str, transport: &str, rsip_calls: bool, outcome: Outcome) -> TestResult {
    scenario_with_faults(name, transport, rsip_calls, outcome, None).await
}

async fn scenario_with_faults(
    name: &str,
    transport: &str,
    rsip_calls: bool,
    outcome: Outcome,
    rules: Option<Vec<crate::interop::faults::Rule>>,
) -> TestResult {
    let dir = log_dir(name)?;
    let mut peer = Peer::start(transport, &dir).await?;
    let mut stack = if let Some(rules) = rules {
        Stack::with_faults(&dir, rules).await?
    } else {
        Stack::start(transport, &dir).await?
    };
    let initial_sdp = if matches!(outcome, Outcome::Activity(_)) {
        mid_dialog::offer(1, "sendrecv")?
    } else {
        sdp()
    };
    let (dialog, invite_task) = if rsip_calls {
        let (d, task) = stack
            .layer
            .do_invite_async(
                InviteOption {
                    caller: stack.uri.clone(),
                    callee: peer.uri.clone(),
                    contact: stack.uri.clone(),
                    offer: Some(initial_sdp.clone()),
                    ..Default::default()
                },
                stack.sender.clone(),
            )
            .required()?;
        stack.wire.response(false, Method::Invite, 180).await?;
        (d, Some(task))
    } else {
        peer.command(&format!("m\n{}\n", stack.uri)).await?;
        let d = bounded("incoming dialog", stack.incoming.recv())
            .await?
            .required()?;
        d.ringing(None, None).required()?;
        (d, None)
    };
    peer.wait_text("state changed to EARLY").await?;
    let invite = stack.wire.request(rsip_calls, Method::Invite).await?;
    check!(invite
        .via_header()
        .required()?
        .value()
        .contains(&format!("SIP/2.0/{}", transport.to_uppercase())));

    let established = !matches!(outcome, Outcome::Cancel | Outcome::Busy);
    if established {
        if rsip_calls {
            peer.command("a\n200\n").await?;
        } else {
            dialog
                .accept(
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(initial_sdp),
                )
                .required()?;
        }
        stack
            .state("confirmed dialog", |s| {
                matches!(s, DialogState::Confirmed(..))
            })
            .await?;
        peer.wait_text("state changed to CONFIRMED").await?;
    } else {
        match (rsip_calls, outcome) {
            (true, Outcome::Busy) => peer.command("a\n486\n").await?,
            (false, Outcome::Busy) => dialog.reject(Some(StatusCode::BusyHere), None).required()?,
            (true, Outcome::Cancel) => bounded("send CANCEL", dialog.cancel()).await?.required()?,
            (false, Outcome::Cancel) => peer.command("h\n").await?,
            _ => return Err(crate::interop::Failure("Invalid harness outcome".into())),
        }
    }
    if let Some(task) = invite_task {
        bounded("INVITE driver", task)
            .await?
            .required()?
            .required()?;
    }

    let code = match outcome {
        Outcome::Busy => 486,
        Outcome::Cancel => 487,
        _ => 200,
    };
    let response = stack
        .wire
        .response(!rsip_calls, Method::Invite, code)
        .await?;
    let ack = stack.wire.request(rsip_calls, Method::Ack).await?;
    check_eq!(
        ack.call_id_header().required()?,
        invite.call_id_header().required()?
    );
    check_eq!(
        ack.cseq_header().required()?.seq().required()?,
        invite.cseq_header().required()?.seq().required()?
    );
    check_eq!(
        ack.from_header().required()?.tag().required()?,
        invite.from_header().required()?.tag().required()?
    );
    check_eq!(
        ack.to_header().required()?.tag().required()?,
        response.to_header().required()?.tag().required()?
    );

    if established {
        check!(!response.body.is_empty(), "2xx must carry the SDP answer");
        if let Outcome::Activity(activity) = outcome {
            mid_dialog::exercise(activity, &dialog, &stack, &mut peer).await?;
        }
        let local_bye = !matches!(outcome, Outcome::PeerBye);
        if local_bye {
            bounded("send BYE", dialog.bye()).await?.required()?;
        } else {
            peer.command("h\n").await?;
        }
        let bye = stack.wire.request(local_bye, Method::Bye).await?;
        check_eq!(
            bye.call_id_header().required()?,
            invite.call_id_header().required()?
        );
        let original_from = invite.from_header().required()?.tag().required()?;
        let original_to = response.to_header().required()?.tag().required()?;
        let (from, to) = if local_bye == rsip_calls {
            (original_from, original_to)
        } else {
            (original_to, original_from)
        };
        check_eq!(bye.from_header().required()?.tag().required()?, from);
        check_eq!(bye.to_header().required()?.tag().required()?, to);
        let bye_ok = stack.wire.response(!local_bye, Method::Bye, 200).await?;
        check_eq!(
            bye_ok.cseq_header().required()?,
            bye.cseq_header().required()?
        );
    } else if matches!(outcome, Outcome::Cancel) {
        let cancel = stack.wire.request(rsip_calls, Method::Cancel).await?;
        check_eq!(
            cancel.call_id_header().required()?,
            invite.call_id_header().required()?
        );
        check_eq!(
            cancel.cseq_header().required()?.seq().required()?,
            invite.cseq_header().required()?.seq().required()?
        );
        stack
            .wire
            .response(!rsip_calls, Method::Cancel, 200)
            .await?;
    }
    stack
        .state("terminated dialog", |s| {
            matches!(s, DialogState::Terminated(..))
        })
        .await?;
    peer.wait_text("is DISCONNECTED").await?;
    // PJSUA exits cleanly only after we have observed the expected SIP result.
    if let Some(control) = &stack.faults {
        control.check_retransmissions().await?;
    }
    peer.stop().await?;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await?;
    {
        let states = stack.states.lock().unwrap_or_else(|p| p.into_inner());
        check_eq!(
            states
                .iter()
                .filter(|s| matches!(s, DialogState::Terminated(..)))
                .count(),
            1
        );
        check_eq!(
            states
                .iter()
                .filter(|s| matches!(s, DialogState::Confirmed(..)))
                .count(),
            usize::from(established)
                + match outcome {
                    Outcome::Activity(activity) => activity.extra_confirmations(),
                    _ => 0,
                }
        );
        if !established {
            check_eq!(stack.wire.requests(Method::Bye), 0);
        }
    }
    stack
        .finish(
            &dir,
            format!("{name}: {transport}, rsip_calls={rsip_calls}, {outcome:?}\n"),
        )
        .await?;
    Ok(())
}

macro_rules! interop_case {
    ($name:ident, $transport:literal, $caller:literal, $outcome:ident) => {
        #[tokio::test]
        #[ignore = "requires a separate PJSUA process; use scripts/interop/run.sh"]
        async fn $name() -> TestResult {
            scenario(stringify!($name), $transport, $caller, Outcome::$outcome).await
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
