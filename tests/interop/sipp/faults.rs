//! Packet gates establish the ordering; wall-clock sleeps do not trigger races.
use super::Sipp;
use crate::interop::{
    bounded,
    faults::{Action, Control, Direction, Rule, Trace},
    log_dir, sdp, until, Required, Stack, TestResult,
};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption},
    sip::{prelude::HeadersExt, Method, SipMessage},
};

#[derive(Clone, Copy)]
enum Race {
    RemoteByeBlockedAck,
    RemoteByeHeldAck,
    WrongBye,
    LocalBye,
    Cancel200,
    CrossedBye,
}

fn packet(
    trace: &Trace,
    direction: Direction,
    phase: &str,
    method: Method,
    status: Option<u16>,
) -> bool {
    trace.direction == direction
        && trace.phase == phase
        && match &trace.message {
            Some(SipMessage::Request(r)) => r.method == method && status.is_none(),
            Some(SipMessage::Response(r)) => {
                Some(r.status_code.code()) == status
                    && r.cseq_header().and_then(|h| h.method()).ok() == Some(method)
            }
            _ => false,
        }
}

fn ordered(
    control: &Control,
    a: (Direction, Method, Option<u16>),
    b: (Direction, Method, Option<u16>),
) -> TestResult {
    let traces = control.traces();
    let first = traces
        .iter()
        .position(|t| packet(t, a.0, "delivered", a.1, a.2))
        .required()?;
    let second = traces
        .iter()
        .position(|t| packet(t, b.0, "delivered", b.1, b.2))
        .required()?;
    check!(
        first < second,
        "Unexpected wire ordering: {a:?} must precede {b:?}"
    );
    Ok(())
}

async fn scenario(name: &str, race: Race) -> TestResult {
    let dir = log_dir(name)?;
    let (xml, rules) = match race {
        Race::Cancel200 => (
            "fault_cancel_crossed_200",
            vec![Rule::new(
                "answer",
                Direction::Receive,
                Method::Invite,
                Some(200),
                1,
                Action::Hold,
            )],
        ),
        Race::CrossedBye => (
            "fault_crossed_bye",
            vec![
                Rule::new(
                    "local_bye",
                    Direction::Send,
                    Method::Bye,
                    None,
                    1,
                    Action::Hold,
                ),
                Rule::new(
                    "peer_bye",
                    Direction::Receive,
                    Method::Bye,
                    None,
                    1,
                    Action::Hold,
                ),
            ],
        ),
        Race::LocalBye => (
            "fault_local_bye_after_ack",
            vec![Rule::new(
                "ack",
                Direction::Send,
                Method::Ack,
                None,
                1,
                Action::BlockSend,
            )],
        ),
        _ => (
            if matches!(race, Race::WrongBye) {
                "fault_wrong_bye_before_ack"
            } else {
                "fault_bye_before_ack"
            },
            vec![
                Rule::new(
                    "ack",
                    Direction::Send,
                    Method::Ack,
                    None,
                    1,
                    if matches!(race, Race::RemoteByeHeldAck) {
                        Action::Hold
                    } else {
                        Action::BlockSend
                    },
                ),
                Rule::new(
                    "peer_bye",
                    Direction::Receive,
                    Method::Bye,
                    None,
                    1,
                    Action::Hold,
                ),
            ],
        ),
    };
    let stack = Stack::with_faults(&dir, rules).await?;
    let control = stack.faults.as_ref().required()?;
    let mut peer = Sipp::start(xml, "udp", &dir, &stack.uri).await?;
    let (dialog, mut invite_task) = stack
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
        .required()?;
    let mut invite_joined = false;
    match race {
        Race::Cancel200 => {
            control.applied("answer").await?;
            stack.wire.response(false, Method::Invite, 180).await?;
            bounded("CANCEL while 200 is in flight", dialog.cancel())
                .await?
                .required()?;
            peer.marker("CANCEL_CHECKED").await?;
            stack.wire.response(false, Method::Cancel, 200).await?;
            control.release("answer").await?;
        }
        Race::CrossedBye => {
            bounded("INVITE", &mut invite_task)
                .await?
                .required()?
                .required()?;
            invite_joined = true;
            control.applied("peer_bye").await?;
            let ending = dialog.clone();
            let bye = tokio::spawn(async move { ending.bye().await });
            control.applied("local_bye").await?;
            // Depending on when the library removes a locally ending dialog,
            // RFC 3261 15.1.2 permits 200 for a live dialog or 481 after removal.
            let expected = if matches!(dialog.state(), DialogState::Terminated(..)) {
                481
            } else {
                200
            };
            control.release("peer_bye").await?;
            peer.marker("CROSSED_BYE_ANSWERED").await?;
            stack.wire.response(true, Method::Bye, expected).await?;
            control.release("local_bye").await?;
            bounded("crossed BYE completion", bye)
                .await?
                .required()?
                .required()?;
        }
        Race::LocalBye => {
            control.applied("ack").await?;
            check!(!invite_task.is_finished(), "ACK send is not blocked");
            check!(
                matches!(dialog.state(), DialogState::Confirmed(..)),
                "Receiving 200 must establish the dialog before ACK completes"
            );
            let bye = dialog.bye();
            tokio::pin!(bye);
            tokio::select! {
                biased;
                result = &mut bye => { result.required()?; return Err(crate::interop::Failure("Local BYE completed while ACK was blocked".into())); }
                () = tokio::task::yield_now() => {}
            }
            check!(
                !control.traces().iter().any(|t| packet(
                    t,
                    Direction::Send,
                    "observed",
                    Method::Bye,
                    None
                )),
                "Local BYE overtook ACK"
            );
            control.release("ack").await?;
            bounded("BYE after ACK", bye).await?.required()?;
        }
        _ => {
            control.applied("ack").await?;
            control.applied("peer_bye").await?;
            if matches!(race, Race::RemoteByeHeldAck) {
                bounded("INVITE completed with ACK in flight", &mut invite_task)
                    .await?
                    .required()?
                    .required()?;
                invite_joined = true;
            } else {
                check!(!invite_task.is_finished(), "ACK send is not blocked");
            }
            check!(!control.traces().iter().any(|t| packet(
                t,
                Direction::Send,
                "delivered",
                Method::Ack,
                None
            )));
            control.release("peer_bye").await?;
            peer.marker(if matches!(race, Race::WrongBye) {
                "WRONG_BYE_REJECTED"
            } else {
                "BYE_ACCEPTED"
            })
            .await?;
            if matches!(race, Race::WrongBye) {
                check!(
                    !matches!(dialog.state(), DialogState::Terminated(..)),
                    "Wrong-tag BYE terminated the call"
                );
            } else {
                stack
                    .state("termination before ACK release", |s| {
                        matches!(s, DialogState::Terminated(..))
                    })
                    .await?;
            }
            control.release("ack").await?;
        }
    }
    if !invite_joined {
        bounded("INVITE driver", invite_task)
            .await?
            .required()?
            .required()?;
    }
    peer.finish().await?;
    stack
        .state("terminated dialog", |s| {
            matches!(s, DialogState::Terminated(..))
        })
        .await?;
    until("empty registry", || stack.layer.is_empty().then_some(())).await?;
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
            usize::from(!matches!(race, Race::Cancel200))
        );
        if !matches!(race, Race::Cancel200) {
            let answered = states
                .iter()
                .position(|s| matches!(s, DialogState::Confirmed(..)))
                .required()?;
            let ended = states
                .iter()
                .position(|s| matches!(s, DialogState::Terminated(..)))
                .required()?;
            check!(
                answered < ended,
                "Answer must precede termination; ACK completion must not resurrect the dialog"
            );
        }
    }
    match race {
        Race::RemoteByeBlockedAck | Race::RemoteByeHeldAck => ordered(
            control,
            (Direction::Send, Method::Bye, Some(200)),
            (Direction::Send, Method::Ack, None),
        )?,
        Race::WrongBye => ordered(
            control,
            (Direction::Send, Method::Bye, Some(481)),
            (Direction::Send, Method::Ack, None),
        )?,
        Race::Cancel200 => {
            ordered(
                control,
                (Direction::Send, Method::Cancel, None),
                (Direction::Receive, Method::Invite, Some(200)),
            )?;
            ordered(
                control,
                (Direction::Send, Method::Ack, None),
                (Direction::Send, Method::Bye, None),
            )?;
        }
        Race::LocalBye => ordered(
            control,
            (Direction::Send, Method::Ack, None),
            (Direction::Send, Method::Bye, None),
        )?,
        Race::CrossedBye => {
            let response = control
                .traces()
                .into_iter()
                .find(|t| {
                    packet(t, Direction::Send, "delivered", Method::Bye, Some(200))
                        || packet(t, Direction::Send, "delivered", Method::Bye, Some(481))
                })
                .required()?;
            let code = match response.message.required()? {
                SipMessage::Response(r) => r.status_code.code(),
                _ => return Err(crate::interop::Failure("Expected BYE response".into())),
            };
            ordered(
                control,
                (Direction::Send, Method::Bye, Some(code)),
                (Direction::Send, Method::Bye, None),
            )?;
        }
    }
    stack
        .finish(&dir, format!("{name}: deterministic UDP race\n"))
        .await
}

macro_rules! cases {
    ($(($name:ident, $race:ident)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh faults"]
        async fn $name() -> TestResult { scenario(stringify!($name), Race::$race).await }
    )*};
}
cases! {
    (udp_known_gap_remote_bye_during_blocked_ack, RemoteByeBlockedAck),
    (udp_remote_bye_during_held_ack, RemoteByeHeldAck),
    (udp_wrong_tag_bye_during_blocked_ack, WrongBye),
    (udp_known_gap_local_bye_waits_for_blocked_ack, LocalBye),
    (udp_cancel_crossed_held_200, Cancel200),
    (udp_crossed_held_byes, CrossedBye),
}
