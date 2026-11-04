//! Exercise public dialog operations against PJSUA's real call state machine.
use super::{scenario, Outcome};
use crate::interop::{bounded, sdp, until, until_result, Peer, Required, Stack, TestResult};
use rsipstack::{
    dialog::{dialog::DialogState, invite_dialog::InviteDialog},
    sip::{prelude::HeadersExt, Header, Method, Request, SipMessage, StatusCode},
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Activity {
    LocalHoldResume,
    PeerHoldResume,
    LocalUpdate,
    PeerUpdate,
    OptionsRejected,
    LocalInfo,
    PeerInfo,
    LocalMessage,
    ReinviteRejected,
}

impl Activity {
    pub(super) fn extra_confirmations(self) -> usize {
        match self {
            Self::PeerHoldResume => 2,
            Self::PeerUpdate | Self::PeerInfo => 1,
            _ => 0,
        }
    }
}

pub(super) fn offer(version: u32, direction: &str) -> TestResult<Vec<u8>> {
    Ok(String::from_utf8(sdp())
        .required()?
        .replace("o=- 1 1", &format!("o=- 1 {version}"))
        .replace("a=inactive", &format!("a={direction}"))
        .into_bytes())
}

fn sdp_headers() -> Option<Vec<Header>> {
    Some(vec![Header::ContentType("application/sdp".into())])
}

fn same_dialog(request: &Request, initial: &Request) -> TestResult {
    check_eq!(
        request.call_id_header().required()?,
        initial.call_id_header().required()?
    );
    check!(request
        .from_header()
        .required()?
        .tag()
        .required()?
        .is_some());
    check!(request.to_header().required()?.tag().required()?.is_some());
    Ok(())
}

async fn response_and_ack(
    stack: &Stack,
    request: &Request,
    sent: bool,
    code: u16,
    offset: usize,
) -> TestResult {
    until_result("matching in-dialog response", || {
        for packet in stack
            .wire
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .skip(offset)
        {
            if let SipMessage::Response(response) = &packet.message {
                if packet.sent != sent
                    && response.status_code.code() == code
                    && response.call_id_header().required()?
                        == request.call_id_header().required()?
                    && response.cseq_header().required()? == request.cseq_header().required()?
                {
                    return Ok(Some(()));
                }
            }
        }
        Ok(None)
    })
    .await?;
    if request.method == Method::Invite {
        let ack = stack.wire.request_after(sent, Method::Ack, offset).await?;
        same_dialog(&ack, request)?;
        check_eq!(
            ack.cseq_header().required()?.seq().required()?,
            request.cseq_header().required()?.seq().required()?
        );
        check_eq!(
            ack.from_header().required()?.tag().required()?,
            request.from_header().required()?.tag().required()?
        );
    }
    Ok(())
}

pub(super) async fn exercise(
    activity: Activity,
    dialog: &InviteDialog,
    stack: &Stack,
    peer: &mut Peer,
) -> TestResult {
    let initial = dialog.initial_request();
    let peer_initiates = matches!(
        activity,
        Activity::PeerHoldResume | Activity::PeerUpdate | Activity::PeerInfo
    );
    let steps = if matches!(
        activity,
        Activity::LocalHoldResume | Activity::PeerHoldResume | Activity::ReinviteRejected
    ) {
        2
    } else {
        1
    };
    let mut previous_seq = None;
    for step in 0..steps {
        let offset = stack.wire.checkpoint();
        let states_before = stack.states.lock().unwrap_or_else(|p| p.into_inner()).len();
        let peer_output = peer.output_len();
        let method = match activity {
            Activity::LocalUpdate | Activity::PeerUpdate => Method::Update,
            Activity::OptionsRejected => Method::Options,
            Activity::LocalInfo | Activity::PeerInfo => Method::Info,
            Activity::LocalMessage => Method::Message,
            _ => Method::Invite,
        };
        let version = 2 + step;
        // The pinned PJSUA rejects in-dialog OPTIONS with 500 and also uses
        // 500 when SDP codec negotiation fails. Check rsipstack's recovery,
        // not OPTIONS support or a specific RFC rejection recommendation.
        let expected_code = if matches!(activity, Activity::OptionsRejected)
            || (matches!(activity, Activity::ReinviteRejected) && step == 0)
        {
            500
        } else {
            200
        };
        let request;
        if peer_initiates {
            let command = match activity {
                Activity::PeerHoldResume if step == 0 => "H\n",
                Activity::PeerHoldResume => "v\n",
                Activity::PeerUpdate => "U\n",
                Activity::PeerInfo => "*\n5\n",
                _ => return Err(crate::interop::Failure("Invalid PJSUA activity".into())),
            };
            peer.command(command).await?;
            let (received, handle) = until("application event for PJSUA request", || {
                stack
                    .states
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .skip(states_before)
                    .find_map(|state| match state {
                        DialogState::Updated(_, request, handle)
                        | DialogState::Info(_, request, handle)
                            if request.method == method =>
                        {
                            Some((request.clone(), handle.clone()))
                        }
                        _ => None,
                    })
            })
            .await?;
            request = received;
            if method == Method::Info {
                check!(String::from_utf8_lossy(&request.body).contains("Signal=5"));
                handle.reply(StatusCode::OK).await.required()?;
            } else {
                let direction = if matches!(activity, Activity::PeerHoldResume) && step == 0 {
                    "recvonly"
                } else {
                    "sendrecv"
                };
                let received_sdp = String::from_utf8_lossy(&request.body);
                check!(received_sdp.contains("m=audio"));
                if matches!(activity, Activity::PeerHoldResume) {
                    check!(
                        received_sdp.contains(if step == 0 {
                            "a=sendonly"
                        } else {
                            "a=sendrecv"
                        }),
                        "Unexpected PJSUA SDP: {received_sdp}"
                    );
                }
                handle
                    .respond(
                        StatusCode::OK,
                        sdp_headers(),
                        Some(offer(version, direction)?),
                    )
                    .await
                    .required()?;
            }
            response_and_ack(stack, &request, false, expected_code, offset).await?;
            until("dialog confirmed after application response", || {
                stack
                    .states
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .skip(states_before)
                    .any(|s| matches!(s, DialogState::Confirmed(..)))
                    .then_some(())
            })
            .await?;
        } else {
            let (headers, body) = match activity {
                Activity::OptionsRejected => (None, None),
                Activity::LocalInfo => (Some(vec![Header::ContentType("application/dtmf-relay".into())]), Some(b"Signal=5\r\nDuration=160\r\n".to_vec())),
                Activity::LocalMessage => (Some(vec![Header::ContentType("text/plain".into())]), Some(b"interop message".to_vec())),
                Activity::ReinviteRejected if step == 0 => (sdp_headers(), Some(b"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=interop\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9 RTP/AVP 127\r\na=rtpmap:127 unsupported-codec/8000\r\n".to_vec())),
                _ => (sdp_headers(), Some(offer(version, if matches!(activity, Activity::LocalHoldResume) && step == 0 { "sendonly" } else { "sendrecv" })?)),
            };
            let response = bounded(
                "PJSUA in-dialog response",
                dialog.request(method, headers, body),
            )
            .await?
            .required()?
            .required()?;
            check_eq!(response.status_code.code(), expected_code);
            request = stack.wire.request_after(true, method, offset).await?;
            response_and_ack(stack, &request, true, expected_code, offset).await?;
            if matches!(activity, Activity::LocalHoldResume | Activity::LocalUpdate) {
                let answer = String::from_utf8_lossy(&response.body);
                check!(answer.contains("m=audio"));
                if matches!(activity, Activity::LocalHoldResume) {
                    check!(
                        answer.contains(if step == 0 {
                            "a=recvonly"
                        } else {
                            "a=sendrecv"
                        }),
                        "Unexpected PJSUA answer: {answer}"
                    );
                }
            }
            if matches!(activity, Activity::LocalInfo) {
                peer.wait_text_after(
                    "Incoming DTMF on call 0: 5:duration(160), using SIP INFO method",
                    peer_output,
                )
                .await?;
            } else if matches!(activity, Activity::LocalMessage) {
                peer.wait_text_after(": interop message (text/plain)", peer_output)
                    .await?;
            }
        }
        same_dialog(&request, &initial)?;
        let id = dialog.id();
        let (from, to) = if peer_initiates {
            (&id.remote_tag, &id.local_tag)
        } else {
            (&id.local_tag, &id.remote_tag)
        };
        check_eq!(
            request
                .from_header()
                .required()?
                .tag()
                .required()?
                .required()?
                .value(),
            from
        );
        check_eq!(
            request
                .to_header()
                .required()?
                .tag()
                .required()?
                .required()?
                .value(),
            to
        );
        let seq = request.cseq_header().required()?.seq().required()?;
        if request.from_header().required()?.tag().required()?
            == initial.from_header().required()?.tag().required()?
        {
            check!(
                seq > initial.cseq_header().required()?.seq().required()?,
                "In-dialog CSeq must exceed the initial INVITE"
            );
        }
        if let Some(previous) = previous_seq {
            check!(seq > previous, "CSeq must advance");
        }
        previous_seq = Some(seq);
        check!(matches!(dialog.state(), DialogState::Confirmed(..)));
        check!(!stack
            .states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|s| matches!(s, DialogState::Terminated(..))));
    }
    Ok(())
}

macro_rules! cases {
    ($(($uac_udp:ident, $uac_tcp:ident, $uas_udp:ident, $uas_tcp:ident, $activity:ident)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh pjsip mid_dialog"]
        async fn $uac_udp() -> TestResult { scenario(stringify!($uac_udp), "udp", true, Outcome::Activity(Activity::$activity)).await }
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh pjsip mid_dialog"]
        async fn $uac_tcp() -> TestResult { scenario(stringify!($uac_tcp), "tcp", true, Outcome::Activity(Activity::$activity)).await }
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh pjsip mid_dialog"]
        async fn $uas_udp() -> TestResult { scenario(stringify!($uas_udp), "udp", false, Outcome::Activity(Activity::$activity)).await }
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh pjsip mid_dialog"]
        async fn $uas_tcp() -> TestResult { scenario(stringify!($uas_tcp), "tcp", false, Outcome::Activity(Activity::$activity)).await }
    )*};
}

cases! {
    (udp_uac_local_hold_resume, tcp_uac_local_hold_resume, udp_uas_local_hold_resume, tcp_uas_local_hold_resume, LocalHoldResume),
    (udp_uac_peer_hold_resume, tcp_uac_peer_hold_resume, udp_uas_peer_hold_resume, tcp_uas_peer_hold_resume, PeerHoldResume),
    (udp_uac_local_update, tcp_uac_local_update, udp_uas_local_update, tcp_uas_local_update, LocalUpdate),
    (udp_uac_peer_update, tcp_uac_peer_update, udp_uas_peer_update, tcp_uas_peer_update, PeerUpdate),
    (udp_uac_options_rejected, tcp_uac_options_rejected, udp_uas_options_rejected, tcp_uas_options_rejected, OptionsRejected),
    (udp_uac_local_info, tcp_uac_local_info, udp_uas_local_info, tcp_uas_local_info, LocalInfo),
    (udp_uac_peer_info, tcp_uac_peer_info, udp_uas_peer_info, tcp_uas_peer_info, PeerInfo),
    (udp_uac_message, tcp_uac_message, udp_uas_message, tcp_uas_message, LocalMessage),
    (udp_uac_reinvite_rejected, tcp_uac_reinvite_rejected, udp_uas_reinvite_rejected, tcp_uas_reinvite_rejected, ReinviteRejected),
}
