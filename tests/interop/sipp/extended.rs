use super::{bounded, log_dir, sdp, until, Sipp, Stack};
use rsipstack::{
    dialog::{authenticate::Credential, dialog::DialogState, invitation::InviteOption},
    sip::{prelude::HeadersExt, Header, Method, Request, SipMessage},
};

#[derive(Clone, Copy, Debug)]
enum Case {
    Final(u16),
    NoCredentials(u16),
    Auth(u16, bool, &'static str),
    EarlyMedia,
    InDialog,
    HoldResume,
    ReinviteRejected,
    Update,
    Bye481,
    LateCancel200,
    Prack(&'static str),
    RecordRoute,
    TargetRefresh,
    SessionId,
    Forked200,
}

impl Case {
    fn file(self) -> &'static str {
        match self {
            Self::Final(_) => "final_response",
            Self::NoCredentials(_) => "no_credentials",
            Self::Auth(_, true, _) => "auth_stale",
            Self::Auth(407, false, _) => "auth_proxy",
            Self::Auth(_, false, _) => "auth",
            Self::EarlyMedia => "early_media",
            Self::InDialog => "in_dialog",
            Self::HoldResume => "hold_resume",
            Self::ReinviteRejected => "reinvite_rejected",
            Self::Update => "update",
            Self::Bye481 => "bye_481",
            Self::LateCancel200 => "late_cancel_200",
            Self::Prack(file) => file,
            Self::RecordRoute => "record_route",
            Self::TargetRefresh => "target_refresh",
            Self::SessionId => "session_id",
            Self::Forked200 => "forked_200",
        }
    }

    fn established(self) -> bool {
        !matches!(
            self,
            Self::Final(_) | Self::NoCredentials(_) | Self::LateCancel200
        )
    }

    fn keys(self) -> Vec<(&'static str, String)> {
        match self {
            Self::Final(code) => vec![("final_code", code.to_string())],
            Self::NoCredentials(code) | Self::Auth(code, _, _) => {
                let mut keys = vec![
                    ("challenge_code", code.to_string()),
                    (
                        "challenge_header",
                        if code == 401 {
                            "WWW-Authenticate"
                        } else {
                            "Proxy-Authenticate"
                        }
                        .into(),
                    ),
                ];
                if let Self::Auth(_, _, algorithm) = self {
                    keys.push(("algorithm", algorithm.into()));
                }
                keys
            }
            _ => vec![],
        }
    }
}

pub(super) fn sent_requests(stack: &Stack, method: Method) -> Vec<Request> {
    stack
        .wire
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|p| match &p.message {
            SipMessage::Request(r) if p.sent && r.method == method => Some(r.clone()),
            _ => None,
        })
        .collect()
}

fn assert_alive(stack: &Stack) {
    assert!(!stack
        .states
        .lock()
        .unwrap()
        .iter()
        .any(|s| matches!(s, DialogState::Terminated(..))));
    assert!(!stack.layer.is_empty());
}

async fn scenario(name: &str, transport: &str, case: Case) {
    let dir = log_dir(name);
    let stack = Stack::start(transport, &dir).await;
    let mut peer =
        Sipp::start_with_keys(case.file(), transport, &dir, &stack.uri, &case.keys()).await;
    let credential = matches!(case, Case::Auth(..)).then(|| Credential {
        username: "alice".into(),
        password: "secret".into(),
        realm: Some("interop.test".into()),
        auth_username: None,
    });
    let (dialog, invite_task) = stack
        .layer
        .do_invite_async(
            InviteOption {
                caller: stack.uri.clone(),
                callee: peer.uri.clone(),
                contact: stack.uri.clone(),
                offer: Some(sdp()),
                credential,
                support_prack: matches!(case, Case::Prack(_)),
                session_id: matches!(case, Case::SessionId)
                    .then(|| "1234567890ab4def9234567890abcdef".into()),
                ..Default::default()
            },
            stack.sender.clone(),
        )
        .unwrap();
    if matches!(case, Case::LateCancel200) {
        stack.wire.response(false, Method::Invite, 180).await;
        bounded("CANCEL", dialog.cancel()).await.unwrap();
        stack.wire.response(false, Method::Cancel, 200).await;
    }
    let (_, response) = peer.guarded("INVITE", invite_task).await.unwrap().unwrap();
    let expected = match case {
        Case::Final(code) | Case::NoCredentials(code) => code,
        _ => 200,
    };
    assert_eq!(response.unwrap().status_code.code(), expected);

    match case {
        Case::EarlyMedia => {
            for code in [100, 180, 183] {
                let r = stack.wire.response(false, Method::Invite, code).await;
                if code == 183 {
                    assert!(!r.body.is_empty());
                }
            }
            stack
                .state(
                    "early media notification",
                    |s| matches!(s, DialogState::Early(_, r) if r.status_code.code() == 183),
                )
                .await;
        }
        Case::InDialog => {
            for (method, content_type, body) in [
                (Method::Options, None, None),
                (
                    Method::Info,
                    Some("application/dtmf-relay"),
                    Some(b"Signal=5\r\nDuration=160\r\n".to_vec()),
                ),
                (
                    Method::Message,
                    Some("text/plain"),
                    Some(b"interop message".to_vec()),
                ),
            ] {
                let headers = content_type.map(|c| vec![Header::ContentType(c.into())]);
                let response = bounded("in-dialog request", dialog.request(method, headers, body))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(response.status_code.code(), 200);
                assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
                assert_alive(&stack);
            }
        }
        Case::HoldResume => {
            for (version, direction) in [(2, "sendonly"), (3, "sendrecv")] {
                let offer = String::from_utf8(sdp())
                    .unwrap()
                    .replace("o=- 1 1", &format!("o=- 1 {version}"))
                    .replace("a=inactive", &format!("a={direction}"));
                let response = bounded(
                    "re-INVITE",
                    dialog.reinvite(
                        Some(vec![Header::ContentType("application/sdp".into())]),
                        Some(offer.into_bytes()),
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(response.status_code.code(), 200);
                assert!(!response.body.is_empty());
                assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
                assert_alive(&stack);
            }
        }
        Case::ReinviteRejected => {
            let response = bounded(
                "re-INVITE rejection",
                dialog.reinvite(
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(sdp()),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status_code.code(), 488);
            assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
            assert_alive(&stack);
        }
        Case::Update | Case::TargetRefresh => {
            let response = bounded(
                "UPDATE",
                dialog.update(
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(sdp()),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status_code.code(), 200);
            assert_alive(&stack);
        }
        Case::Forked200 => {
            let response = bounded("release forked answer", dialog.options(None))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status_code.code(), 200);
            peer.marker("FORK_ENDED").await;
            assert_eq!(dialog.id().remote_tag, "sipp-test");
            assert_eq!(stack.layer.len(), 1);
            assert_alive(&stack);
            let response = bounded("primary branch OPTIONS", dialog.options(None))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status_code.code(), 200);
        }
        _ => {}
    }
    if case.established() {
        bounded("BYE", dialog.bye()).await.unwrap();
        stack
            .wire
            .response(
                false,
                Method::Bye,
                if matches!(case, Case::Bye481) {
                    481
                } else {
                    200
                },
            )
            .await;
    }
    peer.finish().await;
    stack
        .state("terminated", |s| matches!(s, DialogState::Terminated(..)))
        .await;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await;

    // ACK every final INVITE response with the corresponding CSeq and Call-ID.
    let invites = sent_requests(&stack, Method::Invite);
    let acks = sent_requests(&stack, Method::Ack);
    let expected_invites = match case {
        Case::Auth(_, stale, _) => {
            if stale {
                3
            } else {
                2
            }
        }
        Case::HoldResume => 3,
        Case::ReinviteRejected => 2,
        _ => 1,
    };
    assert_eq!(invites.len(), expected_invites);
    if matches!(case, Case::Auth(407, ..)) {
        verify_proxy_digest(invites.last().unwrap());
    }
    assert_eq!(
        acks.len(),
        invites.len() + usize::from(matches!(case, Case::Forked200))
    );
    if matches!(case, Case::Forked200) {
        let byes = sent_requests(&stack, Method::Bye);
        assert_eq!(byes.len(), 2);
        assert!(byes[0].uri.to_string().contains("sip:fork@"));
        assert_eq!(
            byes[0].to_header().unwrap().tag().unwrap().unwrap().value(),
            "fork-b"
        );
        assert_eq!(
            byes[1].to_header().unwrap().tag().unwrap().unwrap().value(),
            "sipp-test"
        );
    }
    for (invite, ack) in invites.iter().zip(&acks) {
        assert_eq!(
            invite.call_id_header().unwrap(),
            ack.call_id_header().unwrap()
        );
        assert_eq!(
            invite.cseq_header().unwrap().seq().unwrap(),
            ack.cseq_header().unwrap().seq().unwrap()
        );
        assert_eq!(
            invite.from_header().unwrap().tag().unwrap(),
            ack.from_header().unwrap().tag().unwrap()
        );
    }
    for pair in invites.windows(2) {
        assert_eq!(
            pair[0].call_id_header().unwrap(),
            pair[1].call_id_header().unwrap()
        );
        assert!(
            pair[1].cseq_header().unwrap().seq().unwrap()
                > pair[0].cseq_header().unwrap().seq().unwrap()
        );
    }
    if matches!(case, Case::Final(_) | Case::NoCredentials(_)) {
        assert_eq!(stack.wire.requests(Method::Bye), 0);
    }
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
        usize::from(case.established())
    );
    std::fs::write(
        dir.join("PASS"),
        format!("{name}: {case:?} over {transport}\n"),
    )
    .unwrap();
}

fn verify_proxy_digest(request: &Request) {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut verifier = Command::new("python3")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/verify_digest.py"),
        )
        .stdin(Stdio::piped())
        .spawn()
        .expect("start independent digest verifier");
    verifier
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    assert!(
        verifier.wait().unwrap().success(),
        "Invalid Proxy-Authorization digest"
    );
}

macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $case:expr)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp"]
        async fn $udp() { scenario(stringify!($udp), "udp", $case).await; }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp"]
        async fn $tcp() { scenario(stringify!($tcp), "tcp", $case).await; }
    )*};
}
cases! {
    (udp_invite_403, tcp_invite_403, Case::Final(403)),
    (udp_invite_404, tcp_invite_404, Case::Final(404)),
    (udp_invite_408, tcp_invite_408, Case::Final(408)),
    (udp_invite_480, tcp_invite_480, Case::Final(480)),
    (udp_invite_488, tcp_invite_488, Case::Final(488)),
    (udp_invite_500, tcp_invite_500, Case::Final(500)),
    (udp_invite_503, tcp_invite_503, Case::Final(503)),
    (udp_invite_603, tcp_invite_603, Case::Final(603)),
    (udp_no_credentials_401, tcp_no_credentials_401, Case::NoCredentials(401)),
    (udp_no_credentials_407, tcp_no_credentials_407, Case::NoCredentials(407)),
    (udp_auth_401, tcp_auth_401, Case::Auth(401, false, "MD5")),
    (udp_auth_407, tcp_auth_407, Case::Auth(407, false, "MD5")),
    (udp_auth_stale, tcp_auth_stale, Case::Auth(401, true, "MD5")),
    (udp_known_gap_auth_sha256, tcp_known_gap_auth_sha256, Case::Auth(401, false, "SHA-256")),
    (udp_early_media, tcp_early_media, Case::EarlyMedia),
    (udp_in_dialog, tcp_in_dialog, Case::InDialog),
    (udp_hold_resume, tcp_hold_resume, Case::HoldResume),
    (udp_reinvite_rejected, tcp_reinvite_rejected, Case::ReinviteRejected),
    (udp_update, tcp_update, Case::Update),
    (udp_bye_481, tcp_bye_481, Case::Bye481),
    (udp_late_cancel_200, tcp_late_cancel_200, Case::LateCancel200),
    (udp_prack_basic, tcp_prack_basic, Case::Prack("prack_basic")),
    (udp_prack_duplicate, tcp_prack_duplicate, Case::Prack("prack_duplicate")),
    (udp_prack_sequential, tcp_prack_sequential, Case::Prack("prack_sequential")),
    (udp_known_gap_prack_rseq_gap, tcp_known_gap_prack_rseq_gap, Case::Prack("prack_gap")),
    (udp_record_route, tcp_record_route, Case::RecordRoute),
    (udp_target_refresh, tcp_target_refresh, Case::TargetRefresh),
    (udp_known_gap_session_id, tcp_known_gap_session_id, Case::SessionId),
    (udp_forked_200, tcp_forked_200, Case::Forked200),
}

#[tokio::test]
#[ignore = "requires SIPp; use scripts/interop/run.sh sipp prack_lost_response"]
async fn udp_prack_lost_response() {
    scenario(
        "udp_prack_lost_response",
        "udp",
        Case::Prack("prack_lost_response"),
    )
    .await;
}
