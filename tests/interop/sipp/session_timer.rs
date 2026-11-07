//! Fast RFC 4028 wire exchanges with an independent SIPp peer. Scheduler and
//! expiry tests use virtual time in the library; these tests never shorten SE.
use super::Sipp;
use crate::interop::{bounded, log_dir, sdp, until, Required, Stack, TestResult};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption, session_timer::SessionTimerConfig},
    sip::{Header, HeadersExt, Method, StatusCode},
};

async fn scenario(name: &str, transport: &str, server: bool, reinvite: bool) -> TestResult {
    let dir = log_dir(name)?;
    let mut stack = Stack::start(transport, &dir).await?;
    stack
        .layer
        .set_session_timer(Some(SessionTimerConfig {
            expires: 90,
            ..Default::default()
        }))
        .required()?;
    let kind = format!(
        "session_{}_{}",
        if server { "uas" } else { "uac" },
        if reinvite { "invite" } else { "update" }
    );
    let mut peer = Sipp::start(&kind, transport, &dir, &stack.uri).await?;
    let dialog = if server {
        let dialog = peer
            .guarded("INVITE", stack.incoming.recv())
            .await?
            .required()?;
        dialog
            .accept(
                Some(vec![Header::ContentType("application/sdp".into())]),
                Some(sdp()),
            )
            .required()?;
        if reinvite {
            let handle = until("refresh offer", || {
                stack
                    .states
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .find_map(|s| {
                        if let DialogState::Updated(_, r, h) = s {
                            (r.method == Method::Invite).then(|| h.clone())
                        } else {
                            None
                        }
                    })
            })
            .await?;
            handle
                .respond(
                    StatusCode::OK,
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(sdp()),
                )
                .await
                .required()?;
        }
        peer.marker("TIMER_REFRESHED").await?;
        let status = dialog.session_timer_status().required()?;
        check_eq!(status.interval, Some(120));
        check!(status.local_refresher);
        dialog
    } else {
        let (dialog, task) = stack
            .layer
            .do_invite_async(
                InviteOption {
                    caller: stack.uri.clone(),
                    contact: stack.uri.clone(),
                    callee: peer.uri.clone(),
                    offer: Some(sdp()),
                    ..Default::default()
                },
                stack.sender.clone(),
            )
            .required()?;
        peer.guarded("INVITE with 422 retry", task)
            .await?
            .required()?
            .required()?;
        check_eq!(
            dialog.session_timer_status().required()?.interval,
            Some(120)
        );
        let response = if reinvite {
            let r = dialog
                .prepare_reinvite(
                    Some(vec![Header::ContentType("application/sdp".into())]),
                    Some(sdp()),
                )
                .required()?;
            bounded(
                "re-INVITE refresh",
                dialog.send_reinvite(r, Default::default()),
            )
            .await?
            .required()?
            .required()?
        } else {
            bounded("UPDATE refresh", dialog.update(None, None))
                .await?
                .required()?
                .required()?
        };
        check_eq!(response.status_code.code(), 200);
        check_eq!(
            dialog.session_timer_status().required()?.interval,
            Some(180)
        );
        let requests = super::extended::sent_requests(&stack, Method::Invite);
        check!(requests.len() >= 2);
        check_eq!(
            requests[0].call_id_header().required()?,
            requests[1].call_id_header().required()?
        );
        check_eq!(
            requests[1].cseq_header().required()?.seq().required()?,
            requests[0].cseq_header().required()?.seq().required()? + 1
        );
        check!(requests[0].via_header().required()? != requests[1].via_header().required()?);
        bounded("BYE", dialog.bye()).await?.required()?;
        dialog
    };
    peer.finish().await?;
    until("timer and dialog cleanup", || {
        (stack.layer.is_empty()
            && dialog
                .session_timer_status()
                .is_some_and(|s| !s.worker_running))
        .then_some(())
    })
    .await?;
    stack
        .finish(
            &dir,
            format!("{name}: RFC 4028 negotiated, refreshed, and stopped\n"),
        )
        .await
}
macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $server:literal, $reinvite:literal)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp session_timer"]
        async fn $udp() -> TestResult { scenario(stringify!($udp), "udp", $server, $reinvite).await }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp session_timer"]
        async fn $tcp() -> TestResult { scenario(stringify!($tcp), "tcp", $server, $reinvite).await }
    )*};
}
cases! {
    (udp_session_timer_uac_update, tcp_session_timer_uac_update, false, false),
    (udp_session_timer_uac_reinvite, tcp_session_timer_uac_reinvite, false, true),
    (udp_session_timer_uas_update, tcp_session_timer_uas_update, true, false),
    (udp_session_timer_uas_reinvite, tcp_session_timer_uas_reinvite, true, true),
}
