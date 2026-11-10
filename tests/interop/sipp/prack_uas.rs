use super::{log_dir, sdp, until, Sipp, Stack};
use crate::interop::{Required, TestResult};
use rsipstack::{
    dialog::{
        dialog::DialogState,
        reliable::{
            IncomingPrack, PrackBody, PrackHandler, ReliableProvisionalConfig, ReliableResponse,
            SdpKind,
        },
    },
    sip::{Header, Method},
};

/// The test owns SDP negotiation; rsipstack owns reliable signaling.
pub(super) struct Media;
#[async_trait::async_trait]
impl PrackHandler for Media {
    async fn on_reliable_response(
        &self,
        event: ReliableResponse,
    ) -> rsipstack::Result<Option<PrackBody>> {
        Ok((event.sdp_kind == SdpKind::Offer).then(|| PrackBody::sdp(sdp())))
    }
    async fn on_prack(&self, event: IncomingPrack) -> rsipstack::Result<Option<PrackBody>> {
        Ok((event.sdp_kind == SdpKind::Offer).then(|| PrackBody::sdp(sdp())))
    }
}
pub(super) fn enable(stack: &Stack) {
    stack
        .layer
        .set_reliable_provisional(Some(ReliableProvisionalConfig::new(std::sync::Arc::new(
            Media,
        ))));
}

async fn scenario(
    name: &str,
    transport: &str,
    rack: Option<&str>,
    expected: u16,
    retransmit: bool,
) -> TestResult {
    let dir = log_dir(name)?;
    let mut stack = Stack::start(transport, &dir).await?;
    enable(&stack);
    let keys = [
        (
            "rack_line",
            rack.map(|r| format!("RAck: {r}\n")).unwrap_or_default(),
        ),
        ("prack_status", expected.to_string()),
        ("bye_cseq", if expected == 200 { "3" } else { "4" }.into()),
    ];
    let mut peer = Sipp::start_with_keys(
        if retransmit {
            "prack_uas_retransmit"
        } else if expected != 200 {
            "prack_uas_reject"
        } else {
            "prack_uas"
        },
        transport,
        &dir,
        &stack.uri,
        &keys,
    )
    .await?;
    let dialog = peer
        .guarded("incoming INVITE", stack.incoming.recv())
        .await?
        .required()?;
    dialog
        .ringing(
            Some(vec![
                Header::Require("100rel".into()),
                Header::ContentType("application/sdp".into()),
            ]),
            Some(sdp()),
        )
        .required()?;
    peer.marker("PRACK_CHECKED").await?;
    stack.wire.response(true, Method::PRack, expected).await?;
    dialog
        .accept(
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(sdp()),
        )
        .required()?;
    peer.finish().await?;
    stack
        .state("terminated", |s| matches!(s, DialogState::Terminated(..)))
        .await?;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await?;
    check_eq!(
        stack.wire.requests(Method::PRack),
        if expected == 200 { 1 } else { 2 }
    );
    stack
        .finish(&dir, format!("{name}: UAS PRACK over {transport}\n"))
        .await?;
    Ok(())
}

macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $rack:expr, $status:literal, $retransmit:literal)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp prack"]
        async fn $udp() -> TestResult { scenario(stringify!($udp), "udp", $rack, $status, $retransmit).await }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp prack"]
        async fn $tcp() -> TestResult { scenario(stringify!($tcp), "tcp", $rack, $status, $retransmit).await }
    )*};
}
cases! {
    (udp_prack_uas_valid, tcp_prack_uas_valid, Some("[$rseq] 1 INVITE"), 200, false),
    (udp_prack_uas_missing_rack, tcp_prack_uas_missing_rack, None, 400, false),
    (udp_prack_uas_wrong_rseq, tcp_prack_uas_wrong_rseq, Some("2147483648 1 INVITE"), 481, false),
    (udp_prack_uas_wrong_cseq, tcp_prack_uas_wrong_cseq, Some("[$rseq] 999 INVITE"), 481, false),
    (udp_prack_uas_retransmit, tcp_prack_uas_retransmit, Some("[$rseq] 1 INVITE"), 200, true),
}
