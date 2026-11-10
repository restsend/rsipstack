use super::{bounded, log_dir, sdp, until, Sipp, Stack};
use crate::interop::{Required, TestResult};
use rsipstack::{
    dialog::{
        authenticate::Credential,
        dialog::DialogState,
        invitation::InviteOption,
        reliable::{
            IncomingPrack, PrackBody, PrackHandler, ReliableProvisionalConfig, ReliableResponse,
            SdpKind,
        },
        DialogId,
    },
    sip::{HeadersExt, Method, Request, Response, ToTypedHeader},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Media {
    kinds: Mutex<Vec<SdpKind>>,
    results: Mutex<Vec<Option<Response>>>,
    errors: Mutex<Vec<String>>,
}
#[async_trait::async_trait]
impl PrackHandler for Media {
    async fn on_reliable_response(
        &self,
        event: ReliableResponse,
    ) -> rsipstack::Result<Option<PrackBody>> {
        self.kinds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(event.sdp_kind);
        // Answer an early offer, or make a new offer after receiving an answer.
        Ok(Some(PrackBody::sdp(sdp())))
    }
    async fn on_prack(&self, _: IncomingPrack) -> rsipstack::Result<Option<PrackBody>> {
        Ok(None)
    }
    async fn on_prack_result(&self, _: Request, response: Option<Response>) {
        self.results
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(response);
    }
    async fn on_error(&self, _: DialogId, message: String) {
        self.errors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(message);
    }
}

async fn scenario(
    name: &str,
    transport: &str,
    offered: bool,
    challenge: Option<u16>,
) -> TestResult {
    let dir = log_dir(name)?;
    let stack = Stack::start(transport, &dir).await?;
    let media = Arc::new(Media::default());
    stack
        .layer
        .set_reliable_provisional(Some(ReliableProvisionalConfig::new(media.clone())));
    let challenge_xml = challenge
        .map(|code| {
            format!(
                r#"
  <send><![CDATA[
SIP/2.0 {code} Authentication Required
[last_Via:]
[last_From:]
[last_To:]
[last_Call-ID:]
[last_CSeq:]
{}: Digest realm="interop.test", nonce="interop-1", algorithm=MD5, qop="auth"
Content-Length: 0

]]></send>
  <recv request="PRACK"><action>
    <verifyauth assign_to="valid" username="alice" password="secret"/>
    <ereg regexp="^ *1 1 INVITE" search_in="hdr" header="RAck:" check_it="true" assign_to="_"/>
    <ereg regexp="o=- 1 1" search_in="body" check_it="true" assign_to="_"/>
  </action></recv>
  <nop test="valid" next="valid"/>
  <nop><action><log message="AUTHENTICATION_FAILED"/><exec int_cmd="stop_call"/></action></nop>
  <label id="valid"/>
"#,
                if code == 401 {
                    "WWW-Authenticate"
                } else {
                    "Proxy-Authenticate"
                }
            )
        })
        .unwrap_or_default();
    // SIPp verifyauth reads Authorization only. Verify the proxy digest with
    // the harness's independent Python implementation after the exchange.
    let challenge_xml = if challenge == Some(407) {
        challenge_xml.replace(r#"<verifyauth assign_to="valid" username="alice" password="secret"/>"#,
            r#"<ereg regexp="Digest .*username=&quot;alice&quot;" search_in="hdr" header="Proxy-Authorization:" check_it="true" assign_to="_"/>"#)
            .replace(r#"<nop test="valid" next="valid"/>"#, "")
            .replace(r#"<nop><action><log message="AUTHENTICATION_FAILED"/><exec int_cmd="stop_call"/></action></nop>"#, "")
            .replace(r#"<label id="valid"/>"#, "")
    } else {
        challenge_xml
    };
    let answer = if offered {
        String::from_utf8(sdp())
            .required()?
            .replace("o=- 1 1", "o=sipp 2 2")
    } else {
        String::new()
    };
    let keys = [
        ("prack_challenge", challenge_xml),
        ("prack_answer", answer.clone()),
        ("prack_answer_type", if offered { "Content-Type: application/sdp\n" } else { "" }.into()),
        ("invite_assertions", if offered {
            r#"<ereg regexp="o=- 1 1" search_in="body" check_it="true" assign_to="_"/>"#
        } else {
            r#"<ereg regexp="^ *0" search_in="hdr" header="Content-Length:" check_it="true" assign_to="_"/>"#
        }.into()),
    ];
    let mut peer = Sipp::start_with_keys("prack_sdp", transport, &dir, &stack.uri, &keys).await?;
    let (dialog, task) = stack
        .layer
        .do_invite_async(
            InviteOption {
                caller: stack.uri.clone(),
                callee: peer.uri.clone(),
                contact: stack.uri.clone(),
                offer: offered.then(sdp),
                credential: challenge.map(|_| Credential {
                    username: "alice".into(),
                    password: "secret".into(),
                    realm: Some("interop.test".into()),
                    auth_username: None,
                }),
                ..Default::default()
            },
            stack.sender.clone(),
        )
        .required()?;
    let (_, response) = peer
        .guarded("INVITE with reliable SDP", task)
        .await?
        .required()?
        .required()?;
    check_eq!(response.required()?.status_code.code(), 200);
    until("PRACK result callback", || {
        (!media
            .results
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty())
        .then_some(())
    })
    .await?;
    let results = media
        .results
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    check_eq!(results.len(), 1);
    let result = results[0].as_ref().required()?;
    check_eq!(result.status_code.code(), 200);
    check_eq!(result.body, answer.as_bytes());
    check_eq!(
        *media.kinds.lock().unwrap_or_else(|p| p.into_inner()),
        vec![if offered {
            SdpKind::Answer
        } else {
            SdpKind::Offer
        }]
    );
    check!(media
        .errors
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    let requests = super::extended::sent_requests(&stack, Method::PRack);
    check_eq!(requests.len(), if challenge.is_some() { 2 } else { 1 });
    for request in &requests {
        check_eq!(request.body, sdp());
        check_eq!(request.rack_value(), Some((1, 1, Method::Invite)));
    }
    if challenge == Some(407) {
        super::extended::verify_proxy_digest(requests.last().required()?)?;
    }
    if challenge.is_some() {
        check!(
            requests[1].cseq_header().required()?.seq().required()?
                > requests[0].cseq_header().required()?.seq().required()?
        );
        check!(
            requests[1]
                .via_header()
                .required()?
                .typed()
                .required()?
                .branch()
                != requests[0]
                    .via_header()
                    .required()?
                    .typed()
                    .required()?
                    .branch()
        );
    }
    bounded("BYE", dialog.bye()).await?.required()?;
    peer.finish().await?;
    stack
        .state("terminated", |s| matches!(s, DialogState::Terminated(..)))
        .await?;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await?;
    stack
        .finish(
            &dir,
            format!("{name}: SDP and authenticated PRACK over {transport}\n"),
        )
        .await
}

macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $offered:literal, $challenge:expr)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp prack"]
        async fn $udp() -> TestResult { scenario(stringify!($udp), "udp", $offered, $challenge).await }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp prack"]
        async fn $tcp() -> TestResult { scenario(stringify!($tcp), "tcp", $offered, $challenge).await }
    )*};
}
cases! {
    (udp_prack_sdp_answer, tcp_prack_sdp_answer, false, None),
    (udp_prack_sdp_new_offer, tcp_prack_sdp_new_offer, true, None),
    (udp_prack_auth_401, tcp_prack_auth_401, false, Some(401)),
    (udp_prack_auth_407, tcp_prack_auth_407, true, Some(407)),
}
