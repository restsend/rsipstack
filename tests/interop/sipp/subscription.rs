use super::{bounded, log_dir, until, Sipp, Stack};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption},
    sip::{prelude::*, Header, Method, StatusCode},
};

async fn scenario(name: &str, transport: &str) {
    let dir = log_dir(name);
    let stack = Stack::start(transport, &dir).await;
    let mut peer = Sipp::start("subscription", transport, &dir, &stack.uri).await;
    // Seed an existing subscription dialog. This tests refresh/NOTIFY handling;
    // initial out-of-dialog SUBSCRIBE/NOTIFY racing is a separate coverage gap.
    let mut initial = stack
        .layer
        .make_invite_request(&InviteOption {
            caller: stack.uri.clone(),
            callee: peer.uri.clone(),
            contact: stack.uri.clone(),
            ..Default::default()
        })
        .unwrap();
    initial.method = Method::Subscribe;
    initial
        .headers
        .unique_push(Header::CSeq("1 SUBSCRIBE".into()));
    initial
        .headers
        .unique_push(Header::To(format!("<{}>;tag=sipp-test", peer.uri).into()));
    let call_id = initial.call_id_header().unwrap().value().to_string();
    let local_tag = initial
        .from_header()
        .unwrap()
        .tag()
        .unwrap()
        .unwrap()
        .value()
        .to_string();
    let dialog = stack
        .layer
        .get_or_create_client_subscription(
            call_id,
            local_tag,
            "sipp-test".into(),
            initial,
            stack.sender.clone(),
            None,
            Some(stack.uri.clone()),
        )
        .unwrap();
    let response = bounded(
        "SUBSCRIBE refresh",
        dialog.subscribe(
            Some(vec![
                Header::Event("presence".into()),
                Header::Expires(60.into()),
            ]),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status_code.code(), 200);
    let (request, handle) = until("NOTIFY event", || {
        stack.states.lock().unwrap().iter().find_map(|s| match s {
            DialogState::Notify(_, request, handle) => Some((request.clone(), handle.clone())),
            _ => None,
        })
    })
    .await;
    assert!(request
        .headers
        .iter()
        .any(|h| matches!(h, Header::Event(v) if v.value() == "presence")));
    assert!(String::from_utf8_lossy(&request.body).contains("<basic>open</basic>"));
    handle.reply(StatusCode::OK).await.unwrap();
    peer.marker("NOTIFY_ACCEPTED").await;
    bounded(
        "unsubscribe",
        dialog.unsubscribe_with_headers(Some(vec![Header::Event("presence".into())])),
    )
    .await
    .unwrap();
    peer.finish().await;
    stack
        .state("subscription terminated", |s| {
            matches!(s, DialogState::Terminated(..))
        })
        .await;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await;
    assert_eq!(stack.wire.requests(Method::Subscribe), 2);
    assert_eq!(stack.wire.requests(Method::Notify), 1);
    assert_eq!(stack.wire.requests(Method::Ack), 0);
    std::fs::write(
        dir.join("PASS"),
        format!("{name}: subscription refresh over {transport}\n"),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "requires SIPp; use scripts/interop/run.sh sipp subscription"]
async fn udp_subscription_refresh() {
    scenario("udp_subscription_refresh", "udp").await;
}
#[tokio::test]
#[ignore = "requires SIPp; use scripts/interop/run.sh sipp subscription"]
async fn tcp_subscription_refresh() {
    scenario("tcp_subscription_refresh", "tcp").await;
}
