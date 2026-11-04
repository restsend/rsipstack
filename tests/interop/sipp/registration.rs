use super::{bounded, extended::sent_requests, log_dir, Sipp, Stack};
use rsipstack::{
    dialog::{authenticate::Credential, registration::Registration},
    sip::{prelude::*, Method},
};

async fn scenario(name: &str, transport: &str, kind: &str) {
    let dir = log_dir(name);
    let stack = Stack::start(transport, &dir).await;
    let mut peer = Sipp::start(kind, transport, &dir, &stack.uri).await;
    let credential = (kind == "register_auth").then(|| Credential {
        username: "alice".into(),
        password: "secret".into(),
        realm: Some("interop.test".into()),
        auth_username: None,
    });
    let mut registration = Registration::new(stack.layer.endpoint.clone(), credential);
    registration.contact = Some(
        rsipstack::sip::headers::Contact::new(format!("<{}>", stack.uri))
            .typed()
            .unwrap(),
    );
    let mut server = peer.uri.clone();
    server.auth = None;
    let response = peer
        .guarded("REGISTER", registration.register(server.clone(), Some(300)))
        .await
        .unwrap();
    if kind == "register_423" {
        assert_eq!(response.status_code.code(), 423);
        assert_eq!(response.min_expires_header().unwrap().value().trim(), "300");
        let response = peer
            .guarded("REGISTER retry", registration.register(server, Some(300)))
            .await
            .unwrap();
        assert_eq!(response.status_code.code(), 200);
        assert_eq!(registration.expires(), 300);
    } else {
        assert_eq!(response.status_code.code(), 200);
        assert_eq!(registration.expires(), 90);
        if kind == "register_lifecycle" {
            assert_eq!(registration.service_route().len(), 1);
            assert_eq!(registration.preloaded_route_set().len(), 1);
            let response = bounded(
                "REGISTER refresh",
                registration.register(server.clone(), Some(180)),
            )
            .await
            .unwrap();
            assert_eq!(response.status_code.code(), 200);
            assert_eq!(registration.expires(), 60);
            assert!(
                registration.service_route().is_empty(),
                "missing Service-Route clears the previous route set"
            );
            let response = peer
                .guarded("unregister", registration.register(server, Some(0)))
                .await
                .unwrap();
            assert_eq!(response.status_code.code(), 200);
            assert_eq!(registration.expires(), 0);
        }
    }
    peer.finish().await;
    let requests = sent_requests(&stack, Method::Register);
    assert_eq!(
        requests.len(),
        if kind == "register_lifecycle" { 3 } else { 2 }
    );
    for request in &requests {
        assert!(request
            .via_header()
            .unwrap()
            .value()
            .contains(&format!("SIP/2.0/{}", transport.to_uppercase())));
    }
    for pair in requests.windows(2) {
        assert_eq!(
            pair[0].call_id_header().unwrap(),
            pair[1].call_id_header().unwrap()
        );
        assert!(
            pair[1].cseq_header().unwrap().seq().unwrap()
                > pair[0].cseq_header().unwrap().seq().unwrap()
        );
    }
    assert_eq!(stack.wire.requests(Method::Ack), 0, "REGISTER has no ACK");
    assert!(stack.layer.is_empty(), "REGISTER creates no dialog");
    std::fs::write(
        dir.join("PASS"),
        format!("{name}: {kind} over {transport}\n"),
    )
    .unwrap();
}

macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $kind:literal)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp registration"]
        async fn $udp() { scenario(stringify!($udp), "udp", $kind).await; }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp registration"]
        async fn $tcp() { scenario(stringify!($tcp), "tcp", $kind).await; }
    )*};
}
cases! {
    (udp_register_lifecycle, tcp_register_lifecycle, "register_lifecycle"),
    (udp_register_auth, tcp_register_auth, "register_auth"),
    (udp_register_423, tcp_register_423, "register_423"),
}
