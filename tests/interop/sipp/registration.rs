use super::{bounded, extended::sent_requests, log_dir, Sipp, Stack};
use crate::interop::{Required, TestResult};
use rsipstack::{
    dialog::{authenticate::Credential, registration::Registration},
    sip::{prelude::*, Method},
};

async fn scenario(name: &str, transport: &str, kind: &str) -> TestResult {
    let dir = log_dir(name)?;
    let stack = Stack::start(transport, &dir).await?;
    let mut peer = Sipp::start(kind, transport, &dir, &stack.uri).await?;
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
            .required()?,
    );
    let mut server = peer.uri.clone();
    server.auth = None;
    let response = peer
        .guarded("REGISTER", registration.register(server.clone(), Some(300)))
        .await?
        .required()?;
    if kind == "register_423" {
        check_eq!(response.status_code.code(), 423);
        check_eq!(
            response.min_expires_header().required()?.value().trim(),
            "300"
        );
        let response = peer
            .guarded("REGISTER retry", registration.register(server, Some(300)))
            .await?
            .required()?;
        check_eq!(response.status_code.code(), 200);
        check_eq!(registration.expires(), 300);
    } else {
        check_eq!(response.status_code.code(), 200);
        check_eq!(registration.expires(), 90);
        if kind == "register_lifecycle" {
            check_eq!(registration.service_route().len(), 1);
            check_eq!(registration.preloaded_route_set().len(), 1);
            let response = bounded(
                "REGISTER refresh",
                registration.register(server.clone(), Some(180)),
            )
            .await?
            .required()?;
            check_eq!(response.status_code.code(), 200);
            check_eq!(registration.expires(), 60);
            check!(
                registration.service_route().is_empty(),
                "missing Service-Route clears the previous route set"
            );
            let response = peer
                .guarded("unregister", registration.register(server, Some(0)))
                .await?
                .required()?;
            check_eq!(response.status_code.code(), 200);
            check_eq!(registration.expires(), 0);
        }
    }
    peer.finish().await?;
    let requests = sent_requests(&stack, Method::Register);
    check_eq!(
        requests.len(),
        if kind == "register_lifecycle" { 3 } else { 2 }
    );
    for request in &requests {
        check!(request
            .via_header()
            .required()?
            .value()
            .contains(&format!("SIP/2.0/{}", transport.to_uppercase())));
    }
    for pair in requests.windows(2) {
        check_eq!(
            pair[0].call_id_header().required()?,
            pair[1].call_id_header().required()?
        );
        check!(
            pair[1].cseq_header().required()?.seq().required()?
                > pair[0].cseq_header().required()?.seq().required()?
        );
    }
    check_eq!(stack.wire.requests(Method::Ack), 0, "REGISTER has no ACK");
    check!(stack.layer.is_empty(), "REGISTER creates no dialog");
    stack
        .finish(&dir, format!("{name}: {kind} over {transport}\n"))
        .await?;
    Ok(())
}

macro_rules! cases {
    ($(($udp:ident, $tcp:ident, $kind:literal)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp registration"]
        async fn $udp() -> TestResult { scenario(stringify!($udp), "udp", $kind).await }
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp registration"]
        async fn $tcp() -> TestResult { scenario(stringify!($tcp), "tcp", $kind).await }
    )*};
}
cases! {
    (udp_register_lifecycle, tcp_register_lifecycle, "register_lifecycle"),
    (udp_register_auth, tcp_register_auth, "register_auth"),
    (udp_register_423, tcp_register_423, "register_423"),
}
