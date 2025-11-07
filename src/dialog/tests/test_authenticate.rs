//! Authentication tests
//!
//! Tests for SIP authentication handling, including Via header parameter updates

use crate::dialog::authenticate::{handle_client_authenticate, Credential};
use crate::transaction::{
    endpoint::EndpointBuilder,
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::TransportLayer;
use rsip::headers::*;
use rsip::prelude::{HeadersExt, ToTypedHeader};
use rsip::{Request, Response, StatusCode};
use tokio_util::sync::CancellationToken;

async fn create_test_endpoint() -> crate::Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    Ok(endpoint)
}

fn create_request_with_branch(branch: &str) -> Request {
    Request {
        method: rsip::Method::Register,
        uri: rsip::Uri::try_from("sip:example.com:5060").unwrap(),
        headers: vec![
            Via::new(&format!(
                "SIP/2.0/UDP alice.example.com:5060;branch={}",
                branch
            ))
            .into(),
            CSeq::new("1 REGISTER").into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: vec![],
    }
}

fn create_401_response() -> Response {
    Response {
        status_code: StatusCode::Unauthorized,
        version: rsip::Version::V2,
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 REGISTER").into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
            WwwAuthenticate::new(
                r#"Digest realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5, qop="auth""#,
            )
            .into(),
        ]
        .into(),
        body: vec![],
    }
}

#[tokio::test]
async fn test_authenticate_via_header_branch_update() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;

    // Create a request with a specific branch parameter
    let original_branch = "z9hG4bKoriginal123";
    let original_req = create_request_with_branch(original_branch);

    // Verify the original request has the branch
    let original_via = original_req
        .via_header()
        .expect("Request should have Via header")
        .typed()
        .expect("Via header should be parseable");
    let original_branch_param = original_via
        .params
        .iter()
        .find(|p| matches!(p, rsip::Param::Branch(_)))
        .expect("Original request should have branch parameter");
    let original_branch_value = match original_branch_param {
        rsip::Param::Branch(b) => b.to_string(),
        _ => unreachable!(),
    };
    assert_eq!(original_branch_value, original_branch);

    // Create transaction
    let key = TransactionKey::from_request(&original_req, TransactionRole::Client)?;
    let tx = Transaction::new_client(key, original_req, endpoint.inner.clone(), None);

    // Create 401 response
    let resp = create_401_response();

    // Create credential
    let cred = Credential {
        username: "alice".to_string(),
        password: "secret123".to_string(),
        realm: None,
    };

    // Call handle_client_authenticate
    let new_tx = handle_client_authenticate(2, tx, resp, &cred).await?;

    // Verify the new request has updated Via header
    let new_via = new_tx
        .original
        .via_header()
        .expect("New request should have Via header")
        .typed()
        .expect("Via header should be parseable");

    // Verify old branch is removed
    let old_branch_exists = new_via
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Branch(b) if b.to_string() == original_branch_value));
    assert!(
        !old_branch_exists,
        "Old branch parameter should be removed from Via header"
    );

    // Verify new branch is added (and different from old one)
    let new_branch_param = new_via
        .params
        .iter()
        .find(|p| matches!(p, rsip::Param::Branch(_)))
        .expect("New request should have a new branch parameter");
    let new_branch_value = match new_branch_param {
        rsip::Param::Branch(b) => b.to_string(),
        _ => unreachable!(),
    };
    assert_ne!(
        new_branch_value, original_branch_value,
        "New branch should be different from old branch"
    );
    assert!(
        new_branch_value.starts_with("z9hG4bK"),
        "New branch should start with z9hG4bK"
    );

    // Verify rport parameter is added
    let has_rport = new_via.params.iter().any(
        |p| matches!(p, rsip::Param::Other(key, _) if key.value().eq_ignore_ascii_case("rport")),
    );
    assert!(
        has_rport,
        "Via header should have rport parameter after authentication"
    );

    Ok(())
}
