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
    let new_tx = handle_client_authenticate(2, &tx, resp, &cred).await?;

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

#[test]
fn test_extract_digest_uri_raw() {
    use crate::dialog::authenticate::extract_digest_uri_raw;

    // Quoted URI with lowercase transport (Unify OpenScape TLS case)
    let header = r#"Digest username="111",realm="pbx.e36",nonce="K1KmT96onZZVMvBB",uri="sip:pbx.e36:5061;transport=tls",response="0c9ba3a13fbcc4f342fd7eb9c2be6a83",algorithm=MD5"#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:pbx.e36:5061;transport=tls".to_string()));

    // Quoted URI with uppercase transport (standard rsip output)
    let header = r#"Digest username="111",realm="pbx.e36",nonce="abc",uri="sip:pbx.e36:5061;transport=TLS",response="xxx",algorithm=MD5"#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:pbx.e36:5061;transport=TLS".to_string()));

    // Quoted URI with lowercase UDP transport (Unify OpenScape UDP case)
    let header = r#"Digest username="111",realm="pbx.e36",nonce="MoLk0nzBonitjdoo",uri="sip:pbx.e36:5060;transport=udp",response="5a832a648a56b95f905b8db1d28d8f5b",algorithm=MD5"#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:pbx.e36:5060;transport=udp".to_string()));

    // URI without transport param (simple SIP URI)
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sip:example.com",response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:example.com".to_string()));

    // URI with port and no transport
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sip:example.com:5060",response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:example.com:5060".to_string()));

    // URI with mixed-case transport (e.g., "Tls")
    let header = r#"Digest username="111",realm="pbx.e36",nonce="abc",uri="sip:pbx.e36:5061;transport=Tls",response="xxx",algorithm=MD5"#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:pbx.e36:5061;transport=Tls".to_string()));

    // URI with TCP transport lowercase
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sip:example.com:5060;transport=tcp",response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:example.com:5060;transport=tcp".to_string()));

    // URI with user@ part
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sip:alice@example.com:5060;transport=tls",response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(
        uri,
        Some("sip:alice@example.com:5060;transport=tls".to_string())
    );

    // SIPS URI
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sips:example.com",response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sips:example.com".to_string()));

    // With spaces around params (some devices add spaces after commas)
    let header = r#"Digest username="alice", realm="example.com", nonce="abc", uri="sip:example.com;transport=ws", response="xxx""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:example.com;transport=ws".to_string()));

    // With qop params (full real-world header)
    let header = r#"Digest username="alice",realm="example.com",nonce="abc",uri="sip:example.com:5060;transport=udp",response="xxx",algorithm=MD5,qop=auth,nc=00000001,cnonce="yz""#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:example.com:5060;transport=udp".to_string()));

    // IP address URI with lowercase transport
    let header = r#"Digest username="111",realm="192.168.1.1",nonce="abc",uri="sip:192.168.1.1:5061;transport=tls",response="xxx",algorithm=MD5"#;
    let uri = extract_digest_uri_raw(header);
    assert_eq!(uri, Some("sip:192.168.1.1:5061;transport=tls".to_string()));
}

#[test]
fn test_compute_digest_case_sensitive_uri() {
    use crate::dialog::authenticate::compute_digest;
    use rsip::headers::auth::Algorithm;

    // Compute digest with lowercase transport=tls
    let response_lower = compute_digest(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        "sip:pbx.e36:5061;transport=tls",
        Algorithm::Md5,
        None,
    );

    // Compute digest with uppercase transport=TLS
    let response_upper = compute_digest(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        "sip:pbx.e36:5061;transport=TLS",
        Algorithm::Md5,
        None,
    );

    // They should be different because the URI string is different
    assert_ne!(
        response_lower, response_upper,
        "Digest should differ for different URI case"
    );

    // Compute digest without transport param - should be the same regardless
    let response_no_transport = compute_digest(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        "sip:pbx.e36:5061",
        Algorithm::Md5,
        None,
    );
    assert_ne!(response_no_transport, response_lower);
    assert_ne!(response_no_transport, response_upper);
}

/// Helper: build an Authorization header string and verify it with `verify_digest`.
/// Returns (is_valid, auth_header_value) for further assertions.
fn build_and_verify(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &rsip::Method,
    uri_raw: &str,
    algorithm: rsip::headers::auth::Algorithm,
) -> (bool, String) {
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let response = compute_digest(
        username, password, realm, nonce, method, uri_raw, algorithm, None,
    );

    let auth_header_value = format!(
        r#"Digest username="{}",realm="{}",nonce="{}",uri="{}",response="{}",algorithm={}"#,
        username, realm, nonce, uri_raw, response, algorithm
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    let is_valid = verify_digest(&auth, password, method, &auth_header_value);
    (is_valid, auth_header_value)
}

#[test]
fn test_verify_digest_lowercase_tls() {
    // Simulate Unify OpenScape CP710 with TLS: transport=tls (lowercase)
    let (is_valid, _) = build_and_verify(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        "sip:pbx.e36:5061;transport=tls",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle lowercase transport=tls"
    );
}

#[test]
fn test_verify_digest_uppercase_tls() {
    // Standard uppercase TLS (e.g., rsip's own output)
    let (is_valid, _) = build_and_verify(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        "sip:pbx.e36:5061;transport=TLS",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle uppercase transport=TLS"
    );
}

#[test]
fn test_verify_digest_lowercase_udp() {
    // Unify OpenScape CP710 with UDP: transport=udp (lowercase)
    let (is_valid, _) = build_and_verify(
        "111",
        "111",
        "pbx.e36",
        "MoLk0nzBonitjdoo",
        &rsip::Method::Register,
        "sip:pbx.e36:5060;transport=udp",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle lowercase transport=udp"
    );
}

#[test]
fn test_verify_digest_uppercase_udp() {
    let (is_valid, _) = build_and_verify(
        "111",
        "111",
        "pbx.e36",
        "MoLk0nzBonitjdoo",
        &rsip::Method::Register,
        "sip:pbx.e36:5060;transport=UDP",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle uppercase transport=UDP"
    );
}

#[test]
fn test_verify_digest_lowercase_tcp() {
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret",
        "example.com",
        "nonce123",
        &rsip::Method::Register,
        "sip:example.com:5060;transport=tcp",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle lowercase transport=tcp"
    );
}

#[test]
fn test_verify_digest_no_transport() {
    // Simple URI without transport param
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret123",
        "example.com",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        &rsip::Method::Register,
        "sip:example.com",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should work with URI without transport param"
    );
}

#[test]
fn test_verify_digest_with_port_no_transport() {
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret123",
        "example.com",
        "nonce456",
        &rsip::Method::Register,
        "sip:example.com:5060",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should work with URI with port but no transport"
    );
}

#[test]
fn test_verify_digest_invite_method() {
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret",
        "example.com",
        "nonce789",
        &rsip::Method::Invite,
        "sip:bob@example.com:5060;transport=tls",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(is_valid, "verify_digest should work with INVITE method");
}

#[test]
fn test_verify_digest_sips_uri() {
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret",
        "example.com",
        "nonce_sips",
        &rsip::Method::Register,
        "sips:example.com",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(is_valid, "verify_digest should work with SIPS URI");
}

#[test]
fn test_verify_digest_ip_address_uri() {
    let (is_valid, _) = build_and_verify(
        "111",
        "111",
        "192.168.201.31",
        "nonce_ip",
        &rsip::Method::Register,
        "sip:192.168.201.31:5061;transport=tls",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(is_valid, "verify_digest should work with IP address URI");
}

#[test]
fn test_verify_digest_wrong_password_fails() {
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::auth::Algorithm;
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let uri_raw = "sip:pbx.e36:5061;transport=tls";
    let response = compute_digest(
        "111",
        "111", // correct password
        "pbx.e36",
        "nonce123",
        &rsip::Method::Register,
        uri_raw,
        Algorithm::Md5,
        None,
    );

    let auth_header_value = format!(
        r#"Digest username="111",realm="pbx.e36",nonce="nonce123",uri="{}",response="{}",algorithm=MD5"#,
        uri_raw, response
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    // Verify with wrong password should fail
    let is_valid = verify_digest(
        &auth,
        "wrong_password",
        &rsip::Method::Register,
        &auth_header_value,
    );
    assert!(!is_valid, "verify_digest should fail with wrong password");
}

#[test]
fn test_verify_digest_mixed_case_transport() {
    // Some devices might use mixed case like "Tcp", "Udp"
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret",
        "example.com",
        "nonce_mixed",
        &rsip::Method::Register,
        "sip:example.com:5060;transport=Tcp",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle mixed-case transport=Tcp"
    );
}

#[test]
fn test_verify_digest_websocket_transport() {
    let (is_valid, _) = build_and_verify(
        "webuser",
        "webpass",
        "ws.example.com",
        "nonce_ws",
        &rsip::Method::Register,
        "sip:ws.example.com;transport=ws",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(
        is_valid,
        "verify_digest should handle WebSocket transport=ws"
    );
}

#[test]
fn test_verify_digest_with_user_in_uri() {
    let (is_valid, _) = build_and_verify(
        "alice",
        "secret",
        "example.com",
        "nonce_user",
        &rsip::Method::Register,
        "sip:alice@example.com:5060;transport=tls",
        rsip::headers::auth::Algorithm::Md5,
    );
    assert!(is_valid, "verify_digest should work with user@host URI");
}

#[test]
fn test_verify_digest_rsip_digest_generator_mismatch() {
    // Explicitly demonstrate the rsip DigestGenerator bug with lowercase transport
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::auth::Algorithm;
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let uri_raw = "sip:pbx.e36:5061;transport=tls";
    let response = compute_digest(
        "111",
        "111",
        "pbx.e36",
        "K1KmT96onZZVMvBB",
        &rsip::Method::Register,
        uri_raw,
        Algorithm::Md5,
        None,
    );

    let auth_header_value = format!(
        r#"Digest username="111",realm="pbx.e36",nonce="K1KmT96onZZVMvBB",uri="sip:pbx.e36:5061;transport=tls",response="{}",algorithm=MD5"#,
        response
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    // rsip's DigestGenerator normalizes URI → transport=TLS (uppercase)
    // This causes verification failure for devices using lowercase
    assert_eq!(
        auth.uri.to_string(),
        "sip:pbx.e36:5061;transport=TLS",
        "rsip normalizes transport to uppercase in parsed URI"
    );

    let digest_gen = rsip::services::DigestGenerator::from(&auth, "111", &rsip::Method::Register);
    let rsip_response = digest_gen.compute();
    assert_ne!(
        rsip_response, response,
        "rsip DigestGenerator produces wrong hash due to URI case normalization"
    );

    // Our verify_digest uses raw URI from AuthTokenizer → works correctly
    let is_valid = verify_digest(&auth, "111", &rsip::Method::Register, &auth_header_value);
    assert!(
        is_valid,
        "verify_digest should succeed where rsip DigestGenerator fails"
    );
}

#[test]
fn test_verify_digest_with_qop_auth() {
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::auth::{Algorithm, AuthQop};
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let uri_raw = "sip:pbx.e36:5061;transport=tls";
    let qop = AuthQop::Auth {
        cnonce: "0a4f113b".to_string(),
        nc: 1,
    };
    let response = compute_digest(
        "111",
        "111",
        "pbx.e36",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        &rsip::Method::Register,
        uri_raw,
        Algorithm::Md5,
        Some(&qop),
    );

    let auth_header_value = format!(
        r#"Digest username="111",realm="pbx.e36",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",uri="{}",response="{}",algorithm=MD5,qop=auth,nc=00000001,cnonce="0a4f113b""#,
        uri_raw, response
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    let is_valid = verify_digest(&auth, "111", &rsip::Method::Register, &auth_header_value);
    assert!(
        is_valid,
        "verify_digest should work with qop=auth and lowercase transport"
    );
}

#[test]
fn test_verify_digest_real_world_unify_tls() {
    // Reproduce the exact scenario from GitHub issue #146 (TLS case)
    // Device: Unify OpenScape CP710
    // Authorization: Digest username="111",realm="pbx.e36",nonce="K1KmT96onZZVMvBB",
    //   uri="sip:pbx.e36:5061;transport=tls",response="...",algorithm=MD5
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::auth::Algorithm;
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let username = "111";
    let password = "111";
    let realm = "pbx.e36";
    let nonce = "K1KmT96onZZVMvBB";
    let uri_raw = "sip:pbx.e36:5061;transport=tls"; // lowercase as sent by device

    let response = compute_digest(
        username,
        password,
        realm,
        nonce,
        &rsip::Method::Register,
        uri_raw,
        Algorithm::Md5,
        None,
    );

    // Construct the full Authorization header as the device would send it
    let auth_header_value = format!(
        r#"Digest username="{}",realm="{}",nonce="{}",uri="{}",response="{}",algorithm=MD5"#,
        username, realm, nonce, uri_raw, response
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    let is_valid = verify_digest(&auth, password, &rsip::Method::Register, &auth_header_value);
    assert!(
        is_valid,
        "Real-world Unify TLS case should pass verification"
    );
}

#[test]
fn test_verify_digest_real_world_unify_udp() {
    // Reproduce the exact scenario from GitHub issue #146 (UDP case)
    use crate::dialog::authenticate::{compute_digest, verify_digest};
    use rsip::headers::auth::Algorithm;
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let username = "111";
    let password = "111";
    let realm = "pbx.e36";
    let nonce = "MoLk0nzBonitjdoo";
    let uri_raw = "sip:pbx.e36:5060;transport=udp"; // lowercase as sent by device

    let response = compute_digest(
        username,
        password,
        realm,
        nonce,
        &rsip::Method::Register,
        uri_raw,
        Algorithm::Md5,
        None,
    );

    let auth_header_value = format!(
        r#"Digest username="{}",realm="{}",nonce="{}",uri="{}",response="{}",algorithm=MD5"#,
        username, realm, nonce, uri_raw, response
    );

    let tokenizer = AuthTokenizer::tokenize(&auth_header_value).unwrap();
    let auth: rsip::typed::Authorization = tokenizer.try_into().unwrap();

    let is_valid = verify_digest(&auth, password, &rsip::Method::Register, &auth_header_value);
    assert!(
        is_valid,
        "Real-world Unify UDP case should pass verification"
    );
}
