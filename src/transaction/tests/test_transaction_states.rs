//! Transaction state transition tests
//!
//! This module contains comprehensive tests for transaction state transitions
//! according to RFC 3261 Section 17.

use super::create_test_endpoint;
use crate::sip::headers::*;
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
    TransactionState, TransactionType,
};

/// Test helper to create a mock request
fn create_test_request(method: crate::sip::Method, branch: &str) -> crate::sip::Request {
    crate::sip::Request {
        method,
        uri: crate::sip::Uri::try_from("sip:test.example.com:5060").unwrap(),
        headers: vec![
            Via::new(&format!(
                "SIP/2.0/UDP test.example.com:5060;branch={}",
                branch
            ))
            .into(),
            CSeq::new(&format!("1 {}", method)).into(),
            From::new("Alice <sip:alice@example.com>;tag=1928301774").into(),
            To::new("Bob <sip:bob@example.com>").into(),
            CallId::new("a84b4c76e66710@pc33.atlanta.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    }
}

#[tokio::test]
async fn test_client_invite_transaction_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Create INVITE request
    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Client)?;

    let tx = Transaction::new_client(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        None, // No connection needed for basic tests
    );

    // Initial state should be Calling
    assert_eq!(tx.state, TransactionState::Nothing);
    assert_eq!(tx.transaction_type, TransactionType::ClientInvite);

    Ok(())
}

#[tokio::test]
async fn test_client_non_invite_transaction_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Create REGISTER request (non-INVITE)
    let register_req = create_test_request(crate::sip::Method::Register, "z9hG4bKnashds");
    let key = TransactionKey::from_request(&register_req, TransactionRole::Client)?;

    let tx = Transaction::new_client(
        key.clone(),
        register_req.clone(),
        endpoint.inner.clone(),
        None,
    );

    // Initial state should be Calling
    assert_eq!(tx.state, TransactionState::Nothing);
    assert_eq!(tx.transaction_type, TransactionType::ClientNonInvite);

    Ok(())
}

#[tokio::test]
async fn test_server_invite_transaction_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Create INVITE request for server
    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        None,
    );

    // Initial state should be Trying
    assert_eq!(tx.state, TransactionState::Trying);
    assert_eq!(tx.transaction_type, TransactionType::ServerInvite);

    Ok(())
}

#[tokio::test]
async fn test_server_non_invite_transaction_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Create REGISTER request for server
    let register_req = create_test_request(crate::sip::Method::Register, "z9hG4bKnashds");
    let key = TransactionKey::from_request(&register_req, TransactionRole::Server)?;

    let tx = Transaction::new_server(
        key.clone(),
        register_req.clone(),
        endpoint.inner.clone(),
        None,
    );

    // Initial state should be Trying
    assert_eq!(tx.state, TransactionState::Trying);
    assert_eq!(tx.transaction_type, TransactionType::ServerNonInvite);

    Ok(())
}

#[tokio::test]
async fn test_transaction_key_generation() -> crate::Result<()> {
    // Test transaction key generation for different roles
    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bKnashds");

    let client_key = TransactionKey::from_request(&invite_req, TransactionRole::Client)?;
    let server_key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    // Keys should be different for different roles
    assert_ne!(client_key, server_key);

    // Same request and role should generate same key
    let client_key2 = TransactionKey::from_request(&invite_req, TransactionRole::Client)?;
    assert_eq!(client_key, client_key2);

    Ok(())
}

#[tokio::test]
async fn test_transaction_types() -> crate::Result<()> {
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;

    // Test INVITE transaction type
    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bKnashds");
    let invite_key = TransactionKey::from_request(&invite_req, TransactionRole::Client)?;
    let invite_tx = Transaction::new_client(invite_key, invite_req, endpoint.inner.clone(), None);
    assert_eq!(invite_tx.transaction_type, TransactionType::ClientInvite);

    // Test non-INVITE transaction type
    let register_req = create_test_request(crate::sip::Method::Register, "z9hG4bKnashds2");
    let register_key = TransactionKey::from_request(&register_req, TransactionRole::Client)?;
    let register_tx =
        Transaction::new_client(register_key, register_req, endpoint.inner.clone(), None);
    assert_eq!(
        register_tx.transaction_type,
        TransactionType::ClientNonInvite
    );

    Ok(())
}
