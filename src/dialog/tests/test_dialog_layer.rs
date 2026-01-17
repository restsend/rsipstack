//! Dialog layer tests
//!
//! This module contains tests for dialog management and lifecycle

use crate::dialog::{dialog_layer::DialogLayer, DialogId};
use crate::transaction::{
    endpoint::EndpointBuilder,
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{udp::UdpConnection, TransportLayer};
use rsip::{headers::*, Request};
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

/// Test helper to create a test endpoint
async fn create_test_endpoint() -> crate::Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    Ok(endpoint)
}

/// Test helper to create mock INVITE request
fn create_invite_request(local_tag: &str, remote_tag: &str, call_id: &str, branch: &str) -> Request {
    Request {
        method: rsip::Method::Invite,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060").unwrap(),
        headers: vec![
            Via::new(&format!(
                "SIP/2.0/UDP alice.example.com:5060;branch={}",
                branch
            ))
            .into(),
            CSeq::new("1 INVITE").into(),
            From::new(&format!("Alice <sip:alice@example.com>;tag={}", local_tag)).into(),
            To::new(&format!("Bob <sip:bob@example.com>;tag={}", remote_tag)).into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:alice@alice.example.com:5060>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: b"v=0\r\no=alice 2890844526 2890844527 IN IP4 host.atlanta.com\r\n".to_vec(),
    }
}

/// Test helper to create mock connection
async fn create_mock_connection() -> crate::Result<crate::transport::SipConnection> {
    let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    Ok(udp_conn.into())
}

#[tokio::test]
async fn test_dialog_layer_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    // Initial state should be empty
    assert_eq!(dialog_layer.len(), 0);

    // Test sequence number increment
    let seq1 = dialog_layer.increment_last_seq();
    let seq2 = dialog_layer.increment_last_seq();
    assert_eq!(seq2, seq1 + 1);

    Ok(())
}

#[tokio::test]
async fn test_server_invite_dialog_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // Create INVITE request without to-tag (new dialog)
    let invite_req = create_invite_request("alice-tag-123", "", "call-id-456", "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let tx = Transaction::new_server(
        key,
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(mock_conn),
    );

    let (state_sender, _state_receiver) = unbounded_channel();

    // Create server invite dialog
    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    // Dialog should be created and stored
    assert_eq!(dialog_layer.len(), 1);

    // Dialog ID should have generated local-tag (To-tag for UAS)
    let dialog_id = dialog.id();
    assert_eq!(dialog_id.call_id, "call-id-456");
    assert_eq!(dialog_id.remote_tag, "alice-tag-123");
    assert!(!dialog_id.local_tag.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_existing_server_invite_dialog_retrieval() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // First request creates dialog
    let invite_req1 = create_invite_request("alice-tag-123", "", "call-id-456", "z9hG4bKnashds1");
    let key1 = TransactionKey::from_request(&invite_req1, TransactionRole::Server)?;
    let tx1 = Transaction::new_server(
        key1,
        invite_req1,
        endpoint.inner.clone(),
        Some(mock_conn.clone()),
    );

    let (state_sender, _) = unbounded_channel();

    let dialog1 = dialog_layer.get_or_create_server_invite(
        &tx1,
        state_sender.clone(),
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog1.id();

    // Second request with same dialog identifiers should retrieve existing dialog
    let invite_req2 = create_invite_request(
        "alice-tag-123",
        &dialog_id.local_tag,
        "call-id-456",
        "z9hG4bKnashds2",
    );
    let key2 = TransactionKey::from_request(&invite_req2, TransactionRole::Server)?;
    let tx2 = Transaction::new_server(key2, invite_req2, endpoint.inner.clone(), Some(mock_conn));

    let dialog2 = dialog_layer.get_or_create_server_invite(
        &tx2,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    // Should be the same dialog
    assert_eq!(dialog1.id(), dialog2.id());
    assert_eq!(dialog_layer.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_dialog_retrieval_and_matching() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // Create a dialog
    let invite_req = create_invite_request("alice-tag-123", "", "call-id-456", "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
    let tx = Transaction::new_server(
        key,
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(mock_conn),
    );

    let (state_sender, _) = unbounded_channel();

    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog.id();

    // Test direct retrieval
    let retrieved_dialog = dialog_layer.get_dialog(&dialog_id);
    assert!(retrieved_dialog.is_some());

    // Test request matching
    let bye_req = Request {
        method: rsip::Method::Bye,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            CSeq::new("2 BYE").into(),
            From::new(&format!(
                "Alice <sip:alice@example.com>;tag={}",
                dialog_id.remote_tag
            ))
            .into(),
            To::new(&format!(
                "Bob <sip:bob@example.com>;tag={}",
                dialog_id.local_tag
            ))
            .into(),
            CallId::new(&dialog_id.call_id).into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: vec![],
    };

    let matched_dialog = dialog_layer.match_dialog(&bye_req);
    assert!(matched_dialog.is_some());

    Ok(())
}

#[tokio::test]
async fn test_dialog_removal() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // Create a dialog
    let invite_req = create_invite_request("alice-tag-123", "", "call-id-456", "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
    let tx = Transaction::new_server(key, invite_req, endpoint.inner.clone(), Some(mock_conn));

    let (state_sender, _) = unbounded_channel();

    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog.id();

    // Verify dialog exists
    assert_eq!(dialog_layer.len(), 1);
    assert!(dialog_layer.get_dialog(&dialog_id).is_some());

    // Remove dialog
    dialog_layer.remove_dialog(&dialog_id);

    // Verify dialog is removed
    assert_eq!(dialog_layer.len(), 0);
    assert!(dialog_layer.get_dialog(&dialog_id).is_none());

    Ok(())
}

#[tokio::test]
async fn test_dialog_layer_with_swapped_tags() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // Create a dialog
    let invite_req = create_invite_request("alice-tag-123", "", "call-id-456", "z9hG4bKnashds");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
    let tx = Transaction::new_server(key, invite_req, endpoint.inner.clone(), Some(mock_conn));

    let (state_sender, _) = unbounded_channel();

    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog.id();

    // Create a swapped dialog ID (as if from the other perspective)
    let swapped_id = DialogId {
        call_id: dialog_id.call_id.clone(),
        local_tag: dialog_id.remote_tag.clone(),
        remote_tag: dialog_id.local_tag.clone(),
    };

    // Should NOT be able to find dialog with swapped tags
    let found_dialog = dialog_layer.get_dialog(&swapped_id);
    assert!(found_dialog.is_none());

    Ok(())
}

#[tokio::test]
async fn test_multiple_dialogs_management() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    let (state_sender, _) = unbounded_channel();

    // Create multiple dialogs
    for i in 0..5 {
        let call_id = format!("call-id-{}", i);
        let local_tag = format!("alice-tag-{}", i);
        let branch = format!("z9hG4bKnashds{}", i);

        let invite_req = create_invite_request(&local_tag, "", &call_id, &branch);
        let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
        let tx = Transaction::new_server(
            key,
            invite_req,
            endpoint.inner.clone(),
            Some(mock_conn.clone()),
        );

        dialog_layer.get_or_create_server_invite(
            &tx,
            state_sender.clone(),
            None,
            Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
        )?;
    }

    // Should have 5 dialogs
    assert_eq!(dialog_layer.len(), 5);

    // Remove one dialog
    let _test_id = DialogId {
        call_id: "test-call-2".to_string(),
        local_tag: "alice-tag-2".to_string(),
        remote_tag: "".to_string(), // We need to find the actual dialog first
    };

    // Find all dialogs to get the actual IDs
    let mut dialog_ids = vec![];
    for i in 0..5 {
        let call_id = format!("call-id-{}", i);
        let local_tag = format!("alice-tag-{}", i);
        let _partial_id = DialogId {
            call_id: call_id.clone(),
            local_tag: local_tag.clone(),
            remote_tag: "".to_string(),
        };

        // Try to find dialog by creating a request and matching
        let test_req = create_invite_request(&local_tag, "", &call_id, "test-branch");
        if let Some(dialog) = dialog_layer.match_dialog(&test_req) {
            dialog_ids.push(dialog.id());
        }
    }

    // Remove first dialog
    if let Some(dialog_id) = dialog_ids.first() {
        dialog_layer.remove_dialog(dialog_id);
        assert_eq!(dialog_layer.len(), 4);
    }

    Ok(())
}

#[tokio::test]
async fn test_dialog_error_cases() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());
    let mock_conn = create_mock_connection().await?;

    // Test with invalid dialog ID (non-existent to-tag)
    let invite_req = create_invite_request(
        "alice-tag-123",
        "non-existent-tag",
        "call-id-456",
        "z9hG4bKnashds",
    );
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
    let tx = Transaction::new_server(key, invite_req, endpoint.inner.clone(), Some(mock_conn));

    let (state_sender, _) = unbounded_channel();

    // Should return error when trying to get dialog with non-existent to-tag
    let result = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    );

    assert!(result.is_err());

    Ok(())
}
