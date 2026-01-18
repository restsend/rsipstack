//! Dialog state transition tests
//!
//! This module contains comprehensive tests for dialog state transitions
//! according to RFC 3261 Section 12.

use crate::dialog::{
    dialog::{DialogInner, DialogState, TerminatedReason, TransactionHandle},
    DialogId,
};
use crate::transaction::{endpoint::EndpointBuilder, key::TransactionRole};
use crate::transport::TransportLayer;
use rsip::{headers::*, Request, Response, StatusCode};
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

/// Test helper to create a mock INVITE request
pub fn create_invite_request(local_tag: &str, remote_tag: &str, call_id: &str) -> Request {
    Request {
        method: rsip::Method::Invite,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds;received=172.0.0.1")
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

/// Test helper to create a mock response
fn create_response(
    status: StatusCode,
    local_tag: &str,
    remote_tag: &str,
    call_id: &str,
) -> Response {
    let body = if status == StatusCode::OK {
        b"v=0\r\no=bob 2890844527 2890844528 IN IP4 host.biloxi.com\r\n".to_vec()
    } else {
        vec![]
    };

    Response {
        status_code: status,
        version: rsip::Version::V2,
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new(&format!("Alice <sip:alice@example.com>;tag={}", local_tag)).into(),
            To::new(&format!("Bob <sip:bob@example.com>;tag={}", remote_tag)).into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:bob@bob.example.com:5060>").into(),
        ]
        .into(),
        body,
    }
}

pub async fn create_test_endpoint() -> crate::Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    Ok(endpoint)
}

#[test]
fn test_dialog_id_eq() {
    let dialog_id_1 = DialogId {
        call_id: "test-call-id-123".to_string(),
        local_tag: "456".to_string(),
        remote_tag: "789".to_string(),
    };
    assert_eq!(dialog_id_1.to_string(), "test-call-id-123-456-789");
    let dialog_id_2 = DialogId {
        call_id: "test-call-id-123".to_string(),
        local_tag: "789".to_string(),
        remote_tag: "456".to_string(),
    };
    assert_eq!(dialog_id_2.to_string(), "test-call-id-123-789-456");
    assert_ne!(dialog_id_1, dialog_id_2);

    let dialog_id_3 = DialogId {
        call_id: "mock".to_string(),
        local_tag: "M3wnsBf".to_string(),
        remote_tag: "1NyRqPt1".to_string(),
    };
    let dialog_id_4 = DialogId {
        call_id: "mock".to_string(),
        local_tag: "1NyRqPt1".to_string(),
        remote_tag: "M3wnsBf".to_string(),
    };
    assert_ne!(dialog_id_3, dialog_id_4);
}
#[tokio::test]
async fn test_dialog_state_transitions() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();

    // Create dialog ID
    let dialog_id = DialogId {
        call_id: "test-call-id-123".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    // Create INVITE request
    let invite_req = create_invite_request("alice-tag-456", "", "test-call-id-123");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    // Create dialog inner
    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    // Test initial state
    let initial_state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(initial_state, DialogState::Calling(_)));

    // Test transition to Trying
    dialog_inner.transition(DialogState::Trying(dialog_id.clone()))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Trying(_)));

    // Test transition to Early
    let ringing_resp = create_response(
        StatusCode::Ringing,
        "alice-tag-456",
        "bob-tag-789",
        "test-call-id-123",
    );
    dialog_inner.transition(DialogState::Early(dialog_id.clone(), ringing_resp))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Early(_, _)));

    // Test transition to Confirmed
    dialog_inner.transition(DialogState::Confirmed(
        dialog_id.clone(),
        Response::default(),
    ))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Confirmed(_, _)));
    assert!(dialog_inner.is_confirmed());

    // Test transition to Terminated
    dialog_inner.transition(DialogState::Terminated(
        dialog_id.clone(),
        TerminatedReason::Timeout,
    ))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Terminated(_, _)));

    Ok(())
}

#[tokio::test]
async fn test_server_dialog_state_transitions() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();

    // Create dialog ID
    let dialog_id = DialogId {
        call_id: "test-call-id-server-123".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    // Create INVITE request
    let invite_req = create_invite_request("alice-tag-456", "", "test-call-id-server-123");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    // Create server dialog inner
    let dialog_inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:bob@bob.example.com:5060")?),
        tu_sender,
    )?;

    // Test initial state
    let initial_state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(initial_state, DialogState::Calling(_)));

    // Test transition to Trying (server sends 100 Trying)
    dialog_inner.transition(DialogState::Trying(dialog_id.clone()))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Trying(_)));

    // Test transition to WaitAck (server sends 200 OK)
    let ok_resp = create_response(
        StatusCode::OK,
        "alice-tag-456",
        "bob-tag-789",
        "test-call-id-server-123",
    );
    dialog_inner.transition(DialogState::WaitAck(dialog_id.clone(), ok_resp.clone()))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::WaitAck(_, _)));

    // Test transition to Confirmed (after receiving ACK)
    dialog_inner.transition(DialogState::Confirmed(dialog_id.clone(), ok_resp))?;
    let state = dialog_inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Confirmed(_, _)));
    assert!(dialog_inner.is_confirmed());

    Ok(())
}

#[tokio::test]
async fn test_dialog_in_dialog_requests() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();

    // Create dialog ID
    let dialog_id = DialogId {
        call_id: "test-call-id-in-dialog-123".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    // Create initial INVITE request
    let invite_req =
        create_invite_request("alice-tag-456", "bob-tag-789", "test-call-id-in-dialog-123");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    // Create confirmed dialog
    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    // Set dialog to confirmed state
    dialog_inner.transition(DialogState::Confirmed(
        dialog_id.clone(),
        Response::default(),
    ))?;
    assert!(dialog_inner.is_confirmed());

    // Test INFO request in dialog
    let info_req = Request {
        method: rsip::Method::Info,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-info").into(),
            CSeq::new("2 INFO").into(),
            From::new("Alice <sip:alice@example.com>;tag=alice-tag-456").into(),
            To::new("Bob <sip:bob@example.com>;tag=bob-tag-789").into(),
            CallId::new("test-call-id-in-dialog-123").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: vec![],
    };

    let (handle, _) = TransactionHandle::new();
    dialog_inner.transition(DialogState::Info(dialog_id.clone(), info_req, handle))?;

    // Test UPDATE request in dialog
    let update_req = Request {
        method: rsip::Method::Update,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-update").into(),
            CSeq::new("3 UPDATE").into(),
            From::new("Alice <sip:alice@example.com>;tag=alice-tag-456").into(),
            To::new("Bob <sip:bob@example.com>;tag=bob-tag-789").into(),
            CallId::new("test-call-id-in-dialog-123").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: b"v=0\r\no=alice 2890844526 2890844528 IN IP4 host.atlanta.com\r\n".to_vec(),
    };

    let (handle, _) = TransactionHandle::new();
    dialog_inner.transition(DialogState::Updated(dialog_id.clone(), update_req, handle))?;

    // Test OPTIONS request in dialog
    let options_req = Request {
        method: rsip::Method::Options,
        uri: rsip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-options").into(),
            CSeq::new("4 OPTIONS").into(),
            From::new("Alice <sip:alice@example.com>;tag=alice-tag-456").into(),
            To::new("Bob <sip:bob@example.com>;tag=bob-tag-789").into(),
            CallId::new("test-call-id-in-dialog-123").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: vec![],
    };

    let (handle, _) = TransactionHandle::new();
    dialog_inner.transition(DialogState::Options(dialog_id.clone(), options_req, handle))?;

    // Dialog should still be confirmed after in-dialog requests
    assert!(dialog_inner.is_confirmed());

    Ok(())
}

#[tokio::test]
async fn test_dialog_termination_scenarios() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();

    // Test 1: Termination with error status code
    let dialog_id_1 = DialogId {
        call_id: "test-call-id-term-1".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    let invite_req_1 = create_invite_request("alice-tag-456", "", "test-call-id-term-1");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner_1 = DialogInner::new(
        TransactionRole::Client,
        dialog_id_1.clone(),
        invite_req_1,
        endpoint.inner.clone(),
        state_sender.clone(),
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    // Terminate with error
    dialog_inner_1.transition(DialogState::Terminated(
        dialog_id_1.clone(),
        TerminatedReason::UasBusy,
    ))?;
    let state = dialog_inner_1.state.lock().unwrap().clone();
    assert!(matches!(
        state,
        DialogState::Terminated(_, TerminatedReason::UasBusy)
    ));

    // Test 2: Normal termination (BYE)
    let dialog_id_2 = DialogId {
        call_id: "test-call-id-term-2".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    let invite_req_2 = create_invite_request("alice-tag-456", "bob-tag-789", "test-call-id-term-2");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner_2 = DialogInner::new(
        TransactionRole::Client,
        dialog_id_2.clone(),
        invite_req_2,
        endpoint.inner.clone(),
        state_sender.clone(),
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    // First confirm the dialog
    dialog_inner_2.transition(DialogState::Confirmed(
        dialog_id_2.clone(),
        Response::default(),
    ))?;
    assert!(dialog_inner_2.is_confirmed());

    // Then terminate normally
    dialog_inner_2.transition(DialogState::Terminated(
        dialog_id_2.clone(),
        TerminatedReason::UacBye,
    ))?;
    let state = dialog_inner_2.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Terminated(_, _)));

    Ok(())
}

#[tokio::test]
async fn test_dialog_sequence_numbers() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _state_receiver) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-id-seq-123".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    let invite_req = create_invite_request("alice-tag-456", "bob-tag-789", "test-call-id-seq-123");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    // Test initial sequence number
    let initial_seq = dialog_inner.get_local_seq();
    assert_eq!(initial_seq, 1); // Based on CSeq from initial request

    // Test increment
    let next_seq = dialog_inner.increment_local_seq();
    assert_eq!(next_seq, 2);
    assert_eq!(dialog_inner.get_local_seq(), 2);

    Ok(())
}

#[tokio::test]
async fn test_dialog_state_display() -> crate::Result<()> {
    let dialog_id = DialogId {
        call_id: "test-call-id-display".to_string(),
        local_tag: "alice-tag".to_string(),
        remote_tag: "bob-tag".to_string(),
    };

    // Test all state display formats
    let calling_state = DialogState::Calling(dialog_id.clone());
    assert!(calling_state.to_string().contains("Calling"));

    let trying_state = DialogState::Trying(dialog_id.clone());
    assert!(trying_state.to_string().contains("Trying"));

    let confirmed_state = DialogState::Confirmed(dialog_id.clone(), Response::default());
    assert!(confirmed_state.to_string().contains("Confirmed"));
    assert!(confirmed_state.is_confirmed());

    let terminated_state = DialogState::Terminated(dialog_id.clone(), TerminatedReason::Timeout);
    assert!(terminated_state.to_string().contains("Terminated"));
    assert!(terminated_state.to_string().contains("Timeout"));

    Ok(())
}

#[tokio::test]
async fn test_dialog_id_creation() -> crate::Result<()> {
    // Test from Request (UAS perspective)
    let request = create_invite_request("alice-tag-123", "", "call-id-456");
    let dialog_id = DialogId::from_uas_request(&request)?;
    assert_eq!(dialog_id.call_id, "call-id-456");
    assert_eq!(dialog_id.local_tag, "");
    assert_eq!(dialog_id.remote_tag, "alice-tag-123");

    // Test from Request (UAC perspective)
    let dialog_id_uac = DialogId::from_uac_request(&request)?;
    assert_eq!(dialog_id_uac.local_tag, "alice-tag-123");
    assert_eq!(dialog_id_uac.remote_tag, "");

    // Test from Response (UAC perspective)
    let response = create_response(
        StatusCode::OK,
        "alice-tag-123",
        "bob-tag-789",
        "call-id-456",
    );
    let dialog_id_resp = DialogId::from_uac_response(&response)?;
    assert_eq!(dialog_id_resp.call_id, "call-id-456");
    assert_eq!(dialog_id_resp.local_tag, "alice-tag-123");
    assert_eq!(dialog_id_resp.remote_tag, "bob-tag-789");

    // Test from Response (UAS perspective)
    let dialog_id_resp_uas = DialogId::from_uas_response(&response)?;
    assert_eq!(dialog_id_resp_uas.local_tag, "bob-tag-789");
    assert_eq!(dialog_id_resp_uas.remote_tag, "alice-tag-123");

    // Test display
    let display_str = dialog_id_resp.to_string();
    assert!(display_str.contains("call-id-456"));
    assert!(display_str.contains("alice-tag-123"));
    assert!(display_str.contains("bob-tag-789"));

    Ok(())
}
