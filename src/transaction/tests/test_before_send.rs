use crate::sip::headers::*;
use crate::sip::{SipMessage, Uri};
use crate::transaction::endpoint::MessageInspector;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::TransactionState;
use crate::transport::SipAddr;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct TestInspector {
    before_send_called: Arc<AtomicBool>,
}

impl MessageInspector for TestInspector {
    fn before_send(&self, msg: SipMessage, _dest: Option<&SipAddr>) -> SipMessage {
        self.before_send_called.store(true, Ordering::SeqCst);
        msg
    }

    fn after_received(&self, msg: SipMessage, _from: Option<&SipAddr>) -> SipMessage {
        msg
    }
}

fn make_request(uri: &str) -> crate::sip::Request {
    crate::sip::Request {
        method: crate::sip::Method::Bye,
        uri: crate::sip::Uri::try_from(uri).expect("valid uri"),
        headers: vec![
            Via::new("SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK1").into(),
            CSeq::new("1 BYE").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>;tag=to-tag").into(),
            CallId::new("callid@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

#[tokio::test]
async fn test_before_send_called_and_transaction_enters_calling_on_dns_failure() {
    let called = Arc::new(AtomicBool::new(false));
    let inspector = TestInspector {
        before_send_called: called.clone(),
    };

    let endpoint = super::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_inspector(Box::new(inspector))
        .build();

    let request = make_request("sip:user@invalid.invalid;transport=udp");

    let key =
        TransactionKey::from_request(&request, TransactionRole::Client).expect("transaction key");
    let mut tx = Transaction::new_client(key, request, endpoint.inner.clone(), None);

    let result = tx.send().await;
    assert!(result.is_ok(), "send() must return Ok even on DNS failure");

    assert_eq!(
        tx.state,
        TransactionState::Calling,
        "transaction must be in Calling state after send()"
    );

    assert!(
        called.load(Ordering::SeqCst),
        "before_send must have been called even though DNS resolution failed"
    );
}

fn make_invite_request(uri: &str) -> crate::sip::Request {
    crate::sip::Request {
        method: crate::sip::Method::Invite,
        uri: crate::sip::Uri::try_from(uri).expect("valid uri"),
        headers: vec![
            Via::new("SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK1").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("callid@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

#[tokio::test]
async fn test_send_ack_transitions_to_terminated_without_connection() {
    let called = Arc::new(AtomicBool::new(false));
    let inspector = TestInspector {
        before_send_called: called.clone(),
    };

    let endpoint = super::EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_inspector(Box::new(inspector))
        .build();

    // Must use INVITE so new_client creates ClientInvite (send_ack requires it)
    let request = make_invite_request("sip:user@invalid.invalid;transport=udp");
    let key =
        TransactionKey::from_request(&request, TransactionRole::Client).expect("transaction key");
    let mut tx = Transaction::new_client(key, request, endpoint.inner.clone(), None);

    // Manually set state to Completed (as if we received a final response)
    tx.state = TransactionState::Completed;

    // Pre-set a simple ACK request so send_ack doesn't need to call make_ack
    let ack = crate::sip::Request {
        method: crate::sip::Method::Ack,
        uri: Uri::try_from("sip:bob@invalid.invalid").expect("valid uri"),
        headers: vec![
            Via::new("SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK2").into(),
            CSeq::new("1 ACK").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>;tag=to-tag").into(),
            CallId::new("callid@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    };
    tx.last_ack = Some(ack);

    // send_ack with no connection available
    let result = tx.send_ack(None).await;
    assert!(
        result.is_ok(),
        "send_ack must return Ok even without connection, got: {:?}",
        result
    );

    assert_eq!(
        tx.state,
        TransactionState::Terminated,
        "transaction must transition to Terminated after send_ack"
    );

    assert!(
        called.load(Ordering::SeqCst),
        "before_send must have been called in send_ack even without connection"
    );
}

#[tokio::test]
async fn test_normal_bye_send_succeeds_with_valid_transport() {
    let endpoint = super::create_test_endpoint(Some("127.0.0.1:0"))
        .await
        .expect("create_test_endpoint");

    let server_addr = endpoint
        .get_addrs()
        .first()
        .expect("must have connection")
        .to_owned();

    // Create a request targeting the server
    let request = crate::sip::Request {
        method: crate::sip::Method::Bye,
        uri: crate::sip::Uri {
            scheme: Some(crate::sip::Scheme::Sip),
            host_with_port: server_addr.addr.clone(),
            ..Default::default()
        },
        headers: vec![
            Via::new("SIP/2.0/UDP uac.example.com:5060;branch=z9hG4bK1").into(),
            CSeq::new("1 BYE").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>;tag=to-tag").into(),
            CallId::new("callid@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    };

    let key =
        TransactionKey::from_request(&request, TransactionRole::Client).expect("transaction key");
    let mut tx = Transaction::new_client(key, request, endpoint.inner.clone(), None);

    let result = tx.send().await;
    assert!(result.is_ok(), "BYE send to valid transport must succeed");
    assert_eq!(
        tx.state,
        TransactionState::Calling,
        "transaction must be in Calling state after successful send"
    );
}
