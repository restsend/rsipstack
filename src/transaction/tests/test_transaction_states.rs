//! Transaction state transition tests
//!
//! This module contains comprehensive tests for transaction state transitions
//! according to RFC 3261 Section 17.

use super::create_test_endpoint;
use crate::sip::headers::*;
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
    TransactionState, TransactionTimer, TransactionType,
};
use crate::transport::udp::UdpConnection;
use crate::transport::SipConnection;

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

// ===========================================================================
// RFC 6026 conformance tests
//
// Validate the Accepted state and Timer L / Timer M behaviour required by
// RFC 6026 §7.1 (server INVITE) + §7.2 (client INVITE).
//
// Test design notes:
// - Display-impl tests are pure unit tests — no async setup required.
// - State-machine tests use a mock UDP connection bound to 127.0.0.1:0
//   so respond() can issue a real UDP send into the void; UDP is
//   connectionless so the send succeeds even with no peer listener,
//   letting the state transition fire without a full peer orchestration.
// - Timer L / Timer M actually firing (transitioning Accepted → Terminated
//   after 64*T1 ≈ 32s) is NOT exercised here because waiting 32s per test
//   would balloon the suite runtime; instead these tests verify
//   timer_l.is_some() / timer_m.is_some() to confirm the timers are armed.
//   The transition logic itself is exercised by the unit-level state
//   machine in transaction.rs on_timer dispatch.
// ===========================================================================

/// Helper: mock UDP connection on localhost for tests that exercise respond().
/// The connection sends UDP packets to a bogus loopback port — UDP is
/// connectionless so the send succeeds (packets are dropped at the OS).
async fn mock_udp_connection() -> crate::Result<SipConnection> {
    let conn = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    Ok(conn.into())
}

#[test]
fn test_rfc6026_accepted_state_display() {
    // RFC 6026 §7.1/§7.2 exposes the Accepted state via the public
    // TransactionState Display impl. Lock the rendering so external
    // observers (logs, metrics, debug dumps) see "Accepted".
    assert_eq!(
        format!("{}", TransactionState::Accepted),
        "Accepted",
        "TransactionState::Accepted must Display as `Accepted` (RFC 6026 §7.1/§7.2)",
    );
}

#[test]
fn test_rfc6026_timer_l_display() {
    // RFC 6026 §7.1 server INVITE Accepted-state timer.
    let request = crate::sip::Request {
        method: crate::sip::Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP example.com:5060;branch=z9hG4bKtimerL").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=t1").into(),
            CallId::new("call-l@example.com").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    };
    let key = TransactionKey::from_request(&request, TransactionRole::Server).unwrap();
    let timer = TransactionTimer::TimerL(key.clone());
    assert_eq!(format!("{}", timer), format!("TimerL: {}", key));
}

#[test]
fn test_rfc6026_timer_m_display() {
    // RFC 6026 §7.2 client INVITE Accepted-state timer.
    let request = crate::sip::Request {
        method: crate::sip::Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP example.com:5060;branch=z9hG4bKtimerM").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=t1").into(),
            CallId::new("call-m@example.com").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    };
    let key = TransactionKey::from_request(&request, TransactionRole::Client).unwrap();
    let timer = TransactionTimer::TimerM(key.clone());
    assert_eq!(format!("{}", timer), format!("TimerM: {}", key));
}

#[tokio::test]
async fn test_rfc6026_server_invite_2xx_routes_to_accepted_with_timer_l() -> crate::Result<()> {
    // RFC 6026 §7.1: server INVITE 2xx final response transitions
    // Proceeding/Trying → Accepted (NOT Completed), and arms Timer L.
    // Concurrently, Timer G must NOT be started for 2xx (§7.1 prohibits
    // the server transaction from retransmitting 2xx on its own).
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srv2xx");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    tx.reply(crate::sip::StatusCode::OK).await?;

    assert_eq!(
        tx.state,
        TransactionState::Accepted,
        "server INVITE 2xx must route to Accepted per RFC 6026 §7.1, not Completed",
    );
    assert!(
        tx.timer_l.is_some(),
        "Accepted state must arm Timer L (= 64*T1) per RFC 6026 §7.1",
    );
    assert!(
        tx.timer_g.is_none(),
        "Accepted state must NOT arm Timer G — RFC 6026 §7.1 prohibits the server transaction from retransmitting 2xx",
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc6026_server_invite_4xx_still_routes_to_completed() -> crate::Result<()> {
    // RFC 3261 §17.2.1 regression: non-2xx final responses (3xx-6xx) must
    // continue to route to Completed (not Accepted) so the existing Timer G
    // retransmit + Timer K + Timer D semantics for ACK matching are preserved.
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srv404");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    tx.reply(crate::sip::StatusCode::NotFound).await?;

    assert_eq!(
        tx.state,
        TransactionState::Completed,
        "server INVITE 4xx must continue to route to Completed (RFC 3261 §17.2.1 retained)",
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc6026_server_invite_accepted_registers_waiting_ack() -> crate::Result<()> {
    // RFC 6026 §7.1: when a server INVITE transaction enters Accepted, it
    // MUST register itself in the dialog-layer ACK routing map so the
    // forthcoming ACK (sent by the UAC outside this transaction per
    // §17.1.1.3) lands at this transaction key. The waiting_ack map keyed
    // by DialogId is rsipstack's canonical routing primitive.
    use crate::dialog::DialogId;

    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srvack");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    tx.reply(crate::sip::StatusCode::OK).await?;

    // The 200 OK has been stored as last_response; derive the dialog_id
    // (server role) and check that the waiting_ack map points back to us.
    let last_response = tx
        .last_response
        .as_ref()
        .expect("respond() must store the 2xx in last_response");
    let dialog_id = DialogId::try_from((last_response, TransactionRole::Server))?;
    let registered = endpoint.inner.waiting_ack.get(&dialog_id);
    assert!(
        registered.is_some(),
        "Accepted-state entry must register the dialog in waiting_ack for ACK routing per RFC 6026 §7.1",
    );
    assert_eq!(
        registered.expect("registered").value(),
        &key,
        "waiting_ack entry must point back to this transaction key",
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc6026_server_invite_3xx_still_arms_timer_g() -> crate::Result<()> {
    // RFC 6026 §7.1 retains Timer G for non-2xx final responses
    // (the §7.1 prohibition is "MUST NOT generate 2xx retransmissions",
    // explicitly NOT a blanket ban). This regression test ensures the
    // server-side 3xx-6xx Timer G retransmit path remains live.
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srvtimerg");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    tx.reply(crate::sip::StatusCode::ServerInternalError)
        .await?;

    assert_eq!(tx.state, TransactionState::Completed);
    assert!(
        tx.timer_g.is_some(),
        "non-2xx final must continue to arm Timer G (RFC 3261 §17.2.1 retained; RFC 6026 §7.1 only prohibits 2xx retransmits)",
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc6026_server_invite_accepted_absorbs_duplicate_2xx() -> crate::Result<()> {
    // RFC 6026 §7.1: 'absorb retransmissions of the INVITE after a 2xx
    // response has been sent' implies the server transaction MUST tolerate
    // a TU-retransmitted 2xx in the Accepted state — the response is
    // re-sent through the transport but no state error is raised. The
    // can_transition() (Accepted, Accepted) self-loop edge enables this.
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srvdup");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    let response_1 = tx.reply(crate::sip::StatusCode::OK).await;
    response_1?;
    assert_eq!(tx.state, TransactionState::Accepted);

    // Second TU-driven 2xx (e.g. retransmit per §7.1 forwarding rule):
    // must succeed without state-machine error; transaction stays in
    // Accepted (the (Accepted, Accepted) edge in can_transition).
    tx.reply(crate::sip::StatusCode::OK).await?;
    assert_eq!(
        tx.state,
        TransactionState::Accepted,
        "duplicate 2xx in Accepted must keep the transaction in Accepted, not raise a transition error",
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc6026_server_invite_accepted_rejects_3xx_transition() -> crate::Result<()> {
    // can_transition matrix: once a server INVITE has entered Accepted (2xx
    // already sent), a subsequent 3xx-6xx attempt must be rejected. The
    // matrix has no (Accepted, Completed) edge so respond() should error.
    let endpoint = create_test_endpoint(Some("127.0.0.1:0")).await?;
    let conn = mock_udp_connection().await?;

    let invite_req = create_test_request(crate::sip::Method::Invite, "z9hG4bK6026srvreject");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;

    let mut tx = Transaction::new_server(
        key.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );
    tx.destination = Some(crate::transport::SipAddr::from(
        "127.0.0.1:1".parse::<std::net::SocketAddr>()?,
    ));

    tx.reply(crate::sip::StatusCode::OK).await?;
    assert_eq!(tx.state, TransactionState::Accepted);

    // Now try sending a 4xx — this is illegal per the can_transition matrix
    // (Accepted has no edge to Completed). reply() should return an Err.
    let err = tx.reply(crate::sip::StatusCode::BusyHere).await;
    assert!(
        err.is_err(),
        "reply() must reject Accepted → Completed (no such edge in can_transition matrix)",
    );
    Ok(())
}
