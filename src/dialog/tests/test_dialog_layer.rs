//! Dialog layer tests
//!
//! This module contains tests for dialog management and lifecycle

use crate::dialog::{dialog_layer::DialogLayer, DialogId};
use crate::sip::{headers::*, prelude::HeadersExt, HostWithPort, Param, Transport, Request};
use crate::transaction::{
    endpoint::EndpointBuilder,
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{
    tcp_listener::TcpListenerConnection, udp::UdpConnection, SipAddr, TransportLayer,
};
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
fn create_invite_request(from_tag: &str, to_tag: &str, call_id: &str, branch: &str) -> Request {
    Request {
        method: crate::sip::Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com:5060").unwrap(),
        headers: vec![
            Via::new(&format!(
                "SIP/2.0/UDP alice.example.com:5060;branch={}",
                branch
            ))
            .into(),
            CSeq::new("1 INVITE").into(),
            From::new(&format!("Alice <sip:alice@example.com>;tag={}", from_tag)).into(),
            To::new(&format!("Bob <sip:bob@example.com>;tag={}", to_tag)).into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:alice@alice.example.com:5060>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    // Dialog should be created and stored
    assert_eq!(dialog_layer.len(), 1);

    // Dialog ID should have generated to-tag
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
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
        Some(mock_conn.clone()),
    );

    let (state_sender, _) = unbounded_channel();

    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog.id();

    // Test direct retrieval
    let retrieved_dialog = dialog_layer.get_dialog(&dialog_id);
    assert!(retrieved_dialog.is_some());

    // Test request matching
    let bye_req = Request {
        method: crate::sip::Method::Bye,
        uri: crate::sip::Uri::try_from("sip:bob@example.com:5060")?,
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKbye").into(),
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
        version: crate::sip::Version::V2,
        body: vec![],
    };

    let bye_key = TransactionKey::from_request(&bye_req, TransactionRole::Server)?;
    let bye_tx = Transaction::new_server(bye_key, bye_req, endpoint.inner.clone(), Some(mock_conn));
    let matched_dialog = dialog_layer.match_dialog(&bye_tx);
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    let dialog_id = dialog.id();

    // Create a swapped dialog ID (as if from the other perspective)
    let swapped_id = DialogId {
        call_id: dialog_id.call_id.clone(),
        local_tag: dialog_id.remote_tag.clone(),
        remote_tag: dialog_id.local_tag.clone(),
    };

    // Swapped tags should NOT match the server-side dialog ID
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
        let from_tag = format!("alice-tag-{}", i);
        let branch = format!("z9hG4bKnashds{}", i);

        let invite_req = create_invite_request(&from_tag, "", &call_id, &branch);
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
            Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
        )?;
    }

    // Should have 5 dialogs
    assert_eq!(dialog_layer.len(), 5);

    // Remove one dialog
    let _test_id = DialogId {
        call_id: "test-call-2".to_string(),
        local_tag: "".to_string(),
        remote_tag: "alice-tag-2".to_string(), // We need to find the actual dialog first
    };

    // Find all dialogs to get the actual IDs
    let mut dialog_ids = vec![];
    for i in 0..5 {
        let call_id = format!("call-id-{}", i);
        let from_tag = format!("alice-tag-{}", i);
        let _partial_id = DialogId {
            call_id: call_id.clone(),
            local_tag: "".to_string(),
            remote_tag: from_tag.clone(),
        };

        // Try to find dialog by creating a request and matching
        let test_req = create_invite_request(&from_tag, "", &call_id, "test-branch");
        let test_key = TransactionKey::from_request(&test_req, TransactionRole::Server)?;
        let test_tx = Transaction::new_server(
            test_key,
            test_req,
            endpoint.inner.clone(),
            Some(mock_conn.clone()),
        );
        if let Some(dialog) = dialog_layer.match_dialog(&test_tx) {
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
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    );

    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_server_invite_dialog_with_tcp_transport() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    // Create a TCP listener connection (without binding a socket)
    let tcp_addr = SipAddr {
        r#type: Some(Transport::Tcp),
        addr: HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
            )),
            port: Some(5060.into()),
        },
    };
    let tcp_listener = TcpListenerConnection::new(tcp_addr.clone(), None).await?;
    let conn: crate::transport::SipConnection = tcp_listener.into();

    // Create INVITE request
    let invite_req = create_invite_request("alice-tcp-tag", "", "call-id-tcp", "z9hG4bKtcp");
    let key = TransactionKey::from_request(&invite_req, TransactionRole::Server)?;
    let tx = Transaction::new_server(
        key,
        invite_req.clone(),
        endpoint.inner.clone(),
        Some(conn),
    );

    let (state_sender, _state_receiver) = unbounded_channel();

    let dialog = dialog_layer.get_or_create_server_invite(
        &tx,
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@bob.example.com:5060")?),
    )?;

    // Dialog should be created
    assert_eq!(dialog_layer.len(), 1);

    // The remote_uri should have a Transport::Tcp param added
    let remote_uri = dialog.inner.remote_uri.lock();
    let has_tcp_transport = remote_uri
        .params
        .iter()
        .any(|p| matches!(p, Param::Transport(Transport::Tcp)));
    assert!(
        has_tcp_transport,
        "expected Transport::Tcp param in remote_uri, got params: {:?}",
        remote_uri.params
    );

    Ok(())
}

#[tokio::test]
async fn test_make_invite_request_with_tcp_transport() -> crate::Result<()> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    // Add a TCP listener address to the transport layer
    let tcp_addr = SipAddr {
        r#type: Some(Transport::Tcp),
        addr: HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(192, 168, 1, 10),
            )),
            port: Some(5060.into()),
        },
    };
    let tcp_listener = TcpListenerConnection::new(tcp_addr.clone(), None).await?;
    tl.add_transport(crate::transport::SipConnection::TcpListener(tcp_listener));

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let destination = SipAddr {
        r#type: Some(Transport::Tcp),
        addr: HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            )),
            port: Some(5060.into()),
        },
    };

    let opt = crate::dialog::invitation::InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com")?,
        callee: crate::sip::Uri::try_from("sip:bob@example.com")?,
        contact: crate::sip::Uri::try_from("sip:alice@192.168.1.10:5060")?,
        destination: Some(destination),
        ..Default::default()
    };

    let request = dialog_layer.make_invite_request(&opt)?;

    // Verify Contact header has the transport layer's TCP address and transport param
    let contact = request.contact_header()?.typed()?;
    assert_eq!(
        contact.uri.host_with_port,
        tcp_addr.addr,
        "Contact URI should use the transport layer's TCP address"
    );
    assert!(
        contact
            .uri
            .params
            .iter()
            .any(|p| matches!(p, Param::Transport(Transport::Tcp))),
        "Contact should have Transport::Tcp param, got: {:?}",
        contact.uri.params
    );
    assert_eq!(
        contact.uri.scheme,
        Some(crate::sip::Scheme::Sip),
        "TCP contact should have sip scheme"
    );

    Ok(())
}

#[tokio::test]
async fn test_make_invite_request_without_transport_uses_contact_as_is() -> crate::Result<()> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    // Add a UDP address so get_via has an address to use
    let udp_conn = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    tl.add_transport(crate::transport::SipConnection::Udp(udp_conn));

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let opt = crate::dialog::invitation::InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com")?,
        callee: crate::sip::Uri::try_from("sip:bob@example.com")?,
        contact: crate::sip::Uri::try_from("sip:alice@192.168.1.10:5060")?,
        ..Default::default()
    };

    let request = dialog_layer.make_invite_request(&opt)?;
    let contact = request.contact_header()?.typed()?;

    // When no destination transport, contact should remain unchanged
    assert_eq!(
        contact.uri, opt.contact,
        "Contact should remain unchanged when no transport destination"
    );

    Ok(())
}

#[tokio::test]
async fn test_make_invite_request_with_tls_transport_uses_sips_scheme() -> crate::Result<()> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    // Add a TLS listener address
    let tls_addr = SipAddr {
        r#type: Some(Transport::Tls),
        addr: HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(192, 168, 1, 10),
            )),
            port: Some(5061.into()),
        },
    };
    let tcp_listener = TcpListenerConnection::new(tls_addr.clone(), None).await?;
    tl.add_transport(crate::transport::SipConnection::TcpListener(tcp_listener));

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let destination = SipAddr {
        r#type: Some(Transport::Tls),
        addr: HostWithPort {
            host: crate::sip::Host::IpAddr(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            )),
            port: Some(5061.into()),
        },
    };

    let opt = crate::dialog::invitation::InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com")?,
        callee: crate::sip::Uri::try_from("sip:bob@example.com")?,
        contact: crate::sip::Uri::try_from("sip:alice@192.168.1.10:5061")?,
        destination: Some(destination),
        ..Default::default()
    };

    let request = dialog_layer.make_invite_request(&opt)?;
    let contact = request.contact_header()?.typed()?;

    // TLS should use sips scheme
    assert_eq!(
        contact.uri.scheme,
        Some(crate::sip::Scheme::Sips),
        "TLS contact should have sips scheme"
    );
    assert!(
        contact
            .uri
            .params
            .iter()
            .any(|p| matches!(p, Param::Transport(Transport::Tls))),
        "Contact should have Transport::Tls param"
    );

    Ok(())
}
