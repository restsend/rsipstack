use crate::transaction::endpoint::TargetLocator;
use crate::transaction::key::TransactionRole;
use crate::transport::transport_layer::DomainResolver;
use crate::transport::SipConnection;
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use crate::{
    dialog::{
        client_dialog::ClientInviteDialog,
        dialog::{DialogInner, DialogState, TerminatedReason},
        DialogId,
    },
    rsip_ext::destination_from_request,
};
use async_trait::async_trait;
use rsip::{headers::*, prelude::HeadersExt, Request, Response, StatusCode, Uri};
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::oneshot;
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

fn create_invite_request(from_tag: &str, to_tag: &str, call_id: &str) -> Request {
    Request {
        method: rsip::Method::Invite,
        uri: Uri::try_from("sip:bob@example.com:5060").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new(&format!("Alice <sip:alice@example.com>;tag={}", from_tag)).into(),
            To::new(&format!("Bob <sip:bob@example.com>;tag={}", to_tag)).into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:alice@alice.example.com:5060>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: rsip::Version::V2,
        body: b"v=0\r\no=alice 2890844526 2890844527 IN IP4 host.atlanta.com\r\n".to_vec(),
    }
}

#[tokio::test]
async fn test_client_dialog_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-id".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "bob-tag".to_string(),
    };

    let invite_req = create_invite_request("alice-tag", "", "test-call-id");
    let (tu_sender, _tu_receiver) = unbounded_channel();
    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060").unwrap()),
        tu_sender,
    )?;

    let client_dialog = ClientInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Test initial state
    assert_eq!(client_dialog.id(), dialog_id);
    assert!(!client_dialog.inner.is_confirmed());

    Ok(())
}

#[tokio::test]
async fn test_client_dialog_sequence_handling() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-seq".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "bob-tag".to_string(),
    };

    let invite_req = create_invite_request("alice-tag", "bob-tag", "test-call-seq");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060").unwrap()),
        tu_sender,
    )?;

    let client_dialog = ClientInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Test initial sequence
    let initial_seq = client_dialog.inner.get_local_seq();
    assert_eq!(initial_seq, 1);

    // Test sequence increment
    let next_seq = client_dialog.inner.increment_local_seq();
    assert_eq!(next_seq, 2);

    Ok(())
}

#[tokio::test]
async fn test_client_dialog_state_transitions() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "test-call-flow".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "".to_string(),
    };

    let invite_req = create_invite_request("alice-tag", "", "test-call-flow");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060").unwrap()),
        tu_sender,
    )?;

    let client_dialog = ClientInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Test state transitions manually (simulating what happens during invite flow)

    // Initial state should be Calling
    let state = client_dialog.inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Calling(_)));

    // Transition to Trying (after sending INVITE)
    client_dialog
        .inner
        .transition(DialogState::Trying(dialog_id.clone()))?;
    let state = client_dialog.inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Trying(_)));

    // Transition to Early (after receiving 1xx)
    let ringing_resp = Response {
        status_code: StatusCode::Ringing,
        version: rsip::Version::V2,
        headers: vec![
            Via::new("SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bKnashds").into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
            To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
            CallId::new("test-call-flow").into(),
            Contact::new("<sip:bob@bob.example.com:5060>").into(),
        ]
        .into(),
        body: vec![],
    };

    client_dialog
        .inner
        .transition(DialogState::Early(dialog_id.clone(), ringing_resp.clone()))?;
    let state = client_dialog.inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Early(_, _)));

    let mut final_resp = ringing_resp.clone();
    final_resp.status_code = StatusCode::OK;
    // Transition to Confirmed (after receiving 200 OK and sending ACK)
    client_dialog
        .inner
        .transition(DialogState::Confirmed(dialog_id.clone(), final_resp))?;
    let state = client_dialog.inner.state.lock().unwrap().clone();
    assert!(matches!(state, DialogState::Confirmed(_, _)));
    assert!(client_dialog.inner.is_confirmed());

    Ok(())
}

#[tokio::test]
async fn test_client_dialog_termination_scenarios() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    // Test 1: Early termination (before confirmed)
    let dialog_id_1 = DialogId {
        call_id: "test-call-term-early".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "".to_string(),
    };

    let invite_req_1 = create_invite_request("alice-tag", "", "test-call-term-early");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner_1 = DialogInner::new(
        TransactionRole::Client,
        dialog_id_1.clone(),
        invite_req_1,
        endpoint.inner.clone(),
        state_sender.clone(),
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060").unwrap()),
        tu_sender,
    )?;

    let client_dialog_1 = ClientInviteDialog {
        inner: Arc::new(dialog_inner_1),
    };

    // Terminate early with error
    client_dialog_1.inner.transition(DialogState::Terminated(
        dialog_id_1.clone(),
        TerminatedReason::UasBusy,
    ))?;

    let state = client_dialog_1.inner.state.lock().unwrap().clone();
    assert!(matches!(
        state,
        DialogState::Terminated(_, TerminatedReason::UasBusy)
    ));

    // Test 2: Normal termination after confirmed
    let dialog_id_2 = DialogId {
        call_id: "test-call-term-normal".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "bob-tag".to_string(),
    };

    let invite_req_2 = create_invite_request("alice-tag", "bob-tag", "test-call-term-normal");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner_2 = DialogInner::new(
        TransactionRole::Client,
        dialog_id_2.clone(),
        invite_req_2,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060").unwrap()),
        tu_sender,
    )?;

    let client_dialog_2 = ClientInviteDialog {
        inner: Arc::new(dialog_inner_2),
    };
    // Confirm dialog first
    client_dialog_2.inner.transition(DialogState::Confirmed(
        dialog_id_2.clone(),
        Response::default(),
    ))?;
    assert!(client_dialog_2.inner.is_confirmed());

    // Then terminate normally
    client_dialog_2.inner.transition(DialogState::Terminated(
        dialog_id_2.clone(),
        TerminatedReason::UacBye,
    ))?;
    let state = client_dialog_2.inner.state.lock().unwrap().clone();
    assert!(matches!(
        state,
        DialogState::Terminated(_, TerminatedReason::UacBye)
    ));

    Ok(())
}

#[tokio::test]
async fn test_make_request_preserves_remote_target_and_route_order() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "route-order-call".to_string(),
        from_tag: "from-tag".to_string(),
        to_tag: "to-tag".to_string(),
    };

    let invite_req = create_invite_request("from-tag", "to-tag", "route-order-call");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id,
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    let client_dialog = ClientInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    let remote_target = Uri::try_from("sip:uas@192.0.2.55:5080;transport=tcp")?;
    *client_dialog.inner.remote_uri.lock().unwrap() = remote_target.clone();

    {
        let mut route_set = client_dialog.inner.route_set.lock().unwrap();
        *route_set = vec![
            Route::from("<sip:proxy2.example.com:5070;transport=tcp;lr>"),
            Route::from("<sip:proxy1.example.com:5060;transport=tcp;lr>"),
        ];
    }

    let outbound_addr =
        SipAddr::try_from(&Uri::try_from("sip:uac.example.com:5060;transport=tcp")?)?;
    let request = client_dialog.inner.make_request(
        rsip::Method::Bye,
        None,
        Some(outbound_addr),
        None,
        None,
        None,
    )?;

    assert_eq!(
        request.uri, remote_target,
        "Request-URI must stay the remote target"
    );

    let routes: Vec<String> = request
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert_eq!(
        routes,
        vec![
            "<sip:proxy2.example.com:5070;transport=tcp;lr>".to_string(),
            "<sip:proxy1.example.com:5060;transport=tcp;lr>".to_string()
        ],
        "Route headers must match the stored route set order"
    );
    let destination = destination_from_request(&request)
        .expect("route-enabled request should resolve to a destination");
    let expected_destination = Uri::try_from("sip:proxy2.example.com:5070;transport=tcp;lr")?;
    assert_eq!(
        &*destination, &expected_destination,
        "First Route entry must determine the transport destination"
    );

    Ok(())
}

#[tokio::test]
async fn test_route_set_updates_from_200_ok_response() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "route-update-call".to_string(),
        from_tag: "from-tag".to_string(),
        to_tag: "".to_string(),
    };

    let invite_req = create_invite_request("from-tag", "", "route-update-call");
    let (tu_sender, _tu_receiver) = unbounded_channel();

    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id,
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )?;

    let client_dialog = ClientInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    let remote_target = Uri::try_from("sip:uas@192.0.2.55:5088;transport=tcp")?;
    client_dialog
        .inner
        .set_remote_target(remote_target.clone(), None);

    let mut headers: Vec<Header> = vec![
        Via::new("SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKproxy").into(),
        CSeq::new("1 INVITE").into(),
        From::new("Alice <sip:alice@example.com>;tag=from-tag").into(),
        To::new("Bob <sip:bob@example.com>;tag=bob-tag").into(),
        CallId::new("route-update-call").into(),
        Header::RecordRoute(RecordRoute::new(
            "<sip:edge1.example.net:5070;transport=tcp;lr>",
        )),
        Header::RecordRoute(RecordRoute::new(
            "<sip:edge2.example.net:5080;transport=tcp;lr>",
        )),
    ];
    headers.push(ContentLength::new("0").into());

    let success_resp = Response {
        status_code: StatusCode::OK,
        version: rsip::Version::V2,
        headers: headers.into(),
        body: vec![],
    };

    client_dialog
        .inner
        .update_route_set_from_response(&success_resp);

    let outbound_addr =
        SipAddr::try_from(&Uri::try_from("sip:uac.example.com:5060;transport=tcp")?)?;
    let bye_request = client_dialog.inner.make_request(
        rsip::Method::Bye,
        None,
        Some(outbound_addr),
        None,
        None,
        None,
    )?;

    let routes: Vec<String> = bye_request
        .headers
        .iter()
        .filter_map(|header| match header {
            Header::Route(route) => Some(route.value().to_string()),
            _ => None,
        })
        .collect();

    assert_eq!(
        routes,
        vec![
            "<sip:edge2.example.net:5080;transport=tcp;lr>".to_string(),
            "<sip:edge1.example.net:5070;transport=tcp;lr>".to_string(),
        ],
        "Route set must be reversed compared to the Record-Route header order",
    );

    let destination = destination_from_request(&bye_request)
        .expect("route-enabled request should resolve to a destination");
    let expected_destination = Uri::try_from("sip:edge2.example.net:5080;transport=tcp;lr")?;
    assert_eq!(
        &*destination, &expected_destination,
        "First Route entry must determine the transport destination",
    );

    assert_eq!(
        bye_request.uri, remote_target,
        "Record-Route application must not change the remote target",
    );

    Ok(())
}

/// Verifies CANCEL request construction per RFC 3261 Section 9.1.
///
/// RFC 3261 9.1 states:
/// - Request-URI, Call-ID, To, the numeric part of CSeq, and From header
///   fields in the CANCEL request MUST be identical to those in the
///   request being cancelled, including tags.
/// - A CANCEL constructed by a client MUST have only a single Via header
///   field value matching the top Via value in the request being cancelled.
#[tokio::test]
async fn test_cancel_conforms_to_rfc3261_section_9_1() -> crate::Result<()> {
    use crate::dialog::{dialog_layer::DialogLayer, invitation::InviteOption};

    // Start a UDP listener to capture SIP messages
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let local_port = socket.local_addr()?.port();

    let endpoint = create_test_endpoint().await?;

    // Setup outbound transport for client
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(
            endpoint
                .inner
                .transport_layer
                .inner
                .cancel_token
                .child_token(),
        ),
    )
    .await?;
    endpoint.inner.transport_layer.add_transport(udp.into());

    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let invite_option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{};transport=udp", local_port).as_str())?,
        contact: Uri::try_from("sip:alice@alice.example.com:5060")?,
        ..Default::default()
    };

    let (state_sender, _) = unbounded_channel();

    // Use create_client_invite_dialog - creates dialog and transaction without sending
    let (client_dialog, mut tx) =
        dialog_layer.create_client_invite_dialog(invite_option, state_sender)?;

    tx.send().await?;

    // Receive the INVITE request first
    let mut buf = [0u8; 2048];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| rsip::Error::Unexpected("Timeout receiving INVITE".into()))??;

    let invite_msg = std::str::from_utf8(&buf[..len]).unwrap();
    let invite_req: Request = rsip::SipMessage::try_from(invite_msg)?.try_into()?;
    assert_eq!(invite_req.method, rsip::Method::Invite);

    let dialog_clone = client_dialog.clone();
    tokio::spawn(async move { dialog_clone.cancel().await });

    // Receive the CANCEL request
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| rsip::Error::Unexpected("Timeout receiving CANCEL".into()))??;

    let cancel_msg = std::str::from_utf8(&buf[..len]).unwrap();
    let cancel_req: Request = rsip::SipMessage::try_from(cancel_msg)?.try_into()?;
    let cancel_vias = cancel_req
        .headers
        .iter()
        .filter_map(|header| {
            if let Header::Via(via) = header {
                Some(via)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(cancel_req.method, rsip::Method::Cancel);

    assert_eq!(
        cancel_req.uri, invite_req.uri,
        "CANCEL Request-URI must match INVITE"
    );

    assert_eq!(
        cancel_req.call_id_header()?.value().to_string(),
        invite_req.call_id_header()?.value().to_string(),
        "CANCEL Call-ID must match INVITE"
    );

    assert_eq!(
        cancel_req.from_header()?.value().to_string(),
        invite_req.from_header()?.value().to_string(),
        "CANCEL From header must match INVITE (including tag)"
    );

    assert_eq!(
        cancel_req.to_header()?.value().to_string(),
        invite_req.to_header()?.value().to_string(),
        "CANCEL To header must match INVITE"
    );

    assert!(
        cancel_req.to_header()?.tag()?.is_none(),
        "CANCEL should not have To tag, because the invite does not have"
    );

    assert_eq!(
        cancel_req.cseq_header()?.seq()?,
        invite_req.cseq_header()?.seq()?,
        "CANCEL CSeq number must match INVITE"
    );

    assert_eq!(
        cancel_vias.len(),
        1,
        "CANCEL must have exactly one Via header"
    );

    assert_eq!(
        cancel_req.via_header()?.value(),
        invite_req.via_header()?.value(),
        "CANCEL Via must match top Via in INVITE"
    );

    Ok(())
}

/// Mock domain resolver that redirects all domain lookups to a local address
struct MockDomainResolver {
    local_addr: SipAddr,
}

#[async_trait]
impl DomainResolver for MockDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> crate::Result<SipAddr> {
        // Redirect domain lookups to our local test address, preserving transport
        Ok(SipAddr {
            r#type: target.r#type,
            addr: self.local_addr.addr.clone(),
        })
    }
}

async fn create_test_endpoint_with_resolver(
    local_addr: SipAddr,
) -> crate::Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let resolver = Box::new(MockDomainResolver { local_addr });
    let tl = TransportLayer::new_with_domain_resolver(token.child_token(), resolver);
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    Ok(endpoint)
}

/// Verifies that when the 200 OK contains a Contact header with a domain name,
/// the ACK is sent to that domain (resolved via the DomainResolver).
///
/// This tests the full invite flow with two separate endpoints:
/// 1. UAC sends INVITE to UAS endpoint
/// 2. UAS responds with 200 OK containing Contact with domain name
/// 3. UAC sends ACK to the domain (which gets resolved to UAS endpoint)
#[tokio::test]
async fn test_ack_sent_to_domain_name_from_contact() -> crate::Result<()> {
    use crate::dialog::{dialog_layer::DialogLayer, invitation::InviteOption};

    // ========== Create UAS endpoint ==========
    let uas_token = CancellationToken::new();
    let uas_transport_layer = TransportLayer::new(uas_token.child_token());

    let uas_udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(uas_token.child_token()),
    )
    .await?;

    let uas_port = uas_udp
        .get_addr()
        .addr
        .port
        .map(|p| u16::from(p))
        .unwrap_or(0);
    uas_transport_layer.add_transport(uas_udp.into());

    let uas_endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-uas")
        .with_transport_layer(uas_transport_layer)
        .build();

    uas_endpoint.inner.transport_layer.serve_listens().await?;
    let uas_endpoint_inner = uas_endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = uas_endpoint_inner.serve().await;
    });

    // ========== Create UAC endpoint with mock resolver ==========
    let domain_target_addr = SipAddr {
        r#type: Some(rsip::Transport::Udp),
        addr: rsip::HostWithPort {
            host: rsip::Host::IpAddr("127.0.0.1".parse().unwrap()),
            port: Some(uas_port.into()),
        },
    };

    let uac_endpoint = create_test_endpoint_with_resolver(domain_target_addr).await?;

    let uac_udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(
            uac_endpoint
                .inner
                .transport_layer
                .inner
                .cancel_token
                .child_token(),
        ),
    )
    .await?;
    let uac_port = uac_udp
        .get_addr()
        .addr
        .port
        .map(|p| u16::from(p))
        .unwrap_or(0);
    uac_endpoint
        .inner
        .transport_layer
        .add_transport(uac_udp.into());

    uac_endpoint.inner.transport_layer.serve_listens().await?;
    let uac_endpoint_inner = uac_endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = uac_endpoint_inner.serve().await;
    });

    // ========== Create dialog layers ==========
    let uac_dialog_layer = DialogLayer::new(uac_endpoint.inner.clone());
    let uas_dialog_layer = DialogLayer::new(uas_endpoint.inner.clone());

    // ========== UAS: Start listening for incoming transactions ==========
    let mut uas_incoming = uas_endpoint.incoming_transactions()?;

    let (uac_state_sender, _) = unbounded_channel();
    let (uas_state_sender, _) = unbounded_channel();

    // Oneshot channel to receive the ACK for verification
    let (ack_sender, ack_receiver) = oneshot::channel::<Request>();

    // UAS handler - wait for INVITE, respond with 200 OK containing domain Contact
    tokio::spawn(async move {
        let mut invite_tx = uas_incoming.recv().await.expect("failed to get the INVITE");
        assert!(matches!(invite_tx.original.method, rsip::Method::Invite));

        let contact_uri = Uri::try_from(format!(
            "sip:bob@uas.example.com:{};transport=udp",
            uas_port
        ))
        .unwrap();

        let dialog = uas_dialog_layer
            .get_or_create_server_invite(&invite_tx, uas_state_sender, None, Some(contact_uri))
            .expect("failed to create dialog");

        dialog.accept(None, None).expect("accept failed");

        if let Some(msg) = invite_tx.receive().await {
            if let rsip::SipMessage::Request(ack) = msg {
                if ack.method == rsip::Method::Ack {
                    let _ = ack_sender.send(ack);
                }
            }
        }
    });

    // ========== UAC: Create and process INVITE ==========
    let invite_option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{};transport=udp", uas_port).as_str())?,
        contact: Uri::try_from(format!("sip:alice@127.0.0.1:{}", uac_port).as_str())?,
        ..Default::default()
    };

    let (client_dialog, _) = uac_dialog_layer
        .do_invite(invite_option, uac_state_sender)
        .await?;

    // ========== Verify ACK was received by UAS with domain in Request-URI ==========
    let ack_req = tokio::time::timeout(std::time::Duration::from_secs(2), ack_receiver)
        .await
        .expect("timeout receiving ACK")
        .expect("fail to receiving ACK");

    // Verify ACK Request-URI contains the domain from Contact header
    assert_eq!(ack_req.method, rsip::Method::Ack, "Expected ACK request");

    assert_eq!(
        ack_req.uri.host_with_port.host,
        rsip::Host::Domain("uas.example.com".into()),
        "ACK Request-URI host should be the domain from Contact header"
    );

    assert_eq!(
        ack_req.uri.host_with_port.port,
        Some(uas_port.into()),
        "ACK Request-URI port should match Contact port"
    );

    // Verify dialog was confirmed
    assert!(
        client_dialog.inner.is_confirmed(),
        "Dialog should be confirmed after 200 OK"
    );

    uas_token.cancel();

    Ok(())
}

/// Mock target locator that maps Contact URIs to WebSocket address
struct WebSocketChannelLocator {
    /// Map from Contact URI host to the channel's SipAddr
    contact: String,
    ws_addr: SipAddr,
}

#[async_trait]
impl TargetLocator for WebSocketChannelLocator {
    async fn locate(&self, uri: &rsip::Uri) -> crate::Result<SipAddr> {
        if let rsip::Host::Domain(domain) = &uri.host_with_port.host {
            if domain.to_string().contains(&self.contact) {
                return Ok(self.ws_addr.clone());
            }
        }
        SipAddr::try_from(uri)
    }
}

/// Verifies ACK to sip over websocket, it will use channel and have a contact like "bmf9p1ekfdar.invalid"
///
/// This simulates the scenario where:
/// 1. A WebSocket client registers with Contact: <sip:kr9e8brl@nbs1t4oqh57u.invalid;transport=ws>
/// 2. The proxy forwards messages through a ChannelConnection
/// 3. When the UAC receives a 200 OK with this Contact, the ACK should be sent to the channel
#[tokio::test]
async fn test_ack_sent_to_websocket_channel_via_locator() -> crate::Result<()> {
    use crate::dialog::{dialog_layer::DialogLayer, invitation::InviteOption};
    use crate::transport::channel::ChannelConnection;
    use crate::transport::connection::TransportEvent;

    // ========== Setup channel connection to simulate WebSocket ==========
    let (to_channel_tx, to_channel_rx) = unbounded_channel();
    let (from_channel_tx, mut from_channel_rx) = unbounded_channel();

    let contact_host = "nbs1t4oqh57u.invalid";
    let contact_user = "kr9e8brl";
    // address used by sipjs
    let ws_contact_uri = format!("sip:{}@{};transport=ws", contact_user, contact_host);

    // websocket address register into locator
    let ws_addr = SipAddr {
        r#type: Some(rsip::Transport::Ws),
        addr: rsip::HostWithPort {
            host: rsip::Host::IpAddr("127.0.0.1".parse().unwrap()),
            port: Some(8080.into()),
        },
    };

    let chan_conn =
        ChannelConnection::create_connection(to_channel_rx, from_channel_tx, ws_addr.clone(), None)
            .await?;

    let sip_conn = SipConnection::Channel(chan_conn.clone());

    let uac_token = CancellationToken::new();
    let locator = Box::new(WebSocketChannelLocator {
        contact: contact_host.to_string(),
        ws_addr: ws_addr.clone(),
    });

    let uac_transport_layer = TransportLayer::new(uac_token.child_token());

    // Add UDP transport (provides addresses for Via/Contact headers, like in proxy)
    let uac_udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(uac_token.child_token()),
    )
    .await?;
    let uac_port = uac_udp
        .get_addr()
        .addr
        .port
        .map(|p| u16::from(p))
        .unwrap_or(0);
    uac_transport_layer.add_transport(uac_udp.into());

    // Add WebSocket channel connection (like proxy's handle_websocket does)
    uac_transport_layer.add_connection(sip_conn.clone());

    let uac_endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-uac")
        .with_transport_layer(uac_transport_layer)
        .with_target_locator(locator)
        .build();

    uac_endpoint.inner.transport_layer.serve_listens().await?;
    let uac_endpoint_inner = uac_endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = uac_endpoint_inner.serve().await;
    });

    // Create channels for dialog state
    let (uac_state_sender, _uac_state_receiver) = unbounded_channel();

    // ========== Start UAC INVITE in background ==========
    // INVITE is sent to the WebSocket contact domain which will be routed via the channel
    let invite_option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{};transport=ws", contact_host).as_str())?,
        contact: Uri::try_from(format!("sip:alice@127.0.0.1:{}", uac_port).as_str())?,
        ..Default::default()
    };

    let uac_endpoint_inner = uac_endpoint.inner.clone();
    let dialog_handle = tokio::spawn(async move {
        let uac_dialog_layer = DialogLayer::new(uac_endpoint_inner);
        uac_dialog_layer
            .do_invite(invite_option, uac_state_sender)
            .await
    });

    // ========== UAS: Receive INVITE from channel and respond with 200 OK ==========
    let invite_req =
        tokio::time::timeout(std::time::Duration::from_secs(1), from_channel_rx.recv())
            .await
            .unwrap()
            .unwrap();

    let TransportEvent::Incoming(rsip::SipMessage::Request(invite_req), _, _) = invite_req else {
        panic!("Expected INVITE request");
    };

    assert_eq!(invite_req.method, rsip::Method::Invite);

    // Build 200 OK with WebSocket Contact
    let ws_contact = rsip::headers::Contact::new(&format!("<{}>", ws_contact_uri));
    let to_with_tag: rsip::Header = invite_req
        .to_header()?
        .clone()
        .with_tag("uas-tag-123".into())?
        .into();

    let ok_response = Response {
        status_code: StatusCode::OK,
        version: rsip::Version::V2,
        headers: vec![
            invite_req.via_header()?.clone().into(),
            invite_req.from_header()?.clone().into(),
            to_with_tag,
            invite_req.call_id_header()?.clone().into(),
            invite_req.cseq_header()?.clone().into(),
            ws_contact.into(),
            rsip::headers::ContentLength::from(0u32).into(),
        ]
        .into(),
        body: vec![],
    };

    // Send 200 OK back through the channel (simulating response from WebSocket peer)
    to_channel_tx
        .send(TransportEvent::Incoming(
            rsip::SipMessage::Response(ok_response),
            sip_conn.clone(),
            ws_addr.clone(),
        ))
        .unwrap();

    let ack_event = tokio::time::timeout(std::time::Duration::from_secs(1), from_channel_rx.recv())
        .await
        .unwrap()
        .unwrap();

    let TransportEvent::Incoming(rsip::SipMessage::Request(ack_req), _, _) = ack_event else {
        panic!("Expected ACK request");
    };

    // Cleanup
    uac_token.cancel();
    dialog_handle.abort();

    assert_eq!(ack_req.method, rsip::Method::Ack, "Expected ACK request");

    // The Request-URI should match the Contact from the 200 OK
    assert!(
        ack_req
            .uri
            .host_with_port
            .host
            .to_string()
            .contains(contact_host),
        "ACK Request-URI host should contain the WebSocket contact domain, got: {}",
        ack_req.uri.host_with_port.host
    );

    // Verify transport parameter is ws
    let has_ws_transport = ack_req
        .uri
        .params
        .iter()
        .any(|p| matches!(p, rsip::Param::Transport(t) if *t == rsip::Transport::Ws));
    assert!(
        has_ws_transport,
        "ACK Request-URI should have transport=ws parameter"
    );

    Ok(())
}
