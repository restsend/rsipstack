use rsip::prelude::{HeadersExt, ToTypedHeader};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;

use crate::{
    dialog::{
        dialog::DialogInner,
        server_dialog::ServerInviteDialog,
        tests::test_dialog_states::{create_invite_request, create_test_endpoint},
        DialogId,
    },
    transaction::{key::TransactionRole, transaction::TransactionEvent},
    transport::SipAddr,
};

#[tokio::test]
async fn test_dialog_make_request() -> crate::Result<()> {
    // Create dialog ID
    let dialog_id = DialogId {
        call_id: "test-call-id-123".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    let endpoint = create_test_endpoint().await?;
    let (tu_sender, _tu_receiver) = unbounded_channel();
    let (state_sender, _state_receiver) = unbounded_channel();
    // Create INVITE request
    let invite_req = create_invite_request("alice-tag-456", "", "test-call-id-123");
    // Create dialog inner
    let dialog_inner = DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        invite_req.clone(),
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(rsip::Uri::try_from("sip:alice@alice.example.com:5060")?),
        tu_sender,
    )
    .expect("Failed to create dialog inner");

    let bye = dialog_inner
        .make_request_with_vias(
            rsip::Method::Bye,
            None,
            dialog_inner
                .build_vias_from_request()
                .expect("Failed to build vias"),
            None,
            None,
        )
        .expect("Failed to make request");
    assert_eq!(bye.method, rsip::Method::Bye);

    assert_eq!(
        bye.via_header()
            .expect("not via header")
            .typed()?
            .received()?,
        "172.0.0.1".parse().ok()
    );
    assert!(
        bye.via_header().expect("not via header").typed()?.branch()
            != invite_req
                .via_header()
                .expect("not via header")
                .typed()?
                .branch()
    );
    Ok(())
}

#[tokio::test]
async fn test_accept_with_public_contact_preserves_contact_header() -> crate::Result<()> {
    // Create dialog ID
    let dialog_id = DialogId {
        call_id: "test-call-id-contact".to_string(),
        local_tag: "alice-tag-456".to_string(),
        remote_tag: "bob-tag-789".to_string(),
    };

    let endpoint = create_test_endpoint().await?;
    let (tu_sender, mut tu_receiver) = unbounded_channel();
    let (state_sender, _state_receiver) = unbounded_channel();

    // Create INVITE request
    let invite_req = create_invite_request("alice-tag-456", "", "test-call-id-contact");

    // Create server dialog inner
    let dialog_inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        None,
        tu_sender,
    )
    .expect("Failed to create dialog inner");

    let server_dialog = ServerInviteDialog {
        inner: Arc::new(dialog_inner),
    };

    // Define the public address we want to use
    let public_address = Some(rsip::HostWithPort {
        host: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)).into(),
        port: Some(5060.into()),
    });

    // Define local address as fallback
    let local_address: SipAddr = rsip::HostWithPort::try_from("127.0.0.1:5060")?.into();

    // Accept with public contact
    server_dialog.accept_with_public_contact(
        "bob",
        public_address.clone(),
        &local_address,
        None,
        None,
    )?;

    // Receive the response from the transaction event channel
    let event = tu_receiver
        .recv()
        .await
        .expect("Should receive transaction event");

    match event {
        TransactionEvent::Respond(response) => {
            // Verify status code is 200 OK
            assert_eq!(response.status_code, rsip::StatusCode::OK);

            // Extract and verify Contact header
            let contact_header = response
                .contact_header()
                .expect("Response should have Contact header")
                .typed()
                .expect("Contact header should be parseable");

            // Verify the Contact URI matches the public address we provided
            assert_eq!(
                contact_header.uri.host_with_port.host,
                public_address.as_ref().unwrap().host
            );
            assert_eq!(
                contact_header.uri.host_with_port.port,
                public_address.as_ref().unwrap().port
            );

            // Verify the username in the Contact URI
            assert_eq!(contact_header.uri.auth.as_ref().unwrap().user, "bob");
        }
        _other => panic!("Expected TransactionEvent::Respond, got different event type"),
    }

    Ok(())
}
