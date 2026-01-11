use rsip::Method;
use crate::dialog::dialog_layer::DialogLayer;
use super::test_dialog_states::{create_invite_request, create_test_endpoint};
use crate::transaction::transaction::Transaction;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::dialog::DialogId;
use std::sync::Arc;

#[tokio::test]
async fn test_server_subscription_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let mut subscribe_req = create_invite_request("alice-tag", "", "sub-call-id");
    subscribe_req.method = Method::Subscribe;

    let key = TransactionKey::from_request(&subscribe_req, TransactionRole::Server)?;
    let transaction = Transaction::new_server(key, subscribe_req, endpoint.inner.clone(), None);

    let (state_sender, _state_receiver) = dialog_layer.new_dialog_state_channel();
    
    let server_sub = dialog_layer.get_or_create_server_subscription(
        &transaction,
        state_sender,
        None,
        None
    )?;

    assert_eq!(server_sub.id().call_id, "sub-call-id");
    assert_eq!(server_sub.id().from_tag, "alice-tag");
    assert!(!server_sub.id().to_tag.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_server_publication_creation() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let dialog_layer = DialogLayer::new(endpoint.inner.clone());

    let mut publish_req = create_invite_request("alice-tag", "", "pub-call-id");
    publish_req.method = Method::Publish;

    let key = TransactionKey::from_request(&publish_req, TransactionRole::Server)?;
    let transaction = Transaction::new_server(key, publish_req, endpoint.inner.clone(), None);

    let (state_sender, _state_receiver) = dialog_layer.new_dialog_state_channel();
    
    let server_pub = dialog_layer.get_or_create_server_publication(
        &transaction,
        state_sender,
        None,
        None
    )?;

    assert_eq!(server_pub.id().call_id, "pub-call-id");
    assert_eq!(server_pub.id().from_tag, "alice-tag");
    assert!(!server_pub.id().to_tag.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_client_publication_etag_handling() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (tu_sender, _tu_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (state_sender, _state_receiver) = tokio::sync::mpsc::unbounded_channel();

    let dialog_id = DialogId {
        call_id: "pub-call-id".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: "bob-tag".to_string(),
    };

    let mut publish_req = create_invite_request("alice-tag", "bob-tag", "pub-call-id");
    publish_req.method = Method::Publish;

    let dialog_inner = crate::dialog::dialog::DialogInner::new(
        TransactionRole::Client,
        dialog_id.clone(),
        publish_req,
        endpoint.inner.clone(),
        state_sender,
        None,
        None,
        tu_sender,
    )?;

    let client_pub = crate::dialog::publication::ClientPublicationDialog::new(Arc::new(dialog_inner));
    
    assert!(client_pub.etag().is_none());
    
    // Simulate receiving a 200 OK with SIP-ETag manually
    *client_pub.etag.lock().unwrap() = Some("test-etag".to_string());
    assert_eq!(client_pub.etag(), Some("test-etag".to_string()));

    Ok(())
}
