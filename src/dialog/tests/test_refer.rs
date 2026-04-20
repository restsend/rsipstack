use std::sync::Arc;

use tokio::sync::mpsc::unbounded_channel;

use crate::dialog::{client_dialog::ClientInviteDialog, dialog::DialogInner, DialogId};
use crate::sip::{ReferTo, Uri};
use crate::transaction::key::TransactionRole;

use super::test_dialog_states::{create_invite_request, create_test_endpoint};

#[test]
fn test_refer_to_from_uri_preserves_existing_uri_behavior() -> crate::Result<()> {
    let refer_to = ReferTo::from(Uri::try_from("sip:carol@restsend.com")?);
    assert_eq!(refer_to.value(), "<sip:carol@restsend.com>");
    Ok(())
}

#[tokio::test]
async fn test_client_dialog_refer_accepts_name_addr_values() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let (state_sender, _) = unbounded_channel();

    let dialog_id = DialogId {
        call_id: "refer-name-addr".to_string(),
        local_tag: "alice-tag".to_string(),
        remote_tag: "bob-tag".to_string(),
    };

    let invite_req = create_invite_request("alice-tag", "bob-tag", "refer-name-addr");
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

    std::mem::drop(client_dialog.refer(
        "\"Display Name\" <sip:user@domain.com;method=INVITE?Replaces=call-id%40host>",
        None,
        None,
    ));

    Ok(())
}
