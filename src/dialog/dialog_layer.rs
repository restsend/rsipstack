use super::authenticate::Credential;
use super::dialog::{DialogSnapshot, DialogStateSender};
use super::publication::{ClientPublicationDialog, ServerPublicationDialog};
use super::subscription::{ClientSubscriptionDialog, ServerSubscriptionDialog};
use super::{dialog::Dialog, server_dialog::ServerInviteDialog, DialogId};
use crate::dialog::client_dialog::ClientInviteDialog;
use crate::dialog::dialog::{DialogInner, DialogStateReceiver};
use crate::transaction::key::TransactionRole;
use crate::transaction::make_tag;
use crate::transaction::transaction::transaction_event_sender_noop;
use crate::transaction::{endpoint::EndpointInnerRef, transaction::Transaction};
use crate::Result;
use rsip::prelude::HeadersExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::debug;

/// Internal Dialog Layer State
///
/// `DialogLayerInner` contains the core state for managing multiple SIP dialogs.
/// It maintains a registry of active dialogs and tracks sequence numbers for
/// dialog creation.
///
/// # Fields
///
/// * `last_seq` - Atomic counter for generating unique sequence numbers
/// * `dialogs` - Thread-safe map of active dialogs indexed by DialogId
///
/// # Thread Safety
///
/// This structure is designed to be shared across multiple threads safely:
/// * `last_seq` uses atomic operations for lock-free increments
/// * `dialogs` uses RwLock for concurrent read access with exclusive writes
pub struct DialogLayerInner {
    pub(super) last_seq: AtomicU32,
    pub(super) dialogs: RwLock<HashMap<String, Dialog>>,
}
pub type DialogLayerInnerRef = Arc<DialogLayerInner>;

/// SIP Dialog Layer
///
/// `DialogLayer` provides high-level dialog management functionality for SIP
/// applications. It handles dialog creation, lookup, and lifecycle management
/// while coordinating with the transaction layer.
///
/// # Key Responsibilities
///
/// * Creating and managing SIP dialogs
/// * Dialog identification and routing
/// * Dialog state tracking and cleanup
/// * Integration with transaction layer
/// * Sequence number management
///
/// # Usage Patterns
///
/// ## Server-side Dialog Creation
///
/// ```rust,no_run
/// use rsipstack::dialog::dialog_layer::DialogLayer;
/// use rsipstack::transaction::endpoint::EndpointInner;
/// use std::sync::Arc;
///
/// # fn example() -> rsipstack::Result<()> {
/// # let endpoint: Arc<EndpointInner> = todo!();
/// # let transaction = todo!();
/// # let state_sender = todo!();
/// # let credential = None;
/// # let contact_uri = None;
/// // Create dialog layer
/// let dialog_layer = DialogLayer::new(endpoint.clone());
///
/// // Handle incoming INVITE transaction
/// let server_dialog = dialog_layer.get_or_create_server_invite(
///     &transaction,
///     state_sender,
///     credential,
///     contact_uri
/// )?;
///
/// // Accept the call
/// server_dialog.accept(None, None)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Dialog Lookup and Routing
///
/// ```rust,no_run
/// # use rsipstack::dialog::dialog_layer::DialogLayer;
/// # async fn example() -> rsipstack::Result<()> {
/// # let dialog_layer: DialogLayer = todo!();
/// # let request = todo!();
/// # let mut transaction = todo!();
/// // Find existing dialog for incoming request
/// if let Some(mut dialog) = dialog_layer.match_dialog(&transaction) {
///     // Route to existing dialog
///     dialog.handle(&mut transaction).await?;
/// } else {
///     // Create new dialog or reject
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Dialog Cleanup
///
/// ```rust,no_run
/// # use rsipstack::dialog::dialog_layer::DialogLayer;
/// # fn example() {
/// # let dialog_layer: DialogLayer = todo!();
/// # let dialog_id = todo!();
/// // Remove completed dialog
/// dialog_layer.remove_dialog(&dialog_id);
/// # }
/// ```
///
/// # Dialog Lifecycle
///
/// 1. **Creation** - Dialog created from incoming INVITE or outgoing request
/// 2. **Early State** - Dialog exists but not yet confirmed
/// 3. **Confirmed** - Dialog established with 2xx response and ACK
/// 4. **Active** - Dialog can exchange in-dialog requests
/// 5. **Terminated** - Dialog ended with BYE or error
/// 6. **Cleanup** - Dialog removed from layer
///
/// # Thread Safety
///
/// DialogLayer is thread-safe and can be shared across multiple tasks:
/// * Dialog lookup operations are concurrent
/// * Dialog creation is serialized when needed
/// * Automatic cleanup prevents memory leaks
pub struct DialogLayer {
    pub endpoint: EndpointInnerRef,
    pub inner: DialogLayerInnerRef,
}

impl DialogLayer {
    pub fn new(endpoint: EndpointInnerRef) -> Self {
        Self {
            endpoint,
            inner: Arc::new(DialogLayerInner {
                last_seq: AtomicU32::new(0),
                dialogs: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub fn get_or_create_server_invite(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
    ) -> Result<ServerInviteDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self
                .inner
                .dialogs
                .read()
                .unwrap()
                .get(&id.to_string())
                .cloned();
            match dlg {
                Some(Dialog::ServerInvite(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        rsip::StatusCode::CallTransactionDoesNotExist,
                    ));
                }
            }
        }
        id.local_tag = make_tag().to_string(); // generate to tag

        let mut local_contact = local_contact;
        if local_contact.is_none() {
            local_contact = self
                .build_local_contact(credential.as_ref().map(|cred| cred.username.clone()), None)
                .ok();
        }

        let dlg_inner = DialogInner::new(
            TransactionRole::Server,
            id.clone(),
            tx.original.clone(),
            self.endpoint.clone(),
            state_sender,
            credential,
            local_contact,
            tx.tu_sender.clone(),
        )?;

        *dlg_inner.remote_contact.lock().unwrap() = tx.original.contact_header().ok().cloned();

        let dialog = ServerInviteDialog {
            inner: Arc::new(dlg_inner),
        };
        self.inner
            .dialogs
            .write()
            .unwrap()
            .insert(id.to_string(), Dialog::ServerInvite(dialog.clone()));
        debug!(%id, "server invite dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_server_subscription(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
    ) -> Result<ServerSubscriptionDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self
                .inner
                .dialogs
                .read()
                .unwrap()
                .get(&id.to_string())
                .cloned();
            match dlg {
                Some(Dialog::ServerSubscription(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        rsip::StatusCode::CallTransactionDoesNotExist,
                    ));
                }
            }
        }
        id.local_tag = make_tag().to_string(); // generate to tag

        let mut local_contact = local_contact;
        if local_contact.is_none() {
            local_contact = self
                .build_local_contact(credential.as_ref().map(|cred| cred.username.clone()), None)
                .ok();
        }

        let dlg_inner = DialogInner::new(
            TransactionRole::Server,
            id.clone(),
            tx.original.clone(),
            self.endpoint.clone(),
            state_sender,
            credential,
            local_contact,
            tx.tu_sender.clone(),
        )?;

        *dlg_inner.remote_contact.lock().unwrap() = tx.original.contact_header().ok().cloned();

        let dialog = ServerSubscriptionDialog {
            inner: Arc::new(dlg_inner),
        };
        self.inner
            .dialogs
            .write()
            .unwrap()
            .insert(id.to_string(), Dialog::ServerSubscription(dialog.clone()));
        debug!(%id, "server subscription dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_server_publication(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
    ) -> Result<ServerPublicationDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self
                .inner
                .dialogs
                .read()
                .unwrap()
                .get(&id.to_string())
                .cloned();
            match dlg {
                Some(Dialog::ServerPublication(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        rsip::StatusCode::CallTransactionDoesNotExist,
                    ));
                }
            }
        }
        id.local_tag = make_tag().to_string(); // generate to tag

        let mut local_contact = local_contact;
        if local_contact.is_none() {
            local_contact = self
                .build_local_contact(credential.as_ref().map(|cred| cred.username.clone()), None)
                .ok();
        }

        let dlg_inner = DialogInner::new(
            TransactionRole::Server,
            id.clone(),
            tx.original.clone(),
            self.endpoint.clone(),
            state_sender,
            credential,
            local_contact,
            tx.tu_sender.clone(),
        )?;

        *dlg_inner.remote_contact.lock().unwrap() = tx.original.contact_header().ok().cloned();

        let dialog = ServerPublicationDialog::new(Arc::new(dlg_inner));
        self.inner
            .dialogs
            .write()
            .unwrap()
            .insert(id.to_string(), Dialog::ServerPublication(dialog.clone()));
        debug!(%id, "server publication dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_client_publication(
        &self,
        call_id: String,
        from_tag: String,
        to_tag: String,
        initial_request: rsip::Request,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
    ) -> Result<ClientPublicationDialog> {
        let id = DialogId {
            call_id,
            local_tag: from_tag,
            remote_tag: to_tag,
        };

        if let Some(Dialog::ClientPublication(dlg)) = self.get_dialog(&id) {
            return Ok(dlg);
        }

        let mut local_contact = local_contact;
        if local_contact.is_none() {
            local_contact = self
                .build_local_contact(credential.as_ref().map(|cred| cred.username.clone()), None)
                .ok();
        }

        let dlg_inner = DialogInner::new(
            TransactionRole::Client,
            id.clone(),
            initial_request,
            self.endpoint.clone(),
            state_sender,
            credential,
            local_contact,
            {
                let (tx, _) = tokio::sync::mpsc::unbounded_channel();
                tx
            },
        )?;

        let dialog = ClientPublicationDialog::new(Arc::new(dlg_inner));
        self.inner
            .dialogs
            .write()
            .unwrap()
            .insert(id.to_string(), Dialog::ClientPublication(dialog.clone()));
        Ok(dialog)
    }

    pub fn get_or_create_client_subscription(
        &self,
        call_id: String,
        from_tag: String,
        to_tag: String,
        initial_request: rsip::Request,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<rsip::Uri>,
    ) -> Result<ClientSubscriptionDialog> {
        let id = DialogId {
            call_id,
            local_tag: from_tag,
            remote_tag: to_tag,
        };

        if let Some(Dialog::ClientSubscription(dlg)) = self.get_dialog(&id) {
            return Ok(dlg);
        }

        let mut local_contact = local_contact;
        if local_contact.is_none() {
            local_contact = self
                .build_local_contact(credential.as_ref().map(|cred| cred.username.clone()), None)
                .ok();
        }

        let dlg_inner = DialogInner::new(
            TransactionRole::Client,
            id.clone(),
            initial_request,
            self.endpoint.clone(),
            state_sender,
            credential,
            local_contact,
            {
                let (tx, _) = tokio::sync::mpsc::unbounded_channel();
                tx
            },
        )?;

        let dialog = ClientSubscriptionDialog {
            inner: Arc::new(dlg_inner),
        };
        self.inner
            .dialogs
            .write()
            .unwrap()
            .insert(id.to_string(), Dialog::ClientSubscription(dialog.clone()));
        Ok(dialog)
    }

    pub fn increment_last_seq(&self) -> u32 {
        self.inner.last_seq.fetch_add(1, Ordering::Relaxed);
        self.inner.last_seq.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.inner.dialogs.read().unwrap().len()
    }

    pub fn all_dialog_ids(&self) -> Vec<String> {
        self.inner
            .dialogs
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn get_dialog(&self, id: &DialogId) -> Option<Dialog> {
        self.get_dialog_with(&id.to_string())
    }

    pub fn get_dialog_with(&self, id: &String) -> Option<Dialog> {
        match self.inner.dialogs.read() {
            Ok(dialogs) => match dialogs.get(id) {
                Some(dialog) => Some(dialog.clone()),
                None => None,
            },
            Err(_) => None,
        }
    }
    /// Returns all client-side INVITE dialogs (UAC) that share the given Call-ID.
    ///
    /// In a forking scenario, multiple client dialogs can exist for the same
    /// Call-ID (same local From-tag, different remote To-tags). This helper
    /// scans the internal dialog registry and returns all `ClientInviteDialog`
    /// instances whose `DialogId.call_id` equals the provided `call_id`.
    ///
    /// The returned vector may be empty if no matching client dialogs are found.
    pub fn get_client_dialog_by_call_id(&self, call_id: &str) -> Vec<ClientInviteDialog> {
        let dialogs = match self.inner.dialogs.read() {
            Ok(guard) => guard,
            Err(_) => {
                // If the lock is poisoned, we conservatively return an empty list.
                return Vec::new();
            }
        };

        dialogs
            .values()
            .filter_map(|dlg| match dlg {
                Dialog::ClientInvite(client_dlg) if client_dlg.id().call_id == call_id => {
                    Some(client_dlg.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Restore a dialog from persisted snapshot.
    ///
    /// Restores only CONFIRMED snapshots.
    /// Non-confirmed snapshots are ignored (warn inside try_restore_from_snapshot).
    ///
    /// Returns:
    /// - Ok(true)  => restored and inserted
    /// - Ok(false) => skipped (already exists or not confirmed)
    pub fn restore_from_snapshot(
        &self,
        snapshot: DialogSnapshot,
        state_sender: DialogStateSender,
    ) -> crate::Result<bool> {
        // Already restored?
        if self.get_dialog(&snapshot.id).is_some() {
            return Ok(false);
        }

        let tu_sender = transaction_event_sender_noop();

        let Some(inner) = DialogInner::try_restore_from_snapshot(
            snapshot,
            self.endpoint.clone(),
            state_sender,
            tu_sender,
        )?
        else {
            // not confirmed -> ignored
            return Ok(false);
        };

        let inner = Arc::new(inner);
        let dialog = Dialog::from_inner(inner.role.clone(), inner.clone());

        let key = dialog.id().to_string();

        self.inner.dialogs.write().unwrap().insert(key, dialog);

        Ok(true)
    }

    pub fn remove_dialog(&self, id: &DialogId) {
        debug!(%id, "remove dialog");
        self.inner
            .dialogs
            .write()
            .unwrap()
            .remove(&id.to_string())
            .map(|d| d.on_remove());
    }

    pub fn match_dialog(&self, tx: &Transaction) -> Option<Dialog> {
        let id = DialogId::try_from(tx).ok()?;
        self.get_dialog(&id)
    }

    pub fn new_dialog_state_channel(&self) -> (DialogStateSender, DialogStateReceiver) {
        tokio::sync::mpsc::unbounded_channel()
    }

    pub fn build_local_contact(
        &self,
        username: Option<String>,
        params: Option<Vec<rsip::Param>>,
    ) -> Result<rsip::Uri> {
        let addr = self
            .endpoint
            .transport_layer
            .get_addrs()
            .first()
            .ok_or(crate::Error::EndpointError("not sipaddrs".to_string()))?
            .clone();

        let scheme = if matches!(addr.r#type, Some(rsip::Transport::Tls)) {
            rsip::Scheme::Sips
        } else {
            rsip::Scheme::Sip
        };

        let mut params = params.unwrap_or_default();
        if !matches!(addr.r#type, Some(rsip::Transport::Udp) | None) {
            addr.r#type.map(|t| params.push(rsip::Param::Transport(t)));
        }
        let auth = username.map(|user| rsip::Auth {
            user,
            password: None,
        });
        Ok(rsip::Uri {
            scheme: Some(scheme),
            auth,
            host_with_port: addr.addr.clone().into(),
            params,
            ..Default::default()
        })
    }
}
