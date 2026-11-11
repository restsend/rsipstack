use super::authenticate::Credential;
use super::dialog::{DialogSnapshot, DialogStateSender};
use super::publication::{ClientPublicationDialog, ServerPublicationDialog};
use super::subscription::{ClientSubscriptionDialog, ServerSubscriptionDialog};
use super::{dialog::Dialog, invite_dialog::InviteDialog, DialogId};
use crate::prelude::*;

use crate::dialog::dialog::{DialogInner, DialogStateReceiver};
use crate::platform::sync::RwMap;
use crate::sip::prelude::HeadersExt;
use crate::transaction::key::TransactionRole;
use crate::transaction::make_tag;
use crate::transaction::transaction::transaction_event_sender_noop;
use crate::transaction::{endpoint::EndpointInnerRef, transaction::Transaction};
use crate::Result;
use alloc::collections::btree_map::Entry;
use core::sync::atomic::{AtomicU32, Ordering};
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
    pub(super) lifecycle_sender:
        crate::platform::sync::Mutex<Option<super::lifecycle::DialogLifecycleSender>>,
    pub(super) last_seq: AtomicU32,
    pub(super) dialogs: RwMap<DialogId, Dialog>,
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
/// * Applications remove completed dialogs with [`Self::remove_dialog`]
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
                lifecycle_sender: crate::platform::sync::Mutex::new(None),
                dialogs: RwMap::new(),
            }),
        }
    }

    /// Subscribe to facts for subsequently created INVITE dialogs. Existing
    /// dialogs retain their subscription. None disables new subscriptions.
    /// A slow or closed receiver never delays SIP processing.
    pub fn set_lifecycle_events(&self, sender: Option<super::lifecycle::DialogLifecycleSender>) {
        if sender.is_some() {
            self.endpoint
                .record_receipt_times
                .store(true, Ordering::Relaxed);
        }
        *self.inner.lifecycle_sender.lock() = sender;
    }

    pub fn get_or_create_server_invite(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
    ) -> Result<InviteDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self.inner.dialogs.get(&id);
            match dlg {
                Some(Dialog::Invite(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        crate::sip::StatusCode::CallTransactionDoesNotExist,
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

        *dlg_inner.remote_contact.lock() = tx.original.contact_header().ok().cloned();

        if let Some(conn) = &tx.connection {
            let transport = conn.transport();
            if !matches!(transport, crate::sip::Transport::Udp) {
                let mut remote_uri = dlg_inner.remote_uri.lock();
                if !remote_uri
                    .params
                    .iter()
                    .any(|p| matches!(p, crate::sip::Param::Transport(_)))
                {
                    remote_uri
                        .params
                        .push(crate::sip::Param::Transport(transport));
                }
            }
        }

        let dialog = InviteDialog::from_inner(Arc::new(dlg_inner));
        dialog.inner.lifecycle.lock().sender = self.inner.lifecycle_sender.lock().clone();
        *tx.initial_dialog.lock() = Some(Arc::downgrade(&dialog.inner));
        dialog.inner.reserve_invite(tx)?;
        dialog.inner.set_server_connection(tx.connection.clone());
        self.inner
            .dialogs
            .insert(id.clone(), Dialog::Invite(dialog.clone()));
        debug!(%id, "server invite dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_server_subscription(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
    ) -> Result<ServerSubscriptionDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self.inner.dialogs.get(&id);
            match dlg {
                Some(Dialog::ServerSubscription(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        crate::sip::StatusCode::CallTransactionDoesNotExist,
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

        *dlg_inner.remote_contact.lock() = tx.original.contact_header().ok().cloned();
        dlg_inner.set_server_connection(tx.connection.clone());

        let dialog = ServerSubscriptionDialog {
            inner: Arc::new(dlg_inner),
        };
        self.inner
            .dialogs
            .insert(id.clone(), Dialog::ServerSubscription(dialog.clone()));
        debug!(%id, "server subscription dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_server_publication(
        &self,
        tx: &Transaction,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
    ) -> Result<ServerPublicationDialog> {
        let mut id = DialogId::try_from(tx)?;
        if !id.local_tag.is_empty() {
            let dlg = self.inner.dialogs.get(&id);
            match dlg {
                Some(Dialog::ServerPublication(dlg)) => return Ok(dlg),
                _ => {
                    return Err(crate::Error::DialogError(
                        "the dialog not found".to_string(),
                        id,
                        crate::sip::StatusCode::CallTransactionDoesNotExist,
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

        *dlg_inner.remote_contact.lock() = tx.original.contact_header().ok().cloned();
        dlg_inner.set_server_connection(tx.connection.clone());

        let dialog = ServerPublicationDialog::new(Arc::new(dlg_inner));
        self.inner
            .dialogs
            .insert(id.clone(), Dialog::ServerPublication(dialog.clone()));
        debug!(%id, "server publication dialog created");
        Ok(dialog)
    }

    pub fn get_or_create_client_publication(
        &self,
        call_id: String,
        from_tag: String,
        to_tag: String,
        initial_request: crate::sip::Request,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
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
                let (tx, _) = crate::platform::mpsc::unbounded_channel();
                tx
            },
        )?;

        let dialog = ClientPublicationDialog::new(Arc::new(dlg_inner));
        self.inner
            .dialogs
            .insert(id.clone(), Dialog::ClientPublication(dialog.clone()));
        Ok(dialog)
    }

    pub fn get_or_create_client_subscription(
        &self,
        call_id: String,
        from_tag: String,
        to_tag: String,
        initial_request: crate::sip::Request,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
        local_contact: Option<crate::sip::Uri>,
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
                let (tx, _) = crate::platform::mpsc::unbounded_channel();
                tx
            },
        )?;

        let dialog = ClientSubscriptionDialog {
            inner: Arc::new(dlg_inner),
        };
        self.inner
            .dialogs
            .insert(id.clone(), Dialog::ClientSubscription(dialog.clone()));
        Ok(dialog)
    }

    pub fn increment_last_seq(&self) -> u32 {
        self.inner
            .last_seq
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    pub fn len(&self) -> usize {
        self.inner.dialogs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.dialogs.is_empty()
    }

    /// Enumerate structured identities suitable for lookup and removal.
    pub fn dialog_ids(&self) -> Vec<DialogId> {
        self.inner.dialogs.with(|m| m.keys().cloned().collect())
    }

    /// Legacy display strings. Distinct identities can have the same string.
    /// Prefer [`Self::dialog_ids`] when iterating or persisting identities.
    pub fn all_dialog_ids(&self) -> Vec<String> {
        self.inner
            .dialogs
            .with(|m| m.keys().map(ToString::to_string).collect())
    }

    pub fn get_dialog(&self, id: &DialogId) -> Option<Dialog> {
        self.inner.dialogs.with(|dialogs| {
            if let Some(dialog) = dialogs.get(id) {
                return Some(dialog.clone());
            }
            // A pending UAC INVITE remains owned under its original tag-less
            // key until its final response. Provisional responses have already
            // taught the dialog its remote tag. Match that complete identity,
            // never just the Call-ID/local tag, for early in-dialog requests.
            if id.remote_tag.is_empty() {
                return None;
            }
            let mut pending_id = id.clone();
            pending_id.remote_tag.clear();
            dialogs
                .get(&pending_id)
                .filter(|dialog| dialog.id() == *id)
                .cloned()
        })
    }

    /// Legacy lookup by display string. Returns `None` if no dialog matches or
    /// the string is ambiguous. This scans the registry; prefer the typed
    /// [`Self::get_dialog`] for unambiguous lookup without a scan.
    pub fn get_dialog_with(&self, id: &String) -> Option<Dialog> {
        self.inner.dialogs.with(|m| {
            let mut matches = m.iter().filter(|(key, _)| key.to_string() == *id);
            let first = matches.next()?.1;
            if matches.next().is_some() {
                None
            } else {
                Some(first.clone())
            }
        })
    }
    /// Returns all client-side INVITE dialogs (UAC) that share the given Call-ID.
    ///
    /// In a forking scenario, multiple client dialogs can exist for the same
    /// Call-ID (same local From-tag, different remote To-tags). This helper
    /// scans the internal dialog registry and returns all `InviteDialog`
    /// instances whose `DialogId.call_id` equals the provided `call_id`.
    ///
    /// The returned vector may be empty if no matching client dialogs are found.
    pub fn get_client_dialog_by_call_id(&self, call_id: &str) -> Vec<InviteDialog> {
        self.inner.dialogs.with(|m| {
            m.values()
                .filter_map(|d| match d {
                    Dialog::Invite(client_dlg)
                        if client_dlg.role() == TransactionRole::Client
                            && client_dlg.id().call_id == call_id =>
                    {
                        Some(client_dlg.clone())
                    }
                    _ => None,
                })
                .collect()
        })
    }

    /// Restore a dialog from persisted snapshot.
    ///
    /// Restores only CONFIRMED snapshots.
    /// Non-confirmed snapshots are ignored (warn inside try_restore_from_snapshot).
    /// Restores without authentication credentials. To supply credentials from
    /// the application's configuration, use
    /// [`Self::restore_from_snapshot_with_credential`].
    ///
    /// Returns:
    /// - Ok(true)  => restored and inserted
    /// - Ok(false) => skipped (already exists or not confirmed)
    ///
    /// Concurrent restores of the same dialog insert at most one instance;
    /// an existing dialog is never replaced by a restored snapshot.
    pub fn restore_from_snapshot(
        &self,
        snapshot: DialogSnapshot,
        state_sender: DialogStateSender,
    ) -> crate::Result<bool> {
        self.restore_from_snapshot_with_credential(snapshot, state_sender, None)
    }

    /// Restore a confirmed dialog with optional SIP digest credentials.
    ///
    /// Credentials are supplied by the application, not stored in
    /// [`DialogSnapshot`]. They are used by the existing authentication logic
    /// when an outgoing in-dialog request receives a 401/407 challenge, for
    /// either the original client or server role.
    ///
    /// Passing `None` is equivalent to [`Self::restore_from_snapshot`].
    /// Returns `Ok(true)` when inserted, or `Ok(false)` if the dialog already
    /// exists or the snapshot is not confirmed. An existing dialog's
    /// credentials are not updated by a skipped restore.
    ///
    /// ```rust,no_run
    /// use rsipstack::dialog::{
    ///     authenticate::Credential,
    ///     dialog::{DialogSnapshot, DialogStateSender},
    ///     dialog_layer::DialogLayer,
    /// };
    /// # fn restore(layer: &DialogLayer, snapshot: DialogSnapshot,
    /// #     states: DialogStateSender, credential: Credential) -> rsipstack::Result<()> {
    /// layer.restore_from_snapshot_with_credential(snapshot, states, Some(credential))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn restore_from_snapshot_with_credential(
        &self,
        snapshot: DialogSnapshot,
        state_sender: DialogStateSender,
        credential: Option<Credential>,
    ) -> crate::Result<bool> {
        // Already restored?
        if self.get_dialog(&snapshot.id).is_some() {
            return Ok(false);
        }

        let tu_sender = transaction_event_sender_noop();

        let Some(mut inner) = DialogInner::try_restore_from_snapshot(
            snapshot,
            self.endpoint.clone(),
            state_sender,
            tu_sender,
        )?
        else {
            // not confirmed -> ignored
            return Ok(false);
        };

        inner.credential = credential;
        let inner = Arc::new(inner);
        let dialog = Dialog::from_inner(inner.role, inner.clone());

        let key = dialog.id();

        // Another restore or live dialog may have won while we built this one.
        // Check and insert under the same registry lock, without replacing it.
        Ok(self
            .inner
            .dialogs
            .with_mut(|dialogs| match dialogs.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(dialog);
                    true
                }
                Entry::Occupied(_) => false,
            }))
    }

    pub fn remove_dialog(&self, id: &DialogId) {
        let dialog = self.inner.dialogs.with_mut(|dialogs| {
            if let Some(dialog) = dialogs.remove(id) {
                return Some(dialog);
            }
            let mut pending_id = id.clone();
            pending_id.remote_tag.clear();
            if dialogs
                .get(&pending_id)
                .is_some_and(|dialog| dialog.id() == *id)
            {
                dialogs.remove(&pending_id)
            } else {
                None
            }
        });
        if let Some(dialog) = dialog {
            dialog.on_remove()
        }
    }

    pub fn match_dialog(&self, tx: &Transaction) -> Option<Dialog> {
        let id = DialogId::try_from(tx).ok()?;
        self.get_dialog(&id)
    }

    pub fn new_dialog_state_channel(&self) -> (DialogStateSender, DialogStateReceiver) {
        crate::platform::mpsc::unbounded_channel()
    }

    pub fn build_local_contact(
        &self,
        username: Option<String>,
        params: Option<Vec<crate::sip::Param>>,
    ) -> Result<crate::sip::Uri> {
        let addr = self
            .endpoint
            .transport_layer
            .get_addrs()
            .first()
            .ok_or(crate::Error::EndpointError("not sipaddrs".to_string()))?
            .clone();

        let scheme = if matches!(addr.r#type, Some(crate::sip::Transport::Tls)) {
            crate::sip::Scheme::Sips
        } else {
            crate::sip::Scheme::Sip
        };

        let mut params = params.unwrap_or_default();
        if !matches!(addr.r#type, Some(crate::sip::Transport::Udp) | None) {
            if let Some(t) = addr.r#type {
                params.push(crate::sip::Param::Transport(t))
            }
        }
        let auth = username.map(|user| crate::sip::Auth {
            user,
            password: None,
        });
        Ok(crate::sip::Uri {
            scheme: Some(scheme),
            auth,
            host_with_port: addr.addr.clone(),
            params,
            ..Default::default()
        })
    }
}
