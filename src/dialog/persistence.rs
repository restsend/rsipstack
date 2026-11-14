//! Opt-in durable checkpoints. Storage remains application-owned.
//!
//! Each dialog has one serial worker. A callback runs without a dialog state
//! lock and may inspect snapshots. It must not await another SIP operation on
//! the same dialog: that operation would wait behind this callback.
//!
//! Returning `Ok(())` promises the application has durably committed the supplied
//! snapshot and any related application state. No serialization or database is
//! chosen by the stack. Applications choose which message fields to serialize;
//! SIP messages may include authentication headers. Media policy remains external.
//!
//! Failure or timeout poisons this dialog's persistence worker. No subsequent
//! protected sends are permitted. A timeout cannot undo a database write that
//! has already started; recovery must inspect storage. Ordinary lifecycle events
//! are released only after the checkpoint covering them succeeds. The legacy
//! `DialogState` channel is still a protocol channel, not a durable commit feed.
//!
//! Enable this explicitly before creating or restoring calls:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rsipstack::dialog::{dialog_layer::DialogLayer, persistence::*};
//! # fn configure(layer: &DialogLayer, store: Arc<dyn DialogPersistence>) -> rsipstack::Result<()> {
//! layer.set_persistence(Some(DialogPersistenceConfig::new(store)))?;
//! # Ok(())
//! # }
//! ```
//!
//! Protected boundaries are the first outgoing request of each dialog-owned
//! transaction (including authentication retries), an incoming final response
//! before its ACK, a locally generated final response before transport send,
//! local termination intent, and completed signaling/terminal state. A wire
//! response and its later acknowledgment are separate checkpoints. Provisional
//! responses and transaction-generated CANCEL acknowledgments do not wait for
//! storage. Pure transaction/proxy users are unaffected.
//!
//! A commit cannot be atomic with network transmission. A crash after commit
//! but before send leaves an intended message with an unknown send outcome.
//! Recovery must use the pending markers and application policy; the stack does
//! not replay in-flight transactions. A successful `accept()`/`reject()` only
//! queues a response: the transaction driver performs its checkpoint. Errors
//! from asynchronous/terminal writes are exposed by `persistence_status()`.
//! After failure, remove the dialog from the layer and reconcile stored state;
//! there is no automatic retry or fail-open mode. The application must keep its
//! async runtime alive long enough to finish accepted writes during shutdown.
//!
//! Handlers must yield rather than block an executor, and must not panic. Use
//! an application-owned incarnation key alongside dialog ID/revision for
//! snapshot idempotency across process restarts. Multiple checkpoints may share
//! a revision: it versions dialog state, not a storage operation. Deduplicate
//! message-related work with its own request/operation identity as well.
//! A new lifecycle notification is not an
//! exactly-once external side effect; persist an application outbox if needed.
//! Early checkpoints may have an empty remote tag; correlate them with the
//! later established dialog using that same application call/incarnation key.

use super::{
    dialog::{DialogInner, DialogSnapshot},
    lifecycle::DialogLifecycleEvent,
};
use crate::{
    platform::{mpsc, sync::Mutex},
    prelude::*,
    sip::SipMessage,
};
use alloc::sync::Weak;
use async_trait::async_trait;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialogCheckpointReason {
    /// Before the first send of a transaction, including authenticated retries.
    OutgoingRequest,
    /// Local hangup/cancellation intent, before waiting for an ACK or peer.
    LocalTerminationRequested,
    /// Before sending a final response to an incoming request.
    BeforeResponse,
    /// An INVITE final response was received; before its automatic ACK.
    /// Includes failures/challenges, re-INVITEs, and fork cleanup. A successful
    /// re-INVITE's snapshot already contains its accepted Contact. The message
    /// preserves the observed response; lifecycle facts identify initial acceptance.
    BeforeAck,
    /// A completed ACK/negotiation permits future quiescent restoration.
    SignalingCompleted,
    /// The dialog ended, including local rejection and protocol timeout.
    Terminated,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DialogCheckpoint {
    pub reason: DialogCheckpointReason,
    pub snapshot: DialogSnapshot,
    /// Intended or observed SIP message, when the checkpoint protects a send.
    /// This lets the application commit its SDP or request metadata atomically.
    pub message: Option<SipMessage>,
}

#[async_trait]
pub trait DialogPersistence: Send + Sync {
    async fn save(&self, checkpoint: DialogCheckpoint) -> crate::Result<()>;
}

#[derive(Clone)]
pub struct DialogPersistenceConfig {
    pub handler: Arc<dyn DialogPersistence>,
    pub timeout: Duration,
}

impl DialogPersistenceConfig {
    pub fn new(handler: Arc<dyn DialogPersistence>) -> Self {
        Self {
            handler,
            timeout: Duration::from_secs(5),
        }
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.timeout.is_zero() {
            return Err(crate::Error::Error(
                "persistence timeout must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DialogPersistenceStatus {
    pub last_committed_revision: Option<u64>,
    pub failure: Option<String>,
}

type CommitResult = core::result::Result<(), String>;
pub(crate) type CommitReceiver = mpsc::UnboundedReceiver<CommitResult>;

struct Work {
    checkpoint: DialogCheckpoint,
    reply: mpsc::UnboundedSender<CommitResult>,
}

pub(crate) struct PersistenceRuntime {
    sender: mpsc::UnboundedSender<Option<Work>>,
    pub status: Arc<Mutex<DialogPersistenceStatus>>,
}

impl PersistenceRuntime {
    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    pub fn start(dialog: Weak<DialogInner>, config: DialogPersistenceConfig) -> Arc<Self> {
        let (sender, mut receiver) = mpsc::unbounded_channel::<Option<Work>>();
        let status = Arc::new(Mutex::new(DialogPersistenceStatus::default()));
        let worker_status = status.clone();
        // The worker never owns a strong dialog reference while awaiting storage.
        // Dropping the dialog queues a stop marker; pending writes have finite timeouts.
        crate::platform::spawn(async move {
            while let Some(Some(work)) = receiver.recv().await {
                let revision = work.checkpoint.snapshot.runtime.revision;
                let sequence = work
                    .checkpoint
                    .snapshot
                    .runtime
                    .lifecycle
                    .last()
                    .map_or(0, |fact| fact.sequence);
                let previous = worker_status.lock().clone();
                let result = if let Some(error) = previous.failure {
                    Err(error)
                } else if previous
                    .last_committed_revision
                    .is_some_and(|r| r > revision)
                {
                    Err("checkpoint revision moved backwards".into())
                } else if work.checkpoint.reason == DialogCheckpointReason::Terminated
                    && previous.last_committed_revision == Some(revision)
                {
                    Ok(())
                } else {
                    match crate::platform::timeout(
                        config.timeout,
                        config.handler.save(work.checkpoint),
                    )
                    .await
                    {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => Err(format!("dialog persistence failed: {error}")),
                        Err(_) => {
                            Err("dialog persistence timed out; commit outcome is unknown".into())
                        }
                    }
                };
                match &result {
                    Ok(()) => {
                        worker_status.lock().last_committed_revision = Some(revision);
                        if let Some(dialog) = dialog.upgrade() {
                            dialog.release_committed_facts(sequence);
                        }
                    }
                    Err(error) => {
                        worker_status.lock().failure = Some(error.clone());
                        tracing::warn!(%error, revision, "dialog persistence stopped");
                    }
                }
                let _ = work.reply.send(result);
            }
        });
        Arc::new(Self { sender, status })
    }

    /// Enqueue while the snapshot gate is held; user code runs in the worker.
    pub fn submit(&self, checkpoint: DialogCheckpoint) -> CommitReceiver {
        let (reply, receiver) = mpsc::unbounded_channel();
        if let Some(error) = self.status.lock().failure.clone() {
            let _ = reply.send(Err(error));
            return receiver;
        }
        if let Err(error) = self.sender.send(Some(Work { checkpoint, reply })) {
            if let Some(work) = error.0 {
                let _ = work
                    .reply
                    .send(Err("dialog persistence worker stopped".into()));
            }
        }
        receiver
    }
}

impl DialogInner {
    pub(crate) fn configure_persistence(self: &Arc<Self>, config: Option<DialogPersistenceConfig>) {
        if let Some(config) = config {
            *self.persistence_owner.lock() = Arc::downgrade(self);
            self.lifecycle.lock().defer_delivery = true;
            *self.persistence.lock() =
                Some(PersistenceRuntime::start(Arc::downgrade(self), config));
        }
    }

    pub(crate) fn bind_persistence(&self, tx: &crate::transaction::transaction::Transaction) {
        *tx.persistence_dialog.lock() = self.persistence_owner.lock().clone();
    }

    pub(crate) fn release_committed_facts(&self, sequence: u64) {
        let _state = self.state.lock();
        let mut lifecycle = self.lifecycle.lock();
        let mut waiting: Vec<DialogLifecycleEvent> = Vec::new();
        for event in core::mem::take(&mut lifecycle.undelivered) {
            if event.sequence <= sequence {
                if let Some(sender) = &lifecycle.sender {
                    let _ = sender.send(event);
                }
            } else {
                waiting.push(event);
            }
        }
        lifecycle.undelivered = waiting;
    }

    #[cfg_attr(not(feature = "platform-tokio"), allow(unused_mut))]
    pub(crate) async fn checkpoint(
        &self,
        reason: DialogCheckpointReason,
        message: Option<SipMessage>,
    ) -> crate::Result<()> {
        let receiver = {
            let state = self.state.lock();
            self.enqueue_checkpoint_locked(&state, reason, message)
        };
        if let Some(mut receiver) = receiver {
            receiver
                .recv()
                .await
                .unwrap_or_else(|| Err("dialog persistence worker stopped".into()))
                .map_err(crate::Error::Error)?;
        }
        Ok(())
    }

    pub(crate) fn enqueue_checkpoint_locked(
        &self,
        state: &super::dialog::DialogState,
        reason: DialogCheckpointReason,
        message: Option<SipMessage>,
    ) -> Option<CommitReceiver> {
        let runtime = self.persistence.lock().clone()?;
        Some(runtime.submit(DialogCheckpoint {
            reason,
            snapshot: self.snapshot_locked(state),
            message,
        }))
    }
}

impl Drop for PersistenceRuntime {
    fn drop(&mut self) {
        // Also works on runtimes whose channels do not close on last-sender drop.
        // FIFO drains already accepted writes before stopping the worker.
        let _ = self.sender.send(None);
    }
}
