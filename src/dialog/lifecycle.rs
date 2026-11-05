//! Optional, observational events for an INVITE dialog.
//!
//! Unlike `DialogState`, these are facts, not requests for application action.
//! Delivery never awaits application code or storage. Events are not a durable
//! journal: a closed receiver drops notifications without affecting SIP.
//!
//! Configure the layer before creating calls:
//!
//! ```rust,no_run
//! use rsipstack::dialog::{dialog_layer::DialogLayer, lifecycle::*};
//! # async fn example(layer: &DialogLayer) {
//! let (sender, mut events) = dialog_lifecycle_channel();
//! layer.set_lifecycle_events(Some(sender));
//! // Drive calls and this receiver in separate application tasks.
//! while let Some(event) = events.recv().await {
//!     match event.kind {
//!         DialogLifecycleKind::InviteAccepted { .. } => { /* initial answer */ }
//!         DialogLifecycleKind::RemoteByeReceived => { /* peer hangup */ }
//!         _ => {}
//!     }
//! }
//! # }
//! ```
//!
//! `occurred_at` and `sequence` have different purposes: concurrent operations
//! may be admitted in a different order from their receive timestamps. Use the
//! sequence to order delivered facts, and the timestamp for the original time.
//! A UAS send can complete after a racing BYE: its `InviteAccepted` fact can
//! follow `DialogTerminated`. This reports transport completion, not a revival.
//! Wall time can jump; use monotonic time for intervals within one process.
//! CDR policy, storage, and cross-process event deduplication belong to the
//! application. An accepted CANCEL followed by a late 2xx is cleanup, not a new
//! accepted call. Fork branches discarded by the dialog are not reported.
//!
//! Subscriptions apply to subsequently created or restored dialogs. Restoring
//! a snapshot retains fact sequence numbers without replaying notifications.
//! The existing `DialogState` channel is unchanged. An unbounded
//! receiver avoids SIP backpressure; applications must drain or drop it.

use super::{dialog::TerminatedReason, DialogId};
use crate::platform::{mpsc, Instant};
use crate::sip::StatusCode;
use crate::transaction::key::TransactionRole;
use core::time::Duration;

/// Time captured where the stack observes an operation, not when it delivers
/// the notification. Incoming times are captured at endpoint dispatch of a
/// parsed message (not kernel packet arrival), before the transaction or
/// application queue. Direct transaction injection falls back to processing
/// time. Monotonic time measures intervals within this process;
/// UTC is optional on platforms without a wall clock. Do not persist `monotonic`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleTime {
    pub monotonic: Instant,
    pub since_unix_epoch: Option<Duration>,
}

impl LifecycleTime {
    pub(crate) fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            #[cfg(feature = "std")]
            since_unix_epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok(),
            #[cfg(not(feature = "std"))]
            since_unix_epoch: None,
        }
    }
}

/// Each fact is emitted at most once per live dialog. Successful re-INVITEs,
/// retransmissions, and other fork branches do not repeat `InviteAccepted`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DialogLifecycleKind {
    /// The UAC received, or the UAS successfully sent, the initial INVITE 2xx.
    /// This does not claim that an ACK or media exchange has completed.
    InviteAccepted { status: StatusCode },
    /// A local BYE, CANCEL, or rejection was admitted, before waiting for
    /// network completion. This does not claim that a message reached the peer.
    LocalTerminationRequested,
    /// An incoming BYE passed dialog identity and sequence validation.
    RemoteByeReceived,
    /// The dialog entered its terminal state; transaction cleanup may continue.
    DialogTerminated { reason: TerminatedReason },
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DialogLifecycleEvent {
    pub dialog_id: DialogId,
    pub role: TransactionRole,
    /// Starts at one. Orders facts within this dialog; unrelated to SIP CSeq.
    pub sequence: u64,
    pub occurred_at: LifecycleTime,
    pub kind: DialogLifecycleKind,
}

pub type DialogLifecycleSender = mpsc::UnboundedSender<DialogLifecycleEvent>;
pub type DialogLifecycleReceiver = mpsc::UnboundedReceiver<DialogLifecycleEvent>;

pub fn dialog_lifecycle_channel() -> (DialogLifecycleSender, DialogLifecycleReceiver) {
    mpsc::unbounded_channel()
}

#[derive(Default)]
pub(crate) struct LifecycleState {
    pub sender: Option<DialogLifecycleSender>,
    pub sequence: u64,
    pub emitted: u8,
    pub revision: u64,
    pub pending_initial_ack: bool,
    pub pending_remote_bye: bool,
    pub negotiations: u32,
    pub facts: alloc::vec::Vec<super::snapshot::DialogLifecycleRecord>,
}

impl LifecycleState {
    pub fn restored(runtime: &super::snapshot::DialogSnapshotRuntime) -> crate::Result<Self> {
        let mut state = Self {
            revision: runtime.revision,
            ..Self::default()
        };
        for fact in &runtime.lifecycle {
            let bit = match &fact.kind {
                DialogLifecycleKind::InviteAccepted { status }
                    if status.kind() == crate::sip::StatusCodeKind::Successful =>
                {
                    1
                }
                DialogLifecycleKind::LocalTerminationRequested => 2,
                DialogLifecycleKind::RemoteByeReceived => 4,
                // A confirmed snapshot cannot already contain a terminal fact.
                _ => {
                    return Err(crate::Error::Error(
                        "invalid snapshot lifecycle fact".into(),
                    ))
                }
            };
            if state.emitted & bit != 0 || fact.sequence != state.sequence + 1 {
                return Err(crate::Error::Error(
                    "invalid snapshot lifecycle sequence".into(),
                ));
            }
            state.emitted |= bit;
            state.sequence = fact.sequence;
        }
        if runtime.revision < state.sequence || runtime.revision == u64::MAX {
            return Err(crate::Error::Error("invalid snapshot revision".into()));
        }
        state.facts = runtime.lifecycle.clone();
        Ok(state)
    }

    pub fn emit(
        &mut self,
        id: DialogId,
        role: TransactionRole,
        time: LifecycleTime,
        kind: DialogLifecycleKind,
    ) {
        let bit = match &kind {
            DialogLifecycleKind::InviteAccepted { .. } => 1,
            DialogLifecycleKind::LocalTerminationRequested => 2,
            DialogLifecycleKind::RemoteByeReceived => 4,
            DialogLifecycleKind::DialogTerminated { .. } => 8,
        };
        if self.emitted & bit != 0 || (self.emitted & 8 != 0 && bit != 1) {
            return;
        }
        self.emitted |= bit;
        self.sequence += 1;
        self.revision += 1;
        self.facts.push(super::snapshot::DialogLifecycleRecord {
            sequence: self.sequence,
            since_unix_epoch: time.since_unix_epoch,
            kind: kind.clone(),
        });
        if let Some(sender) = &self.sender {
            let _ = sender.send(DialogLifecycleEvent {
                dialog_id: id,
                role,
                sequence: self.sequence,
                occurred_at: time,
                kind,
            });
        }
    }
}
