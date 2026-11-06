//! Recovery metadata captured together with the dialog's routing state.
use super::lifecycle::DialogLifecycleKind;
use alloc::vec::Vec;
use core::time::Duration;

/// A persisted fact deliberately excludes process-local monotonic time.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DialogLifecycleRecord {
    pub sequence: u64,
    pub since_unix_epoch: Option<Duration>,
    pub kind: DialogLifecycleKind,
}

impl DialogLifecycleRecord {
    /// Reconstruct a fact from application-owned storage.
    ///
    /// Preserves the supplied sequence and optional wall-clock timestamp; it
    /// does not generate a new event or time. The complete history is validated
    /// when restoring a confirmed snapshot through
    /// [`DialogLayer::restore_from_snapshot`](super::dialog_layer::DialogLayer::restore_from_snapshot).
    ///
    /// ```
    /// use core::time::Duration;
    /// use rsipstack::dialog::{
    ///     lifecycle::DialogLifecycleKind,
    ///     snapshot::DialogLifecycleRecord,
    /// };
    /// use rsipstack::sip::StatusCode;
    ///
    /// let record = DialogLifecycleRecord::new(
    ///     1,
    ///     Some(Duration::from_millis(1_700_000_000_123)),
    ///     DialogLifecycleKind::InviteAccepted { status: StatusCode::OK },
    /// );
    /// assert_eq!(record.sequence, 1);
    /// ```
    pub fn new(
        sequence: u64,
        since_unix_epoch: Option<Duration>,
        kind: DialogLifecycleKind,
    ) -> Self {
        Self {
            sequence,
            since_unix_epoch,
            kind,
        }
    }
}

/// In-flight work is recorded for recovery decisions, not replayed as SIP
/// transactions. Interrupted application handlers remain pending conservatively.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DialogPendingState {
    pub local_invite: bool,
    pub remote_invite: bool,
    pub remote_invite_awaiting_ack: bool,
    pub initial_ack: bool,
    pub negotiations: u32,
    pub local_termination: bool,
    pub remote_termination: bool,
}

impl DialogPendingState {
    pub fn is_empty(&self) -> bool {
        !self.local_invite
            && !self.remote_invite
            && !self.remote_invite_awaiting_ack
            && !self.initial_ack
            && self.negotiations == 0
            && !self.local_termination
            && !self.remote_termination
    }
}

/// Versioned metadata for a single coherent dialog snapshot. This is not a
/// storage schema: applications own serialization and migrations of old records.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DialogSnapshotRuntime {
    pub revision: u64,
    pub pending: DialogPendingState,
    pub lifecycle: Vec<DialogLifecycleRecord>,
}
