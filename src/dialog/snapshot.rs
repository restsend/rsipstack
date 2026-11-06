//! Recovery metadata captured together with the dialog's routing state.
#![doc = include_str!("../../MIGRATING-0.9.md")]
use super::dialog::{DialogSnapshot, DialogSnapshotState, SessionIdState};
use super::lifecycle::DialogLifecycleKind;
use super::DialogId;
use crate::sip::{headers::Route, typed, Uri};
use crate::transaction::key::TransactionRole;
use alloc::vec::Vec;
use core::time::Duration;

/// Reconstruct application-owned snapshot data through [`DialogSnapshot::builder`].
///
/// State, CSeq values and runtime metadata have no implicit defaults. Optional
/// contacts and Session-ID default to `None`, routes to an empty vector, and
/// 100rel support to `false`. Preserve all stored values when rebuilding a
/// snapshot; defaults do not migrate storage or infer missing recovery data.
#[derive(Clone, Debug)]
#[must_use]
pub struct DialogSnapshotBuilder {
    id: DialogId,
    role: TransactionRole,
    from: typed::From,
    to: typed::To,
    remote_uri: Uri,
    state: Option<DialogSnapshotState>,
    local_cseq: Option<u32>,
    remote_cseq: Option<u32>,
    runtime: Option<DialogSnapshotRuntime>,
    local_contact: Option<Uri>,
    remote_contact: Option<crate::sip::headers::untyped::Contact>,
    route_set: Vec<Route>,
    supports_100rel: bool,
    session_id: Option<SessionIdState>,
}

impl DialogSnapshotBuilder {
    pub(crate) fn new(
        id: DialogId,
        role: TransactionRole,
        from: typed::From,
        to: typed::To,
        remote_uri: Uri,
    ) -> Self {
        Self {
            id,
            role,
            from,
            to,
            remote_uri,
            state: None,
            local_cseq: None,
            remote_cseq: None,
            runtime: None,
            local_contact: None,
            remote_contact: None,
            route_set: Vec::new(),
            supports_100rel: false,
            session_id: None,
        }
    }

    /// Set the persisted dialog state; building does not imply confirmation.
    pub fn state(mut self, state: DialogSnapshotState) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the persisted local sequence counter, without resetting it.
    pub fn local_cseq(mut self, cseq: u32) -> Self {
        self.local_cseq = Some(cseq);
        self
    }

    /// Set the persisted remote sequence counter, including an explicit zero.
    pub fn remote_cseq(mut self, cseq: u32) -> Self {
        self.remote_cseq = Some(cseq);
        self
    }

    /// Set recovery metadata, preserving pending operations and lifecycle facts.
    ///
    /// For pre-0.9 records, pass `DialogSnapshotRuntime::default()` only after
    /// the application has established that no signaling was in flight. Missing
    /// metadata alone is not evidence of a quiescent dialog.
    pub fn runtime(mut self, runtime: DialogSnapshotRuntime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn local_contact(mut self, contact: Option<Uri>) -> Self {
        self.local_contact = contact;
        self
    }

    pub fn remote_contact(
        mut self,
        contact: Option<crate::sip::headers::untyped::Contact>,
    ) -> Self {
        self.remote_contact = contact;
        self
    }

    pub fn route_set(mut self, routes: Vec<Route>) -> Self {
        self.route_set = routes;
        self
    }

    pub fn supports_100rel(mut self, supported: bool) -> Self {
        self.supports_100rel = supported;
        self
    }

    pub fn session_id(mut self, session_id: Option<SessionIdState>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Check required inputs and the lifecycle history of a confirmed snapshot.
    ///
    /// This does not restore a dialog or prove it can be resumed. In particular,
    /// pending operations and non-confirmed states remain representable for
    /// application recovery decisions. Restore still rejects confirmed snapshots
    /// with pending signaling and skips non-confirmed snapshots. Mutable public
    /// fields are rechecked at restore time.
    pub fn build(self) -> crate::Result<DialogSnapshot> {
        let snapshot = DialogSnapshot {
            id: self.id,
            role: self.role,
            from: self.from,
            to: self.to,
            remote_uri: self.remote_uri,
            state: self
                .state
                .ok_or_else(|| crate::Error::Error("snapshot state is required".into()))?,
            local_cseq: self
                .local_cseq
                .ok_or_else(|| crate::Error::Error("snapshot local CSeq is required".into()))?,
            remote_cseq: self
                .remote_cseq
                .ok_or_else(|| crate::Error::Error("snapshot remote CSeq is required".into()))?,
            runtime: self.runtime.ok_or_else(|| {
                crate::Error::Error("snapshot runtime metadata is required".into())
            })?,
            local_contact: self.local_contact,
            remote_contact: self.remote_contact,
            route_set: self.route_set,
            supports_100rel: self.supports_100rel,
            session_id: self.session_id,
        };
        if snapshot.state == DialogSnapshotState::Confirmed {
            super::lifecycle::LifecycleState::restored(&snapshot.runtime)?;
        }
        Ok(snapshot)
    }
}

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
