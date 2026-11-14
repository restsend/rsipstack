# Snapshot migration for the proposed 0.9.0 release

These changes require a breaking release. The proposed target is **0.9.0**,
subject to maintainer approval; this document does not announce a release or
change the package version. Do not backport this API change into 0.8.x.

## Constructing and reading snapshots

`DialogSnapshot` now includes coherent runtime metadata and is
`#[non_exhaustive]`. Adding `runtime` breaks old struct literals and exhaustive
patterns. The attribute also prevents external struct literals, even if they
include `runtime`. Replace them with `DialogSnapshot::builder(...)`; adding
`runtime: DialogSnapshotRuntime::default()` to a literal is not sufficient.

Supply the stored identity, role, From/To headers, remote URI, state, both CSeq
counters, and runtime metadata. The builder requires state, counters and runtime
explicitly: it never assumes a stored dialog was confirmed or quiescent. Copy
optional stored contacts, routes, 100rel support and Session-ID through their
builder methods too. Omitting those optional settings yields `None`, no routes,
`false`, and `None`, respectively; it does not recover their persisted values.

This example illustrates an application-approved migration of a legacy,
confirmed record known to have been captured with no signaling in flight:

```rust
use rsipstack::{
    dialog::{
        dialog::{DialogSnapshot, DialogSnapshotState},
        snapshot::DialogSnapshotRuntime,
        DialogId,
    },
    sip::{headers, prelude::ToTypedHeader},
    transaction::key::TransactionRole,
};

let snapshot = DialogSnapshot::builder(
    DialogId {
        call_id: "stored-call".into(),
        local_tag: "local".into(),
        remote_tag: "remote".into(),
    },
    TransactionRole::Client,
    headers::From::from("<sip:alice@example.com>;tag=local").typed()?,
    headers::To::from("<sip:bob@example.com>;tag=remote").typed()?,
    "sip:bob@example.com".try_into()?,
)
.state(DialogSnapshotState::Confirmed)
.local_cseq(42)
.remote_cseq(7)
.local_contact(Some("sip:alice@example.com".try_into()?))
// The application has established that this legacy record was quiescent.
.runtime(DialogSnapshotRuntime::default())
.build()?;

// Field access is unchanged. Patterns must allow future fields.
let DialogSnapshot { id, runtime, .. } = snapshot;
assert_eq!(id.call_id, "stored-call");
assert!(runtime.lifecycle.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The builder checks required inputs and the lifecycle history of confirmed
snapshots. It also represents pending and non-confirmed snapshots so applications
can inspect or store them. `build()` succeeding does **not** guarantee that
restore will resume the dialog. Public fields remain mutable, so restore retains
its own validation.

## Storage and recovery behavior

The application owns serialization, storage schema versions and migrations.
`runtime.revision` identifies a dialog state revision, **not a storage schema**.
Persist the complete runtime metadata, including pending operations and lifecycle
records. Reconstruct individual facts with
`DialogLifecycleRecord::new(sequence, since_unix_epoch, kind)`. Preserve their
sequence and optional wall-clock time; do not invent timestamps or acceptance
events during migration. Restoring retains the history without replaying it to
notification consumers. Monotonic timestamps are process-local and not stored.

For a pre-0.9 record without runtime metadata, explicitly passing
`DialogSnapshotRuntime::default()` represents revision zero, no recorded history,
and no pending operations. This is appropriate only when the application's
existing capture contract or other reliable evidence establishes that signaling
was quiescent. Missing metadata alone does not establish that fact. Empty history
means no history was retained; it is not evidence that the call was never answered.
If quiescence cannot be established, apply an explicit application recovery policy
instead of silently resuming the call. Never discard known pending work or use a
default to hide corrupt metadata.

Calls to `dialog.snapshot()` and `layer.restore_from_snapshot(snapshot, sender)`
keep their signatures. The restore behavior changes as follows:

- A confirmed snapshot with non-empty `runtime.pending` returns an error. SIP
  transactions, outstanding ACKs and application handlers are not replayed.
- Invalid confirmed lifecycle history or revision returns an error.
- Non-confirmed snapshots are still skipped with `Ok(false)`.
- An already registered dialog is still retained and restore returns `Ok(false)`.

Future optional fields may have safe defaults without breaking builder callers.
New data required for safe recovery must instead have an explicit migration or
compatibility plan. `#[non_exhaustive]` protects source construction and matching;
it is not a promise that every future persisted record can be silently migrated.
