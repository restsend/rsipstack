# RFC 4028 session timers

Session timers are opt-in on new INVITE dialogs. Existing dialogs and restored
snapshots are unaffected by a layer configuration change.

```rust,ignore
use rsipstack::dialog::session_timer::SessionTimerConfig;
layer.set_session_timer(Some(SessionTimerConfig {
    expires: 1800,
    min_se: 90,
    prefer_local: true,
    ..Default::default()
}))?;
```

Use `None` to disable the feature for future dialogs. The default is disabled.
An enabled UAC advertises `Supported: timer`, `Session-Expires`, and `Min-SE`.
An enabled UAS validates those headers, selects a refresher, and answers an
unacceptably short interval with 422 and Min-SE. Both sides respect an explicit
refresher choice and track the agreement per dialog. An unsupported required
timer extension gets 420. Invalid or duplicate timer fields get 400.

The absolute minimum is 90 seconds; tests do not negotiate substandard values
to run faster. 422 retries have a new branch and CSeq, preserve dialog routing
and SDP, and stop after three increasing challenges. Refresh requests preserve
the initial Supported, Require and Proxy-Require options.

The local refresher sends at half the negotiated interval. Automatic mode uses
a bodyless UPDATE when the peer advertised UPDATE, otherwise an offered
re-INVITE with the last successfully exchanged local SDP. `RefreshMethod`
can select either method explicitly. An explicit UPDATE policy requires peer
support. Applications with externally managed SDP should provide `RefreshSdp`
to produce a current offer and consume the successful answer. Its futures must
be cancellation-safe. Incoming offers still go through normal dialog events;
only confirmed-dialog bodyless UPDATE refreshes are answered automatically.

Only successful exchanges reset the timer, measured at received/transmitted
2xx, independently of ACK completion. Duplicate responses do not extend it.
A 2xx without Session-Expires disables the negotiated timer. 408, 481,
transaction/transport failure, or inability to generate a usable refresh ends
the dialog with BYE. Other final failures retain the original deadline; 491
uses the RFC 3261 randomized glare retry window. The remote refresher gets the
RFC 4028 recommended expiration margin (the smaller of 32 seconds and one
third of the interval). BYE/removal stops the worker, including pending waits.
Applications must remove terminated dialogs from their registry as usual.

`InviteDialog::session_timer_status()` exposes the last agreement, remaining
time, automatic refresh/expiration counts, and worker liveness for diagnostics.
An interval in a stopped worker is historical, not an active session.

When dialog persistence is enabled, 422 retries retain the storage barrier and
receipt timestamps. Automatically answered bodyless UPDATE requests record a
pending negotiation before their response and commit the refreshed remote
target after completion. Storage failures prevent protected signaling from
continuing, as for other dialog operations.

Timer agreements/deadlines are not persisted in `DialogSnapshot`. Restart
recovery must explicitly renegotiate or terminate according to application
policy. This change does not implement proxy timer policy or timer/media
coordination inside `ReinviteBridge`; that component retains its documented
extension restrictions. RTP liveness and billing duration are separate.

## Verification

```sh
cargo test --lib test_session_timer
bash scripts/interop/run.sh sipp session_timer
```

Library regressions use Tokio's controllable clock between real UDP exchanges.
They cover both refresher roles, unsupported peers, malformed headers, bounded
422 retries, UPDATE/re-INVITE, invalid successful agreements and ACK ordering,
glare, loss, changing deadlines, missing headers, and timer cancellation.
Eight independent SIPp exchanges cover UAC/UAS with UPDATE/re-INVITE over
UDP/TCP, including a UAC 422 retry and a UAS refresher change. These short wire
tests request explicit refreshes; real automatic refresh intervals belong to
the separate soak runner.

Persistence regressions additionally cover delayed and failed storage for a
422 retry and a delayed automatic UPDATE response with a changed Contact:
`cargo test --lib persistence_`.

Protocol reference: [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028.html),
particularly sections 7, 9, and 10.
