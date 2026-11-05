# Changelog

## 0.8.1

Fourteen fixes and additions merged (#223–#236). One public API change:
`Method` gained `Method::Other(String)` for RFC 3261 extension methods and is
no longer `Copy`; exhaustive matches over `Method` must handle the new variant.
Other public signatures, configuration defaults, and snapshot fields are
unchanged.

### Dialog lifecycle and concurrency (#223–#225, #231–#235)

- A final 401/407 for an in-dialog request now returns to its caller without
  terminating a confirmed dialog when credentials are absent or the retry is
  rejected. Applications can decide whether to retry, report the failed
  operation, or explicitly hang up. Initial INVITE authentication and early
  dialog handling are unchanged; an outgoing BYE still ends the dialog.
- `reinvite_with_glare_retry()` now uses the RFC 3261 §14.1 role-specific 491
  retry windows: 2.1–4.0 s for the Call-ID owner and 0–2.0 s for the other
  endpoint, with 10 ms increments.
- `increment_local_seq()` / `increment_last_seq()` reserve distinct CSeq values
  for concurrent callers instead of returning the same value.
- `restore_from_snapshot()` inserts atomically and is idempotent: concurrent
  restores report exactly one successful insertion and never replace a live or
  restored dialog.
- New `DialogLayer::restore_from_snapshot_with_credential(snapshot, states,
  credential)` supplies runtime-only SIP digest credentials for restored
  dialogs. The existing `restore_from_snapshot()` delegates with `None`.
- Incoming INVITE-dialog requests validate and advance the remote CSeq
  atomically; ACK/CANCEL reuse their INVITE's CSeq and do not advance it.
- INVITE transactions are admitted per dialog: conflicting local INVITEs are
  rejected with `DialogError/RequestPending`, incoming re-INVITEs during a
  pending local INVITE receive 491, and duplicate incoming INVITEs receive 500
  with a random Retry-After.
- UAC dialogs are confirmed and registered before awaiting the initial ACK, so
  an incoming BYE during that window no longer receives 481.

### SIP message parsing (#227–#230)

- `Method::Other(String)` accepts any RFC 3261 token as an extension method
  while rejecting empty or non-token values.
- URI parsing extracts `scheme:`/`userinfo@` before headers and parameters, and
  preserves opaque non-SIP URIs (for example `urn:service:sos`) instead of
  splitting `:digits` as a port.
- `name-addr`, `Contact`, and `Via` validation rejects unbalanced quotes,
  unquoted display names with non-token characters, whitespace inside `<...>`,
  missing `;` before header parameters, empty Contact entries, and invalid
  protocol versions.
- Request-Line, Status-Line, and core headers are validated per RFC 3261 and
  RFC 4475, including version, whitespace, URI form, CSeq method matching,
  numeric bounds, and `Date` format.
- RFC 4475 §3.3.9 (`mcl01`) duplicate `Content-Length` remains invalid:
  datagram transports answer 400 from the header block and stream framing
  rejects and closes the connection. Added regression coverage for both.

### Transactions (#226)

- Reliable transports now terminate server non-INVITE transactions immediately
  (Timer J = 0, RFC 3261 §17.2.2) instead of retaining the final response for
  `64*T1`.

### Testing (#236)

- Added the opt-in PJSUA/SIPp interoperability harness: 161 external-peer cases
  covering calls, dialogs, authentication, PRACK, registration, subscription,
  re-INVITE/UPDATE, forked responses, and deterministic UDP fault injection.
- Adapted dialog and interop tests to the non-`Copy` `Method` type.

## 0.8.0

Four RFC-compliance fixes merged (#216, #217, #218, #219). **No public API
signature changed** — `TransactionKey::from_request` / `from_response`,
`Received::parse`, dialog and endpoint APIs keep their signatures, and every
new item is additive. However, several behaviours became stricter or changed
toward RFC 3261; downstream code relying on the old lenient behaviour must be
reviewed. Details below.

### IPv6 & dual-stack transports (#216)

- Listeners bound to `::` explicitly set `IPV6_V6ONLY=off`, so they always
  serve IPv4 too, regardless of the OS `net.ipv6.bindv6only` sysctl (or BSD /
  Windows defaults). Binding a specific IPv6 address stays IPv6-only. To run
  separate same-port listeners per family, bind explicit addresses (`0.0.0.0`
  and a given IPv6 address), not `::` and `0.0.0.0`.
- IPv4 peers of dual-stack sockets surface as IPv4, never as
  `::ffff:a.b.c.d`, on both UDP and TCP/TLS/WebSocket accepts.
- `Via received` for IPv6 sources is written bare (`received=2001:db8::7`,
  RFC 3261 §20.42); previously it was bracketed. Bracketed forms
  (RFC 5118 §4.5, emitted by some stacks) are now accepted when parsing.
- UDP sends pick a listener that can reach the target's address family; a
  dual-stack listener serves both.
- WebSocket client URLs bracket IPv6 hosts (`ws://[2001:db8::1]:5060/`).
- New API: `platform::net::canonical_socket_addr`, `platform::net::socket_for`
  (`platform-tokio`), `UdpConnection::can_send_to`.

### Dialog target refresh (#217)

- In-dialog INVITE and UPDATE now refresh the remote target (R-URI and
  Contact) from a single, well-formed Contact — previously the Contact of
  in-dialog refreshes was ignored, so later in-dialog requests kept going to
  the stale address. Reliable INVITE provisionals refresh the target before
  PRACK is built (RFC 6141 §4.7/4.9).
- A refresh is committed only after an accepting response is actually sent
  (2xx, or reliable 1xx for INVITE); rejections (e.g. 488) and send failures
  preserve the old target, and a slow older CSeq can never overwrite a newer
  refresh. Route sets are never learned from refreshes (RFC 3261 §12.2).
- Malformed incoming Contacts on in-dialog INVITE/UPDATE (missing Contact,
  multiple Contacts, `*`, non-SIP URI) are rejected with 400 before the
  application observes the request.
- **Behaviour change**: applications that relied on in-dialog requests always
  going to the original Contact will now see them sent to refreshed targets.

### Message body framing (#218)

- `Content-Length` is validated per RFC 3261 §18.3/§25.1: exactly one per
  message (compact `l:` counts), digits only, and a truncated body is a parse
  error instead of being silently cut.
- Stream transports (TCP/TLS/WS) require `Content-Length` on every message —
  framing without it is an error (RFC 3261 §18.3). Datagram transports treat
  a missing header as "the rest of the packet is the body".
- **Behaviour change**: peers that omit `Content-Length` on stream transports
  previously appeared to work when it defaulted to zero; they are now
  rejected. Intermediaries stripping the header will surface errors.
- UDP: malformed *requests* whose routing headers are usable get a stateless
  400 (with a repeatable To tag, RFC 3261 §8.2.7); malformed responses and
  malformed ACK/CANCEL are silently discarded.

### Transaction matching (#219)

- `TransactionKey` is a structured value instead of a formatted string.
  Server transactions match on top Via branch + sent-by + method
  (RFC 3261 §17.2.3); client transactions on branch + CSeq method only
  (§17.1.3). Requests without a `z9hG4bK` cookie branch use RFC 2543
  compatibility matching (From/To tags are now optional).
- **Behaviour changes** visible to embedders:
  - `TransactionKey`'s `Display` output changed (it was an internal
    `s.INVITE_2_...` string; it is now a diagnostic struct form). It was only
    ever used in logs — nothing serialises it.
  - `TransactionKey::from_request(.., Client)` without any Via branch now
    errors (RFC 3261 §8.1.1.7 requires one); it previously produced a legacy
    key.
  - `TransactionKey::from_response(.., Server)` for a non-cookie branch now
    errors: a legacy server key cannot be recovered from a response.
  - A CANCEL that matches no transaction is answered 481 with a To tag
    (§9.2, §8.2.6.2); CANCEL retransmissions receive the cached response and
    reach the INVITE transaction's TU only once.

### Post-merge fixes

- `src/transport/tests/test_udp.rs`: socket2 0.6 removed `Socket::domain()`;
  the IPv4-family assertion now checks that an IPv4 socket refuses to bind an
  IPv6 address.
- Clippy `never_loop` in `dialog::tests::test_refer_notify` and two unused
  variables silenced; `cargo clippy --all-features --all-targets` and
  `cargo check --no-default-features --features platform-embassy` are clean.
