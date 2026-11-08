# Changelog

## 0.8.2

Digest authentication interop fixes. Note: `AuthQop`'s `nc` field widened
from `u8` to `u32` (the RFC 2617 `nonce-count` is an 8-hex-digit counter; a
`u8` wrapped at `ff` and rejected `nc=00000100+`).

- Digest: emit the unquoted token form `qop=auth` in Authorization /
  Proxy-Authorization responses (RFC 2617 §3.2.1, RFC 3261 §25.1
  `message-qop`); challenges keep the quoted `qop-options` form.
- Digest: derive `-sess` algorithm HA1 as a session key,
  `H(H(A1):nonce:cnonce)` (RFC 2617 §3.2.2.2, RFC 7616 §5); previously
  `MD5-sess` / `SHA-256-sess` hashed like their non-sess variants and always
  failed verification.
- Digest: `nc` is parsed, printed, and hashed as an 8-digit **hex** counter
  (`{:08x}`); decimal re-encoding desynchronized the server counter at
  nc >= 10.
- Parsing: accept RFC 7616 hyphenated algorithm names (`SHA-256`,
  `SHA-256-sess`, `SHA-512`, `SHA-512-sess`) alongside draft-era spellings.
- Parsing: tolerate multi-option challenge qop lists (`qop="auth,auth-int"`)
  by preferring `auth` (RFC 2617 §3.2.1–§3.2.2); previously such challenges
  failed to parse and authentication could not retry.
- Tests: golden-vector digest coverage against published RFC 2617 values,
  qop-bearing end-to-end INVITE authentication, and qop/algorithm/nc parse
  edge cases.

## 0.8.1

Fourteen fixes and additions merged (#223–#236).

- Dialog: preserve confirmed sessions on in-dialog auth rejection, RFC 3261
  glare retry windows, distinct concurrent CSeq values, atomic/idempotent
  snapshot restore, credentials on restore, atomic remote CSeq validation,
  INVITE overlap/glare handling, and confirm UAC dialogs before awaiting ACK.
- SIP parsing: extension methods via `Method::Other(String)` (**breaking**:
  `Method` is no longer `Copy`), RFC 4475 URI/name-addr/Contact/Via validation,
  and Request-Line/Status-Line/core-header validation.
- Transactions: Timer J = 0 on reliable transports (RFC 3261 §17.2.2).
- Tests: PJSUA/SIPp interoperability harness and duplicate Content-Length
  regression coverage.

No other public signatures, configuration defaults, or snapshot fields changed.

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
