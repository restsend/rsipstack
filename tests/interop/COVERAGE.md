# Coverage and known interoperability gaps

This harness is a growing collection of real-process interoperability tests,
not a certification of complete SIP conformance. A passing case covers only
the exchange and assertions stated for that case.

## Known gap: standard SHA-256 digest challenge

Reproduce with `bash scripts/interop/run.sh known-gaps` (both UDP and TCP),
or select just this issue with `bash scripts/interop/run.sh sipp known_gap_auth_sha256`.

SIPp sends a 401 with `algorithm=SHA-256` and verifies the authenticated retry
using its independent Digest implementation. The expected exchange ends in
200 / ACK / BYE. At upstream revision `03f191d`, rsipstack instead returns
`SipMessageError(ParseError("invalid Algorithm: SHA-256"))`. Its algorithm
parser recognizes `SHA256`, whereas the standardized token has a hyphen.
See [RFC 8760](https://www.rfc-editor.org/rfc/rfc8760.html).

The failing tests retain the interoperable expectation; they do not assert
that the bug is correct. `all` and `sipp` include them and return nonzero on
this revision. `regression` explicitly excludes tests named `known_gap_`,
reports the excluded count, and is used by the normal CI job. `known-gaps`
runs only these probes. Once fixed, move the tests into the regression set
by removing `known_gap_` from their names and update this document.

The harness commit does not modify the digest parser or other library code.

## Known gap: remote Session-ID UUID lost before BYE

Reproduce with `bash scripts/interop/run.sh sipp known_gap_session_id`.
The INVITE advertises a local UUID with a nil remote UUID; SIPp's 200 supplies
its own UUID and echoes the caller's. ACK correctly contains both UUIDs,
but the subsequent BYE resets the remote UUID to nil on upstream `03f191d`.
SIPp's header assertion fails. The expected BYE retains the UUID learned from
the peer; see [RFC 7989 sections 6 and 8](https://www.rfc-editor.org/rfc/rfc7989.html#section-6).
Both UDP and TCP probes remain failing until a separate library fix is made.

## Known gaps: incomplete PRACK reliability and validation

Use `bash scripts/interop/run.sh known-gaps prack`. Eight probes fail at
upstream `03f191d`, reproducing the following on both UDP and TCP:

- `prack_rseq_gap`: after acknowledging RSeq 1, the peer sends RSeq 3 before
  RSeq 2. rsipstack sends `RAck: 3 1 INVITE`; RFC 3262 section 4 requires
  leaving the out-of-order response unacknowledged until the sequence is
  contiguous. SIPp expects the next PRACK to acknowledge RSeq 2.
- `prack_uas_wrong_rseq` and `prack_uas_wrong_cseq`: rsipstack sends a reliable
  183 with `RSeq: 1`, but answers PRACK with `RAck: 999 1 INVITE` or
  `RAck: 1 999 INVITE` with 200. A PRACK that does not match the outstanding
  reliable response should receive 481 (RFC 3262 section 3). These cases
  recover with a valid PRACK after the expected rejection.
- `prack_uas_retransmit`: rsipstack's public `ringing()` API sends one 183
  carrying Require: 100rel and RSeq: 1. With no PRACK, SIPp receives no repeat
  within three seconds (the default T1 is 500 ms). RFC 3262 section 3 requires
  retransmission even over reliable transports. This exposes that the API
  does not itself manage the UAS reliable-provisional timer.

These tests distinguish parsing/accepting a PRACK from implementing the full
100rel state machine. A passing basic PRACK exchange is not evidence that
the remaining reliability, validation or offer/answer behavior is complete.

## Known gaps: blocked ACK and lost 487 after CANCEL

`bash scripts/interop/run.sh known-gaps faults` exercises three failures on
upstream `03f191d` through the public dialog API:

- `remote_bye_during_blocked_ack`: a valid BYE arrives after 200 while the UDP
  ACK send is blocked. The peer expects 200 but receives 481. The required
  lifecycle events are one Confirmed followed by one Terminated, with no
  resurrection when ACK completes.
- `local_bye_waits_for_blocked_ack`: the dialog should already be confirmed
  on receiving 200, and a local BYE must wait for ACK send completion. The
  baseline still exposes Calling at the blocked-ACK checkpoint.
- `drop_outgoing_invite_487`: PJSUA cancels an incoming call and the fixture
  drops rsipstack's first 487. No replacement 487 arrives during the 15-second
  observation window, so PJSUA never sends ACK. In the current public-handler
  integration, `dialog.handle()` returns after CANCEL and the transaction is
  dropped; its timer can no longer drive retransmission. This records a gap
  at that API/integration boundary, without adding a workaround to the fixture.

The blocked-ACK probes deliberately exercise a peer that sends BYE immediately
after its 200. This is an adversarial timing case, not a claim that a normal
callee should initiate BYE before receiving ACK. The caller must still handle
the established dialog consistently. The companion wrong-tag case expects 481
and checks that the valid call survives. See [RFC 3261 sections 12 and 15](https://www.rfc-editor.org/rfc/rfc3261.html#section-15).

The crossed-BYE scenario holds both datagrams before crossing them. It checks
200 if the receiving dialog is still live, or 481 if local termination already
removed it, then verifies a single terminal event and an empty registry. This
covers both registry lifetimes permitted by the tested API without silently
accepting other response codes.

## Executed matrix

There are 161 external-peer test executions:
146 regression cases and 15 known-gap probes. The lost-PRACK-response and all
fault-injection cases are UDP-only; the other families run on both transports.

| Area | Exchanges / assertions | Executions |
| --- | --- | ---: |
| PJSIP calls | rsipstack as caller/callee; local/remote BYE, CANCEL, 486 | 16 |
| PJSIP session changes | hold/resume and UPDATE initiated by either peer; failed re-INVITE followed by a valid one | 20 |
| PJSIP in-dialog methods | INFO in both directions, MESSAGE delivery, OPTIONS rejection without losing the call | 16 |
| SIPp final responses | 403, 404, 408, 480, 488, 500, 503, 603; ACK and cleanup | 16 |
| SIPp authentication | 401, 407, stale nonce; no credentials for 401/407 | 10 |
| Reliable provisional responses | UAC PRACK RAck, duplicate 183, successive RSeq; UDP retry; UAS valid/missing RAck | 11 |
| Call progress | 100, 180, SDP in 183, final 200 | 2 |
| In-dialog methods | OPTIONS, INFO with DTMF body, MESSAGE with text | 2 |
| Session modification | hold/resume re-INVITEs, 488 rejection, UPDATE | 6 |
| Termination | CANCEL/487, crossed CANCEL/200, BYE/481 | 6 |
| Dialog identity | wrong local/remote tags then valid BYE | 2 |
| Repeated / forked answers | repeated 200 re-ACK, second answered branch ACK/BYE | 4 |
| Routing | loose Record-Route on ACK/BYE; UPDATE Contact refresh | 4 |
| Registration | MD5, granted expiry, refresh/unregister, Service-Route, 423 | 6 |
| Existing subscription | refresh, incoming presence NOTIFY, application reply, unsubscribe | 2 |
| UDP fault injection with PJSIP | loss in both directions of INVITE, 200, ACK, BYE, CANCEL and their replies; ACK/BYE delays | 19 |
| UDP races with SIPp | delayed ACK delivery, wrong-tag BYE during blocked ACK, CANCEL crossing held 200, crossed BYEs | 4 |
| Known-gap probes | SHA-256; Session-ID; PRACK; blocked ACK/BYE ordering; lost 487 after CANCEL | 15 |

The 36 PJSUA mid-dialog cases run for both initial caller roles and both
transports. They correlate responses and ACKs with the new request (rather
than accepting the initial INVITE's response), check dialog tags, CSeq progress,
SDP directions and cleanup. INFO/MESSAGE checks also inspect PJSUA's application
output. For incoming modifications, the fixture acts as the application and
explicitly answers the emitted event.

The pinned PJSUA returns 500 for in-dialog OPTIONS (unhandled by its dialog
usages) and 500 for the unsupported-codec re-INVITE (SDP negotiation failure).
Those cases explicitly check rsipstack's handling of rejection; they do not
claim successful OPTIONS negotiation. The failed re-INVITE must receive ACK,
then a valid re-INVITE must succeed before BYE. SIPp separately tests OPTIONS
200 and re-INVITE 488.

PRACK tests include UAC and UAS exchanges with an SDP offer in INVITE. The
sequential case checks RAck values `1 1 INVITE` and `2 1 INVITE`. The UDP loss
case drops the first PRACK response and verifies that the repeated PRACK has
the same Via branch and CSeq. The UAS missing-RAck case expects 400, then sends
a valid PRACK to acknowledge the provisional before accepting the call.
See [RFC 3262 sections 3 and 4](https://www.rfc-editor.org/rfc/rfc3262.html#section-3).

The subscription fixture starts with an existing dialog's tags. It checks the
public subscription API and incoming NOTIFY dispatch; it does not claim to
test initial SUBSCRIBE establishment or the final terminated NOTIFY exchange.
The route test uses a single local SIPp endpoint as the next hop; it checks
the learned Route headers, not a multi-proxy deployment.

## Remaining coverage

These are explicit gaps in this harness, not claims that rsipstack lacks the
features. No finite suite covers every SIP message sequence or peer behavior.

| Area | Not yet exercised with an external peer |
| --- | --- |
| Transports | TLS/WSS certificates, WS, IPv6, DNS SRV/NAPTR, reconnects and NAT |
| PRACK | Offer in PRACK, offerless INVITE, malformed/overflow RSeq, full timer exhaustion |
| Dialog races | overlapping re-INVITEs/glare, additional forking and cancellation schedules |
| Transactions | multi-packet loss bursts, long timer exhaustion, crash/restart recovery |
| Authentication | multiple challenges, auth-int, sess algorithms, SHA-512/256, rejected credentials |
| Routing | strict routes, several proxies, redirects, Path/Outbound flows |
| Event packages | initial SUBSCRIBE/NOTIFY races, terminal NOTIFY, PUBLISH, REFER/Replaces |
| Session extensions | session timers, full Session-ID transfer/conference flows |
| Media and scale | RTP/SRTP, codecs, ICE, DTMF media events, concurrency and soak/load tests |

Add focused XML scenarios and public-API assertions for these areas as the
harness grows; retain unexpected failures as reproducible tests and document
their status instead of changing the expected protocol to fit the library.

## Reference suites and next priorities

These projects provide useful examples of test structure and scenario selection;
our harness does not run their full suites or claim their coverage.

- [PJSIP's PJSUA suite](https://github.com/pjsip/pjproject/tree/master/tests/pjsua)
  combines process-driven calls with [SIPp scenarios](https://github.com/pjsip/pjproject/tree/master/tests/pjsua/scripts-sipp).
  Examples include early BYE, CANCEL without a final INVITE response, forked 200,
  re-INVITE glare, PRACK with SDP and subscription failure/recovery. Its local
  pinned source is available under `target/interop/pjproject-<revision>/tests/pjsua`
  after building the peer.
- [Asterisk Test Suite](https://docs.asterisk.org/Test-Suite-Documentation/)
  orchestrates Asterisk instances and external protocol tools. Its
  [PJSIP tests](https://github.com/asterisk/testsuite/tree/master/tests/channels/pjsip)
  include early/pending re-INVITEs, 100rel, session timers, transports,
  registration, subscriptions and transfers. These are application tests,
  so adapting their scenario ideas requires rsipstack-specific API checks.
- [Sofia-SIP tests](https://github.com/freeswitch/sofia-sip/tree/master/tests)
  separate calls, cancellation, hold, offer/answer, NAT and session timers.
  [test_100rel.c](https://github.com/freeswitch/sofia-sip/blob/master/tests/test_100rel.c)
  also exercises PRACK authentication/failure, cancellation during reliable
  provisional handling and UPDATE interactions.
- [Kamailio tests](https://github.com/kamailio/kamailio-tests)
  use containerized units driven by `ktestsctl`, with SIPp, sipsak and sipexer
  available. This is a useful pattern for future multi-process proxy/routing
  tests, beyond the current two-peer loopback setup.

Priorities beyond the executed matrix above:

1. Extend the existing UDP fault schedules to loss bursts, re-INVITE glare
   and forking. Add a separate stream disconnect/reconnect fixture for TCP/TLS.
2. PRACK offer/answer, authentication and timeout exhaustion; session timer
   negotiation, 422 retry, refresh failure and cleanup.
3. Initial SUBSCRIBE and final NOTIFY, REFER/NOTIFY transfers, redirect chains,
   DNS failover and transport reconnection.
4. Separate longer stress/soak and parser fuzzing jobs, with explicit resource
   limits and reproducible seeds. These are not enabled by the current runner.
