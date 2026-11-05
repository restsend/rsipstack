# Coverage and known interoperability gaps

This harness is a growing collection of real-process interoperability tests,
not a certification of complete SIP conformance. A passing case covers only
the exchange and assertions stated for that case.
This matrix describes the current PR stack on upstream `895d443` (0.8.1).

## Established-dialog re-INVITE bridge

`pjsip bridge` adds four UDP/TCP cases with two PJSUA processes: hold and resume
from either dialog leg, independent dialog identifiers and CSeq, SDP relay,
ACK on both legs, and teardown. `sipp bridge` adds four UDP/TCP offerless cases
plus one UDP ACK-loss case. SIPp supplies an offer in 200, waits for an explicit
driver handshake before returning the answer in ACK, and checks the answer
again after repeating the 200. The loss case drops the first SDP ACK at the
UDP socket boundary and requires a retransmitted ACK with identical contents.

Library wire tests additionally cover 488, CANCEL and late 200, simultaneous
re-INVITEs, missing ACK and rejecting answers with multiple media streams.
They complement the external cases; raw UDP tests are not independent stack
implementations. Initial-call bridging, reliable provisional offer/answer,
session timers and media negotiation remain separate responsibilities.

## Known gap: standard SHA-256 digest challenge

Reproduce with `bash scripts/interop/run.sh known-gaps` (both UDP and TCP),
or select just this issue with `bash scripts/interop/run.sh sipp known_gap_auth_sha256`.

SIPp sends a 401 with `algorithm=SHA-256` and verifies the authenticated retry
using its independent Digest implementation. The expected exchange ends in
200 / ACK / BYE. At upstream revision `004f607`, rsipstack instead returns
`SipMessageError(ParseError("invalid Algorithm: SHA-256"))`. Its algorithm
parser recognizes `SHA256`, whereas the standardized token has a hyphen.
See [RFC 8760](https://www.rfc-editor.org/rfc/rfc8760.html).

The failing tests retain the interoperable expectation; they do not assert
that the bug is correct. `all` and `sipp` include them and return nonzero on
this revision. `regression` explicitly excludes tests named `known_gap_`,
reports the excluded count, and is used by the normal CI job. `known-gaps`
runs only these probes. Once fixed, move the tests into the regression set
by removing `known_gap_` from their names and update this document.

The digest parser is unchanged by these tests.

## Resolved: remote Session-ID UUID lost before BYE

Run with `bash scripts/interop/run.sh regression session_id`.
The INVITE advertises a local UUID with a nil remote UUID; SIPp's 200 supplies
its own UUID and echoes the caller's. ACK correctly contains both UUIDs,
but the subsequent BYE resets the remote UUID to nil on upstream `03f191d`.
SIPp's header assertion fails. The expected BYE retains the UUID learned from
the peer; see [RFC 7989 sections 6 and 8](https://www.rfc-editor.org/rfc/rfc7989.html#section-6).
Both UDP and TCP cases pass on upstream `004f607` and are now part of regression.
Their assertions are unchanged; only the `known_gap_` classification was removed.

## PRACK / 100rel regression coverage

Use `bash scripts/interop/run.sh regression prack`. All 27 executions use
`ReliableProvisionalConfig` with an application media handler. Eight former
known-gap probes are now ordinary regression cases on UDP and TCP:

- `prack_rseq_gap`: RSeq 3 after RSeq 1 is discarded; the next PRACK
  acknowledges the contiguous RSeq 2.
- `prack_uas_wrong_rseq` and `prack_uas_wrong_cseq`: unmatched RAck receives
  481, then a valid PRACK acknowledges the outstanding provisional. SIPp
  extracts the stack-generated random RSeq from the response.
- `prack_uas_retransmit`: the UAS retransmits its reliable 183 on both
  transports until PRACK arrives. SIPp's automatic UDP duplicate handling
  is disabled so the scenario itself observes the repeated 183.

Additional cases cover an offerless INVITE with the answer in PRACK, a new
SDP offer in PRACK with its answer in 200, and PRACK 401/407 authentication.
The retry must retain RAck and SDP, advance CSeq and change the Via branch.
SIPp verifies the 401 digest; the independent Python verifier checks 407
because SIPp's `verifyauth` only reads Authorization. The tests inspect the
media callback and final PRACK response as well as the wire exchange.

Library tests additionally cover all three SDP patterns in both roles,
fork-specific routes and targets, malformed/overflow sequence values,
queued provisionals and finals, CANCEL followed by late PRACK, callback
failures, and deterministic 64*T1 exhaustion without a T2 retransmission cap.
External cases are signaling tests and send no RTP.

## Resolved: blocked ACK

`bash scripts/interop/run.sh regression blocked_ack` exercises three cases,
including wrong-tag rejection. The two former failures on upstream `03f191d`
now pass on `004f607` after [PR #235](https://github.com/restsend/rsipstack/pull/235):

- `remote_bye_during_blocked_ack`: a valid BYE arrives after 200 while the UDP
  ACK send is blocked. The old baseline replied 481 instead of 200. The required
  lifecycle events are one Confirmed followed by one Terminated, with no
  resurrection when ACK completes.
- `local_bye_waits_for_blocked_ack`: the dialog should already be confirmed
  on receiving 200, and a local BYE must wait for ACK send completion. The
  old baseline exposed Calling at the blocked-ACK checkpoint.

Both former known-gap cases now run in the normal regression suite with their
original assertions, alongside the wrong-tag case.

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

The short suite has 208 external-peer test executions (plus two optional soak variants):
206 regression cases and 2 known-gap probes. The lost-PRACK-response,
application lost-BYE-response and all fault-injection cases are UDP-only;
the other families run on both transports.

| Area | Exchanges / assertions | Executions |
| --- | --- | ---: |
| PJSIP calls | rsipstack as caller/callee; local/remote BYE, CANCEL, 486 | 16 |
| PJSIP session changes | hold/resume and UPDATE initiated by either peer; failed re-INVITE followed by a valid one | 20 |
| PJSIP in-dialog methods | INFO in both directions, MESSAGE delivery, OPTIONS rejection without losing the call | 16 |
| SIPp final responses | 403, 404, 408, 480, 488, 500, 503, 603; ACK and cleanup | 16 |
| SIPp authentication | 401, 407, stale nonce; no credentials for 401/407 | 10 |
| Reliable provisional responses | UAC/UAS validation, retransmission, contiguous RSeq, offer/answer in PRACK, 401/407 | 27 |
| Call progress | 100, 180, SDP in 183, final 200 | 2 |
| In-dialog methods | OPTIONS, INFO with DTMF body, MESSAGE with text | 2 |
| RFC 4028 | UAC/UAS negotiation, 422, UPDATE/re-INVITE refresh and teardown over UDP/TCP | 8 |
| Session modification | hold/resume re-INVITEs, 488 rejection, UPDATE | 6 |
| Termination | CANCEL/487, crossed CANCEL/200, BYE/481 | 6 |
| Dialog identity | wrong local/remote tags then valid BYE | 2 |
| Session-ID | retain the local/remote UUID pair through ACK and BYE | 2 |
| Repeated / forked answers | repeated 200 re-ACK, second answered branch ACK/BYE | 4 |
| Routing | loose Record-Route on ACK/BYE; UPDATE Contact refresh | 4 |
| Registration | MD5, granted expiry, refresh/unregister, Service-Route, 423 | 6 |
| Existing subscription | refresh, incoming presence NOTIFY, application reply, unsubscribe | 2 |
| UDP fault injection with PJSIP | loss in both directions of INVITE, 200, ACK, BYE, CANCEL and their replies; ACK/BYE delays | 20 |
| UDP races with SIPp | delayed ACK delivery, valid/wrong-tag BYE during blocked ACK, local BYE waiting for ACK, CANCEL crossing held 200, crossed BYEs | 6 |
| Standalone proxy | two PJSUA peers; caller/callee BYE, 486, CANCEL; SIPp late 200 and lost BYE response; preserved dialog identity and Via/Record-Route forwarding | 11 |
| Standalone B2BUA | two independent dialogs; caller/callee BYE, 486, CANCEL; SIPp late 200 and lost BYE response; independent identifiers and both-leg cleanup | 11 |
| Re-INVITE bridge | two PJSUA peers for hold/resume, two SIPp peers for offerless SDP, lost answer ACK | 9 |
| Known-gap probes | SHA-256 | 2 |

The lost-487 case is a regression test. An earlier fixture dropped the server
INVITE transaction when `dialog.handle()` returned after CANCEL, cancelling
its retransmission timer. Retaining and driving that transaction through
termination restores the retry and ACK without a library change. This was a
fixture lifetime issue, not evidence of a PJSIP retransmission defect.

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
The direct route test uses a single local SIPp endpoint as the next hop; it
checks learned Route headers. The standalone proxy cases add one real proxy
process between two independent peers, but do not cover a multi-proxy chain.
See [the application contract and limitations](README.md#standalone-proxy-and-b2bua).

## Remaining coverage

These are explicit gaps in this harness, not claims that rsipstack lacks the
features. No finite suite covers every SIP message sequence or peer behavior.

| Area | Not yet exercised with an external peer |
| --- | --- |
| Transports | TLS/WSS certificates, WS, IPv6, DNS SRV/NAPTR, reconnects and NAT |
| PRACK | External peer malformed/overflow RSeq and full timer exhaustion; PJSIP media negotiation |
| Dialog races | overlapping re-INVITEs/glare, additional forking and cancellation schedules |
| Transactions | multi-packet loss bursts, long timer exhaustion, crash/restart recovery |
| Authentication | multiple challenges, auth-int, sess algorithms, SHA-512/256, rejected credentials |
| Routing | strict routes, several proxies, redirects, Path/Outbound flows |
| Standalone applications | proxy-specific 2xx retransmission policy, forking, session modification, PRACK, authentication, disconnect recovery and media relay |
| Event packages | initial SUBSCRIBE/NOTIFY races, terminal NOTIFY, PUBLISH, REFER/Replaces |
| Session extensions | proxy timer policy, timer persistence, full Session-ID transfer/conference flows |
| Media and scale | RTP/SRTP, codecs, ICE, DTMF media events, TCP/TLS load and production scale |

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
2. External-peer PRACK timeout exhaustion; session timer
   negotiation, 422 retry, refresh failure and cleanup.
3. Initial SUBSCRIBE and final NOTIFY, REFER/NOTIFY transfers, redirect chains,
   DNS failover and transport reconnection.
4. Separate longer stress/soak and parser fuzzing jobs, with explicit resource
   limits and reproducible seeds. These are not enabled by the current runner.

## Session timers

Eight SIPp cases exercise RFC 4028 UAC/UAS with UPDATE and re-INVITE over
UDP/TCP. They verify 422 retry identity, negotiated intervals and refresher
changes, ACK, BYE and timer/registry cleanup. See [SESSION_TIMERS.md](SESSION_TIMERS.md)
for the API, virtual-clock library regressions and remaining integration limits.

## Optional soak variants

Two separately selected UDP variants run parallel calls and repeated automatic
UPDATE/re-INVITE refreshes against SIPp with one lost response per round. They
check registry/transaction cleanup, endpoint/layer release, runtime task counts,
and post-warmup RSS growth. See [SOAK.md](SOAK.md) for bounds, artifacts and limits.
