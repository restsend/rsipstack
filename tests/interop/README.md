# SIP interoperability tests

Run the current rsipstack checkout against independent PJSUA (PJSIP) and SIPp
processes on loopback. No SIP server, account, audio device or Docker is needed.
The Rust driver exercises the public transaction/dialog APIs and checks both
SIP messages and dialog state events. Additional three-process cases run a
standalone rsipstack proxy or B2BUA between independent SIP peers.

## Setup and commands

Install a Rust toolchain and the peer build prerequisites:

```sh
# Ubuntu / Debian
sudo apt-get install build-essential cmake pkg-config libssl-dev libncurses-dev python3 curl

# macOS: Xcode Command Line Tools must also be installed
brew install cmake pkg-config openssl@3 python
```

From the repository root:

```sh
bash scripts/interop/run.sh regression                # supported baseline (206 tests)
bash scripts/interop/run.sh all                       # all 208; includes 2 known-gap probes
bash scripts/interop/run.sh pjsip                     # 76 PJSUA regression tests
bash scripts/interop/run.sh pjsip mid_dialog          # 36 mid-dialog PJSUA cases
bash scripts/interop/run.sh sipp                      # 110 SIPp tests, including known gaps
bash scripts/interop/run.sh proxy                     # 11 standalone proxy cases
bash scripts/interop/run.sh b2bua                     # 11 linked two-dialog B2BUA cases
bash scripts/interop/run.sh sipp prack                # all 27 PRACK cases
bash scripts/interop/run.sh regression prack          # 27 passing PRACK regression cases
bash scripts/interop/run.sh faults                    # 27 UDP loss/delay/race cases
bash scripts/interop/run.sh known-gaps                # reproduce documented failures
bash scripts/interop/run.sh pjsip udp_uac_peer_bye     # one test
bash scripts/interop/run.sh sipp wrong_tag_bye         # UDP and TCP
bash scripts/interop/run.sh pjsip bridge               # two-peer hold/resume bridge
bash scripts/interop/run.sh sipp session_timer         # eight RFC 4028 wire exchanges
bash scripts/interop/run.sh sipp bridge                # offerless bridge and lost SDP ACK
```

The bridge cases use two independent peer processes and two rsipstack dialog
legs joined by the public `ReinviteBridge` component. Four PJSUA cases cover
hold/resume initiated from either leg over UDP/TCP. Five SIPp cases cover
offerless re-INVITEs in both directions, delayed answers supplied in ACK,
identical ACK retransmission, and loss of the first SDP-bearing ACK over UDP.
Each leg has a separate trace directory; both must finish without background
errors or live dialogs. These tests do not assert RTP delivery or PRACK bridging.

The **first explicit harness run** downloads and builds the selected peers in
`target/interop`. Later runs reuse them. Normal `cargo build` and `cargo test`
never download or run PJSIP/SIPp; these integration tests are marked `#[ignore]`.
Nothing is installed globally or linked into rsipstack. Missing peers,
unmatched filters, timeouts, bad responses and unsuccessful child exits fail
the run. Tests execute serially with dynamically selected loopback ports.

To use existing executables and bypass their download/build steps:

```sh
PJSUA_BIN=/absolute/path/to/pjsua SIPP_BIN=/absolute/path/to/sipp \
  bash scripts/interop/run.sh all
```

The binaries must support the flags and CLI used by the pinned versions below.
To prepare peers without running the suite, use `bash scripts/interop/build-pjsua.sh`
and `bash scripts/interop/build-sipp.sh`. Set `JOBS=2` to limit build concurrency.
With Rust dependencies and peers already cached, `CARGO_NET_OFFLINE=true bash
scripts/interop/run.sh all` runs without downloads. This requires an existing
peer cache or explicit binary overrides; Cargo's offline flag does not disable
the peer download scripts.

See [SESSION_TIMERS.md](SESSION_TIMERS.md) for the opt-in timer API, failure
policy, and short regression coverage.

## Coverage and expectations

See [COVERAGE.md](COVERAGE.md) for the complete matrix, reproducible known gaps,
and the features this suite does not exercise. The default (`all`) and `sipp`
include known-gap probes and currently **return nonzero**. `regression`
explicitly reports and excludes them; it does not change their assertions.
The documented counts describe upstream baseline `895d443` plus the re-INVITE bridge; results can differ when
run against another revision or with uncommitted application changes.

PJSUA checks calls in both directions, UDP loss/retransmission, hold/resume and UPDATE initiated by
both peers, DTMF INFO in both directions, MESSAGE delivery, OPTIONS rejection,
and recovery after a failed re-INVITE. SIPp covers final responses, Digest,
PRACK on both sides, retransmission, forking, re-INVITE/UPDATE, in-dialog
methods, routing, registration and an established subscription. Cases assert
wire messages and application-visible results; INVITE cases also check dialog
state events and registry cleanup. The fixture removes terminated dialogs
from the registry, as an application must do. SIPp must exit with code 0.

Most cases use an inactive PCMU SDP. The PJSUA mid-dialog cases start with
sendrecv PCMU and change direction for hold/resume; PJSUA uses null audio and
may send RTP to loopback discard port 9. No test asserts media delivery or
quality. RTP/audio quality, scale and downstream application
behavior (such as CDR/billing) require separate tests.

SIPp's repeated-200, repeated-183, lost-PRACK-response, bridge offerless, and
application lost-BYE-response cases use `-nr` so its UDP duplicate
detector does not consume the repeated request before the explicit XML receive
step. The peer still has to receive the real retransmission from rsipstack.
Handshake messages/log markers coordinate state checks without timed sleeps.

SIPp 3.8.0's `verifyauth` reads Authorization only. The 407 case therefore
checks Proxy-Authorization with a separate Python `hashlib` oracle; 401 and
stale-nonce cases use SIPp's native Digest verifier. No credentials used in
these scenarios belong to an external account.

## Results and troubleshooting

The runner prints a fresh `target/interop/results/<UTC timestamp>-<pid>/` directory:

- `results.txt`, `test-names.txt`, `environment.txt`: test result, selected tests,
  checkout commit/dirty status, Rust version and peer paths.
- `<test>/sip.log`, `states.log`: rsipstack SIP messages and dialog events.
- `<test>/pjsua.log`, `pjsua.stderr.log`: PJSIP's own output.
- `<test>/sipp.messages.log`, `sipp.errors.log`, `sipp.screen.log`,
  `sipp.actions.log`, `sipp.stdout.log`, `sipp.stderr.log`: SIPp traces and counters
  (some files are created only when there is output).
- `<test>/scenario.xml`: rendered SIPp scenario, including fixed test parameters.
- `<test>/fault-plan.tsv`, `fault-events.tsv`, `fault-packets.log`: the fault
  schedule, observed/applied/delivered events and raw UDP datagrams (fault cases).
- `<test>/background-errors.log`: endpoint, dialog handler and trace-writing errors.
- `<test>/caller/`, `callee/`: independent peer logs in three-process cases.
- `<test>/application/sip.frames`: length-framed TX/RX messages from the standalone
  application; `events.log` records calls/dialog states, `summary.txt` checks
  active call and dialog counts plus background errors at shutdown.
- `<test>/PASS`: written only after protocol checks, peer shutdown and dialog
  handlers succeed, with no recorded background errors.

Expected failures return ordinary test errors without unwinding. SIPp failures
include its error-log excerpt and scenario directory. A secondary transport
error during teardown (for example, Broken pipe after SIPp times out) is recorded
in `background-errors.log`; it cannot turn a failed scenario into a pass. Genuine
panics inside the tested library are not suppressed.

`sip.log` records incoming messages at the transport inspector, including ACKs
absorbed by the finished-transaction cache. Outgoing messages use the message
inspector; cached retransmissions can bypass it, so consult peer traces too.
Build failures are in `target/interop/build.log` or `sipp-build.log`. Override
`RSIPSTACK_INTEROP_LOG_DIR` to choose another result directory. The exit status
and final Cargo result determine success, not the mere presence of log files.

The separate GitHub Actions workflow runs `regression` on PRs and main pushes.
Manual dispatch also allows `all` and `known-gaps`. It caches pinned peers and
uploads logs even on failure.
There are no credentials or external SIP services involved.

## Standalone proxy and B2BUA

The runner builds `examples/interop_proxy.rs` or `examples/interop_b2bua.rs`
from the current checkout. Each case starts the application as a separate OS
process. Normal cases use two PJSUA instances; late-answer and packet-loss
cases use a PJSUA caller and a SIPp callee.

Both groups cover UDP/TCP calls, BYE from either peer, 486 rejection, CANCEL,
and a downstream 200 arriving after CANCEL. An additional UDP case withholds
the first BYE response and requires the same transaction to be retransmitted.
SIPp independently checks its Via, CSeq and Call-ID before replying.

The proxy preserves Call-ID, dialog tags, CSeq and Contact, adds/removes its Via,
decrements Max-Forwards and Record-Routes the call. The B2BUA creates two dialog
legs with different Call-IDs and caller tags, maps progress/final responses,
and propagates cancellation/termination. A late 200 after cancellation is
forwarded by the proxy; the B2BUA keeps 487 on the cancelled caller leg and
ACKs/BYEs the answered callee leg. The SIPp callee requires both ACK and BYE,
allowing either arrival order because forwarding and UDP can reorder them.
Assertions check SDP, ACK correlation, dialog identity and final responses.
Each B2BUA leg must emit exactly one terminal event; both registries must be
empty. Shutdown also joins application tasks and reports background failures.
SIP transaction retention timers are cancelled only at process shutdown; these
counts do not claim that every transaction timer has naturally expired.

To run either program manually against a loopback peer:

```sh
cargo run --example interop_proxy -- \
  --listen 127.0.0.1:5062 --transport udp \
  --target 'sip:callee@127.0.0.1:5064;transport=udp' \
  --log-dir target/interop/manual-proxy
```

Use `--example interop_b2bua` for the linked-dialog application. The program
prints `READY`, then accepts calls; type `quit` after the calls finish to check
cleanup and stop. Tests use dynamically chosen ports. `INTEROP_PROXY_BIN` and
`INTEROP_B2BUA_BIN` can select alternative application executables for direct
test invocation; those must implement the same CLI, trace and shutdown contract.

These are deliberately small test applications with one configured next hop,
loopback addresses and offer-in-INVITE SDP passthrough. They do not implement
production proxy/B2BUA policy, authentication, registration, forking, multiple
route hops, media relay, PRACK or session modification. In particular the
proxy uses the current public transaction API, whose server-INVITE layer also
retransmits 2xx until ACK; proxy-specific 2xx retransmission policy is not
validated by these scenarios. TCP disconnect/reconnect behavior and application
crash recovery remain outside this initial matrix.

## Controlled UDP faults and replay

`bash scripts/interop/run.sh faults` selects only the 27 fault scenarios.
All 27 are regression cases in this checkout, including the previously
failing blocked-ACK cases fixed by PR #235. A `known-gaps faults` selection now
matches no tests and fails explicitly rather than reporting a misleading pass.
The six small fault-engine checks also run under normal `cargo test`; they
need loopback sockets but no external peer binaries or downloads.

The fixture wraps the public platform UDP socket interface and still uses a
real loopback UDP socket. It does not change production code, SIP headers,
Contact/Via routing or the library's timers. It sees retransmissions that
bypass the message inspector. TLS/TCP are not covered by this mechanism.

The fixture keeps completed/confirmed server INVITE transactions in their
owning tasks after `dialog.handle()` returns, driving `receive()` until
transaction termination. In particular, CANCEL ends the dialog before the
487 is acknowledged; dropping the transaction at that point would cancel its
retransmission timer. The lost-487 test checks the real timer-driven retry
and PJSUA's ACK, with unchanged SIP timers and no injected replacement response.

Each rule selects a direction (`send`/`receive` relative to rsipstack), CSeq
method, request or exact response status, and a 1-based occurrence. Actions:

- `drop`: discard the selected datagram; a send still completes successfully.
- `delay`: queue delivery for the specified milliseconds; other traffic flows.
- `hold`: queue delivery until the scenario explicitly releases the rule ID;
  a local send completes immediately, as if the datagram were in the network.
- `block_send`: hold both the outgoing datagram and completion of `send_to`;
  receiving and unrelated sends continue. This reproduces a blocked ACK send.

Gate releases are coordinated with observed packets/events, not guessed sleeps.
Rules affect only the selected occurrence, so subsequent retransmissions follow
their own rules or pass normally. The loss scenarios verify that a later retry
arrives with the same transaction/dialog identifiers. `fault-events.tsv` uses
columns: elapsed microseconds, packet ID, direction, phase, rule ID, peer address,
and byte count. The packet ID joins it to `fault-packets.log`; `sip.log` records
what the library saw, which can differ from what the socket delivered.

Every configured rule must fire, all held/delayed packets must be resolved, and
background checks must succeed before PASS is written. A missing rule match is
a failure, not a skipped injection. The plan parser rejects duplicate IDs,
overlapping selectors, invalid actions and delays outside 1..10000 ms.

To replay a saved plan, select exactly the same single scenario:

```sh
RSIPSTACK_FAULT_PLAN="$PWD/target/interop/results/<run>/udp_delay_outgoing_ack/fault-plan.tsv" \
  bash scripts/interop/run.sh faults udp_delay_outgoing_ack
```

The runner rejects a plan override matching multiple tests. The plan preserves
selectors and delay values; the test supplies its gate-release sequence. This
replays the injection schedule with fresh SIP identifiers, not a recording of
OS scheduling or original wall-clock timing. Scenarios and binary revisions
must match for a meaningful comparison.

## Revisions and other branches

The scripts pin full commits and check archive SHA-256 before extracting:

- [PJSIP 2.17](https://github.com/pjsip/pjproject/tree/5a457451fa2712ba18e12b01738e8ff3af2b26fd)
- [SIPp 3.8.0](https://github.com/SIPp/sipp/tree/c44a9fe5a5896665b2c6a19bfd6190e10a9144e2)
- [SIPp's pinned pugixml submodule](https://github.com/zeux/pugixml/tree/c8033ce9d039e7f9d134877c363397b3cfe20816)

These are external test programs with their own upstream licenses. Their
sources and binaries stay under ignored `target/`; the commit contains only
the driver, our scenarios, scripts, documentation and workflow. Updating a
peer requires updating its revision, checksum and build-cache version in the
script, then rerunning the whole suite. If reusing a local cache while changing
pins, remove the corresponding old `.tar.gz` archive before rebuilding.

The runner always builds the checkout containing `scripts/interop/run.sh`.
Running it in a separate worktree does **not** test uncommitted changes in your
main working directory. To test another branch, bring this harness commit onto
that branch (for example, cherry-pick it into a clean temporary worktree) and
run the command there. Binary overrides can reuse peers from the original
checkout. Keep regression fixes in separate commits from this harness.
