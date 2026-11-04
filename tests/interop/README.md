# SIP interoperability tests

Run the current rsipstack checkout against independent PJSUA (PJSIP) and SIPp
processes on loopback. No SIP server, account, audio device or Docker is needed.
The Rust driver exercises the public dialog API and checks both SIP messages
and dialog state events.

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
bash scripts/interop/run.sh regression                # supported baseline (123 tests)
bash scripts/interop/run.sh all                       # all 135; includes 12 known-gap probes
bash scripts/interop/run.sh pjsip                     # 52 PJSUA tests
bash scripts/interop/run.sh pjsip mid_dialog          # 36 mid-dialog PJSUA cases
bash scripts/interop/run.sh sipp                      # 83 SIPp tests, including known gaps
bash scripts/interop/run.sh sipp prack                # all 19 PRACK cases, including known gaps
bash scripts/interop/run.sh regression prack          # 11 passing PRACK regression cases
bash scripts/interop/run.sh known-gaps                # reproduce documented failures
bash scripts/interop/run.sh pjsip udp_uac_peer_bye     # one test
bash scripts/interop/run.sh sipp wrong_tag_bye         # UDP and TCP
```

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

## Coverage and expectations

See [COVERAGE.md](COVERAGE.md) for the complete matrix, reproducible known gaps,
and the features this suite does not exercise. The default (`all`) and `sipp`
include known-gap probes and currently **return nonzero**. `regression`
explicitly reports and excludes them; it does not change their assertions.
The documented counts describe the baseline commit; results can differ when
run against another revision or with uncommitted application changes.

PJSUA checks calls in both directions, hold/resume and UPDATE initiated by
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

SIPp's repeated-200 and lost-PRACK-response cases use `-nr` so its UDP duplicate
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
- `<test>/background-errors.log`: endpoint, dialog handler and trace-writing errors.
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
