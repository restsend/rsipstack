# Long-running session timer interoperability

This suite is explicitly separate from PR checks. `all`, `regression`, `sipp`
and the default runner exclude it. Normal `cargo test` leaves it ignored.
Use `run-soak.sh` or `run.sh soak` deliberately; the GitHub workflow is manual.

```sh
# From the repository root; first run builds the pinned SIPp if needed.
bash scripts/interop/run-soak.sh update
bash scripts/interop/run-soak.sh reinvite

# Smaller validation run, still using real protocol intervals (~3-6 minutes).
RSIPSTACK_SOAK_ROUNDS=2 RSIPSTACK_SOAK_CALLS=4 RSIPSTACK_SOAK_REFRESHES=2 \
  bash scripts/interop/run-soak.sh update

# Longer run with more simultaneous calls and repeated refreshes.
RSIPSTACK_SOAK_ROUNDS=10 RSIPSTACK_SOAK_CALLS=32 RSIPSTACK_SOAK_REFRESHES=10 \
  bash scripts/interop/run-soak.sh reinvite
```

The current suite uses UDP and one independent SIPp process serving concurrent
rsipstack UAC dialogs. Every dialog negotiates Session-Expires 90, refresher=uac.
The stack initiates automatic UPDATE or offered re-INVITE at the real half
interval (45 seconds). There is no accelerated clock or shortened SIP timer.
Each round drops one refresh's 200 response at the UDP boundary and requires a
matching successful retransmission. Other calls must continue concurrently.
The re-INVITE variant also checks an ACK for every successful refresh.

After every dialog has completed the configured number of distinct successful
refreshes, the runner hangs up all calls concurrently. It requires:

- Empty dialog registry and stopped session timer workers.
- No outstanding transactions, cached final responses or waiting ACK routes
  after their natural absorption/cleanup windows (up to 75 seconds).
- Successful SIPp completion and no background handler/transport errors.
- Released endpoint/layer weak references and runtime task count back to its
  pre-round baseline after fixture shutdown.
- Test-process RSS growth within the configured limit after the first round.

Each round uses a fresh fixture so in-memory trace/state collectors cannot grow
across rounds. The full SIP, state and fault traces remain on disk. RSS is sampled
with `ps` on Linux/macOS after teardown; it includes the test binary and allocator,
not the external SIPp process. The first round warms caches/allocator arenas.
RSS growth is a regression signal, not proof of absence of leaks: allocators can
retain freed memory, and a small leak may require a longer run or heap profiler.
Task counts cover this test's Tokio runtime, not arbitrary OS threads.

| Environment variable | Default | Accepted range |
| --- | --- | --- |
| `RSIPSTACK_SOAK_ROUNDS` | 3 | 2–1000 |
| `RSIPSTACK_SOAK_CALLS` | 8 | 2–256 |
| `RSIPSTACK_SOAK_REFRESHES` | 3 | 2–100 |
| `RSIPSTACK_SOAK_RSS_GROWTH_MIB` | 64 | 1–8192 |

The default takes approximately 7–11 minutes per variant. Duration grows mainly
with rounds and refreshes, not with the number of simultaneous calls. Every
phase is bounded; a stalled call or cleanup fails with diagnostics. Peer
startup and call establishment retain the regular harness timeout, so very
large concurrency on a slow machine can fail that bound rather than hang.

`target/interop/results/<run>/<test>/` contains `config.txt`, `soak.csv` (one
quiescent sample per completed round), `round-NNNN/` traces and PASS files.
The parent PASS appears only after every round passed. Ordinary runner metadata
records the checkout and toolchain. The manual **Session timer soak** workflow
uploads these artifacts even on failure; it has a three-hour job limit.

This does not test RTP, application persistence/billing, production routing,
TCP/TLS load, a permanently unreachable peer under load, or all network loss
patterns. Short library regressions separately cover refresh failure/expiry;
short SIPp cases cover UAC and UAS over UDP/TCP. See [SESSION_TIMERS.md](SESSION_TIMERS.md).
