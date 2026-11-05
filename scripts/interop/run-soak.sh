#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
case "${1:-update}" in
    update|reinvite) METHOD=${1:-update} ;;
    --help)
        cat <<'HELP'
Usage: bash scripts/interop/run-soak.sh [update|reinvite]
Runs real 90-second sessions with concurrent SIPp calls and response loss.
Defaults: 3 rounds, 8 calls, 3 automatic refreshes per call (about 7-11 minutes).
RSIPSTACK_SOAK_ROUNDS=2..1000
RSIPSTACK_SOAK_CALLS=2..256
RSIPSTACK_SOAK_REFRESHES=2..100
RSIPSTACK_SOAK_RSS_GROWTH_MIB=1..8192 (default 64, after warmup)
Reports and traces are saved under target/interop/results.
HELP
        exit 0 ;;
    *) echo 'Expected update or reinvite; use --help' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo 'Too many arguments' >&2; exit 2; }
exec bash "$ROOT/scripts/interop/run.sh" soak "udp_session_soak_$METHOD"
