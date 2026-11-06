#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
usage() {
    echo "Usage: bash scripts/interop/run.sh [all|regression|pjsip|sipp|proxy|b2bua|faults|known-gaps] [test-name-filter]"
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if [[ $# -gt 2 ]]; then usage >&2; exit 2; fi
SUITE=${1:-all}
case "$SUITE" in
    all|regression|known-gaps|faults) PREFIX=interop:: ;;
    pjsip|sipp|proxy|b2bua) PREFIX="interop::$SUITE::" ;;
    *) usage >&2; exit 2 ;;
esac
FILTER=${2:-}
export RSIPSTACK_INTEROP_LOG_DIR=${RSIPSTACK_INTEROP_LOG_DIR:-"$ROOT/target/interop/results/$(date -u +%Y%m%dT%H%M%SZ)-$$"}
mkdir -p "$RSIPSTACK_INTEROP_LOG_DIR"
RSIPSTACK_INTEROP_LOG_DIR=$(cd "$RSIPSTACK_INTEROP_LOG_DIR" && pwd)
echo "Interop logs: $RSIPSTACK_INTEROP_LOG_DIR"
# Fail on misspelled filters instead of reporting success for zero tests.
cargo test --test interop_tests -- "$PREFIX" --ignored --list \
    > "$RSIPSTACK_INTEROP_LOG_DIR/test-list.txt"
python3 - "$RSIPSTACK_INTEROP_LOG_DIR/test-list.txt" "$FILTER" "$SUITE" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
names = [line.removesuffix(": test") for line in path.read_text().splitlines()
         if line.endswith(": test") and sys.argv[2] in line.removesuffix(": test")]
if sys.argv[3] == "faults":
    names = [name for name in names if "::faults::" in name]
gaps = [name for name in names if "known_gap_" in name]
if sys.argv[3] == "regression":
    names = [name for name in names if name not in gaps]
    print(f"Regression suite excludes {len(gaps)} documented known-gap probes; use 'all' to include them.")
elif sys.argv[3] == "known-gaps":
    names = gaps
elif gaps:
    print(f"Including {len(gaps)} documented known-gap probes: failures are currently expected (see COVERAGE.md).")
if not names:
    sys.exit("No interoperability tests match this filter.")
if os.environ.get("RSIPSTACK_FAULT_PLAN") and (len(names) != 1 or "::faults::" not in names[0]):
    sys.exit("RSIPSTACK_FAULT_PLAN requires exactly one fault scenario; supply its full test-name filter.")
path.with_name("test-names.txt").write_text("\n".join(names) + "\n")
PY
TESTS=()
while IFS= read -r name; do TESTS+=("$name"); done < "$RSIPSTACK_INTEROP_LOG_DIR/test-names.txt"
if python3 -c 'import pathlib,sys; sys.exit(not any(any(p in n for p in ("::pjsip::", "::proxy::", "::b2bua::")) for n in pathlib.Path(sys.argv[1]).read_text().splitlines()))' "$RSIPSTACK_INTEROP_LOG_DIR/test-names.txt"; then
    if [[ -z ${PJSUA_BIN:-} ]]; then
        bash scripts/interop/build-pjsua.sh
        export PJSUA_BIN="$ROOT/target/interop/pjsua"
    fi
    [[ -x "$PJSUA_BIN" ]] || { echo "PJSUA_BIN is not executable: $PJSUA_BIN" >&2; exit 1; }
    export PJSUA_BIN=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$PJSUA_BIN")
fi
for APP in proxy b2bua; do
    if python3 -c 'import pathlib,sys; sys.exit(not any("::"+sys.argv[2]+"::" in n for n in pathlib.Path(sys.argv[1]).read_text().splitlines()))' "$RSIPSTACK_INTEROP_LOG_DIR/test-names.txt" "$APP"; then
        cargo build --example "interop_$APP"
    fi
done
if python3 -c 'import pathlib,sys; sys.exit(not any("::sipp::" in n or "_sipp_" in n for n in pathlib.Path(sys.argv[1]).read_text().splitlines()))' "$RSIPSTACK_INTEROP_LOG_DIR/test-names.txt"; then
    if [[ -z ${SIPP_BIN:-} ]]; then
        bash scripts/interop/build-sipp.sh
        export SIPP_BIN="$ROOT/target/interop/sipp"
    fi
    [[ -x "$SIPP_BIN" ]] || { echo "SIPP_BIN is not executable: $SIPP_BIN" >&2; exit 1; }
    export SIPP_BIN=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$SIPP_BIN")
fi
{
    git rev-parse HEAD
    git status --short
    rustc --version
    printf 'suite=%s\nfilter=%s\nPJSUA_BIN=%s\nSIPP_BIN=%s\n' "$SUITE" "$FILTER" "${PJSUA_BIN:-unused}" "${SIPP_BIN:-unused}"
} > "$RSIPSTACK_INTEROP_LOG_DIR/environment.txt"
# Each ignored test launches a real peer; missing dependencies are failures.
cargo test --test interop_tests -- --exact "${TESTS[@]}" --ignored --nocapture --test-threads=1 \
    2>&1 | tee "$RSIPSTACK_INTEROP_LOG_DIR/results.txt"
