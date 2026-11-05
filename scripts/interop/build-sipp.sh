#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CACHE="$ROOT/target/interop"
REV=c44a9fe5a5896665b2c6a19bfd6190e10a9144e2 # SIPp 3.8.0
PUGI=c8033ce9d039e7f9d134877c363397b3cfe20816 # submodule at this revision
SOURCE="$CACHE/sipp-$REV"
mkdir -p "$CACHE"
if [[ -x "$CACHE/sipp" && -f "$CACHE/sipp-build-id" ]] && \
   [[ $(cat "$CACHE/sipp-build-id") == "$REV-v1" ]]; then
    echo "$CACHE/sipp"
    exit 0
fi
fetch() {
    local archive="$CACHE/$1.tar.gz" url=$2 checksum=$3
    if [[ ! -f "$archive" ]]; then
        curl --fail --location --retry 3 "$url" -o "$archive"
    fi
    python3 - "$archive" "$checksum" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
if hashlib.sha256(path.read_bytes()).hexdigest() != sys.argv[2]:
    sys.exit(f"Checksum mismatch: {path}. Remove this archive and retry.")
PY
}
fetch sipp "https://codeload.github.com/SIPp/sipp/tar.gz/$REV" \
    ac13a3a285fc92eaca56820d89e4d90830a6aa78ebb8590bcd20b7e9b80351d7
fetch pugixml "https://codeload.github.com/zeux/pugixml/tar.gz/$PUGI" \
    4ae8941bc2c19e176c13153e5f53cefa8498aacab0063823b1efdebc719797d9
if [[ ! -d "$SOURCE" ]]; then tar -xzf "$CACHE/sipp.tar.gz" -C "$CACHE"; fi
if [[ ! -f "$SOURCE/third_party/pugixml/CMakeLists.txt" ]]; then
    tar -xzf "$CACHE/pugixml.tar.gz" -C "$SOURCE/third_party/pugixml" --strip-components=1
fi
if ! pkg-config --exists openssl && command -v brew >/dev/null 2>&1; then
    OPENSSL_PREFIX=$(brew --prefix openssl@3)
    export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi
echo "Building SIPp 3.8.0 ($REV); log: $CACHE/sipp-build.log"
(
    cmake -S "$SOURCE" -B "$SOURCE/build" -DCMAKE_BUILD_TYPE=Release \
        -DUSE_SYSTEM_PUGIXML=OFF -DUSE_LUA=OFF -DUSE_PCAP=OFF -DUSE_SCTP=OFF -DUSE_GSL=OFF
    # Commit archives have no .git directory from which SIPp can derive VERSION.
    python3 - "$SOURCE" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1])
template = (source / "include/version.h.in").read_text()
(source / "build/version.h").write_text(template.replace("@VERSION@", "v3.8.0-c44a9fe"))
PY
    cmake --build "$SOURCE/build" --target sipp --parallel "${JOBS:-4}"
) > "$CACHE/sipp-build.log" 2>&1 || {
    tail -n 60 "$CACHE/sipp-build.log"
    exit 1
}
ln -sfn "$SOURCE/build/sipp" "$CACHE/sipp"
printf '%s\n' "$REV-v1" > "$CACHE/sipp-build-id"
echo "$CACHE/sipp"
