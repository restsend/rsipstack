#!/usr/bin/env bash
# Build a separate, pinned PJSUA test peer. Nothing is installed globally.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CACHE="$ROOT/target/interop"
REV=5a457451fa2712ba18e12b01738e8ff3af2b26fd # PJSIP 2.17
SHA256=3b4fe10612949f8c673b2eb80617c3873d8acb8b1411ba7e6d08508d2978085f
SOURCE="$CACHE/pjproject-$REV"
mkdir -p "$CACHE"
if [[ -x "$CACHE/pjsua" && -f "$CACHE/build-id" ]] && \
   [[ $(cat "$CACHE/build-id") == "$REV-v1" ]]; then
    echo "$CACHE/pjsua"
    exit 0
fi
ARCHIVE="$CACHE/pjproject.tar.gz"
if [[ ! -f "$ARCHIVE" ]]; then
    curl --fail --location --retry 3 \
        "https://codeload.github.com/pjsip/pjproject/tar.gz/$REV" -o "$ARCHIVE"
fi
python3 - "$ARCHIVE" "$SHA256" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != sys.argv[2]:
    sys.exit(f"Checksum mismatch: {path}. Remove this archive and retry.")
PY
if [[ ! -d "$SOURCE" ]]; then
    tar -xzf "$ARCHIVE" -C "$CACHE"
fi
echo "Building PJSIP 2.17 ($REV); log: $CACHE/build.log"
(
    cd "$SOURCE"
    ./configure --disable-sound --disable-video --disable-ssl \
        --disable-opus --disable-libyuv --disable-ffmpeg --disable-v4l2 \
        --disable-sdl --disable-libwebrtc --disable-speex-aec
    make dep
    make -j "${JOBS:-4}"
) >"$CACHE/build.log" 2>&1 || {
    tail -n 60 "$CACHE/build.log"
    exit 1
}
BIN=$(find "$SOURCE/pjsip-apps/bin" -maxdepth 1 -type f -name 'pjsua-*' ! -name '*.exe' | head -n 1)
[[ -n "$BIN" && -x "$BIN" ]] || { echo "PJSUA executable not found" >&2; exit 1; }
ln -sfn "$BIN" "$CACHE/pjsua"
printf '%s\n' "$REV-v1" > "$CACHE/build-id"
echo "$CACHE/pjsua"
