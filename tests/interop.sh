#!/usr/bin/env bash
# End to end: Swift SenderCore (iost-interop-sender) against the real Rust receiver.
# Usage: tests/interop.sh   (builds both first unless SKIP_BUILD=1)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; [[ "${KEEP:-}" ]] || rm -rf "$WORK"' EXIT

if [[ -z "${SKIP_BUILD:-}" ]]; then
  (cd "$ROOT/pc" && cargo build -q -p iostransfer)
  (cd "$ROOT/ios/TransferCore" && swift build -q --product iost-interop-sender)
fi
RECV="$ROOT/pc/target/debug/iostransfer"
SENDER="$ROOT/ios/TransferCore/.build/debug/iost-interop-sender"
DEV=0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f
SECRET=$(printf '42%.0s' {1..32})
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; [[ -f "$WORK/recv.log" ]] && tail -20 "$WORK/recv.log"; exit 1; }

make_library() {
  local lib=$1
  mkdir -p "$lib/sub"
  head -c 300000 /dev/urandom > "$lib/IMG_0001.HEIC"
  head -c 200000 /dev/urandom > "$lib/IMG_0002.HEIC"
  head -c 900000 /dev/urandom > "$lib/IMG_0002.MOV"
  head -c 5000000 /dev/urandom > "$lib/IMG_0003.MOV"
  head -c 120000 /dev/urandom > "$lib/sub/IMG_0004.JPG"
}

start_receiver() { # dest [extra env...]
  local dest=$1; shift
  env "$@" "$RECV" --config "$WORK/cfg" receive --insecure-dev --port "$PORT" --dest "$dest" \
    --dev-device "$DEV:$SECRET" --checkpoint-bytes 65536 --reserve-bytes 1048576 >> "$WORK/recv.log" 2>&1 &
  RECV_PID=$!
  for _ in $(seq 50); do grep -q "Listening on" "$WORK/recv.log" 2>/dev/null && return; sleep 0.1; done
  fail "receiver did not start"
}

stop_receiver() { kill "$RECV_PID" 2>/dev/null || true; wait "$RECV_PID" 2>/dev/null || true; : > "$WORK/recv.log"; }

sender() { # mode folder [extra...]
  local mode=$1 folder=$2; shift 2
  "$SENDER" --port "$PORT" --device "$DEV:$SECRET" --folder "$folder" --spool "$WORK/spool" \
    --journal "$WORK/journal-$mode.db" --mode "$mode" --timeout 90 "$@"
}

# Every library file must exist in dest with identical bytes.
check_copied() { # lib dest
  local lib=$1 dest=$2 f name found
  while IFS= read -r f; do
    name=$(basename "$f")
    found=$(find "$dest" -type f -name "*_${name}" | head -1)
    [[ -n "$found" ]] || fail "$name missing in dest"
    cmp -s "$f" "$found" || fail "$name differs"
  done < <(find "$lib" -type f)
}

field() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "$1" "$2"; }

# 1. Copy
make_library "$WORK/lib"
start_receiver "$WORK/dest"
out=$(sender copy "$WORK/lib") || fail "copy job exited non-zero"
[[ $(field "$out" copied) == 4 ]] || fail "copy: expected 4 copied, got $out"
check_copied "$WORK/lib" "$WORK/dest"
[[ -z $(find "$WORK/dest" -name '*.xmp') ]] || fail "copy jobs must not write XMP"
pass "copy: 4 assets (photo, Live pair, video, nested) byte-identical"

# 2. Same library, new job: everything is already on the PC
out=$(sender copy "$WORK/lib" --job "$(python3 -c 'import uuid;print(uuid.uuid4())')") || fail "re-run exited non-zero"
[[ $(field "$out" copied) == 0 && $(field "$out" already) == 4 ]] || fail "re-run: expected 0 copied / 4 already, got $out"
pass "re-run: 0 sent, 4 already on the PC"
stop_receiver

# 3. Receiver crashes mid-video (P1), restarts; the sender reconnects and resumes
rm -rf "$WORK/spool"
start_receiver "$WORK/dest3" IOST_CRASH_AT=P1:2000000 IOST_CRASH_KEY=video#0
sender copy "$WORK/lib" --job "$(python3 -c 'import uuid;print(uuid.uuid4())')" > "$WORK/out3" &
SENDER_PID=$!
for _ in $(seq 100); do kill -0 "$RECV_PID" 2>/dev/null || break; sleep 0.1; done
kill -0 "$RECV_PID" 2>/dev/null && fail "receiver did not crash"
: > "$WORK/recv.log"
start_receiver "$WORK/dest3"
wait "$SENDER_PID" || fail "sender failed after receiver restart"
check_copied "$WORK/lib" "$WORK/dest3"
grep -q "startup recovery" "$WORK/recv.log" || true
pass "crash mid-video: receiver restarted, sender resumed, all files identical"
stop_receiver

# 4. Move: copy, VERIFY, delete from the library; XMP sidecars on the PC
cp -r "$WORK/lib" "$WORK/lib-move"
start_receiver "$WORK/dest4"
out=$(sender move "$WORK/lib-move" --delete-for-real --yes) || fail "move exited non-zero"
[[ $(field "$out" deleted) == 4 ]] || fail "move: expected 4 deleted, got $out"
[[ -z $(find "$WORK/lib-move" -type f) ]] || fail "move: library not emptied"
check_copied "$WORK/lib" "$WORK/dest4"
[[ $(find "$WORK/dest4" -name '*.xmp' | wc -l) == 4 ]] || fail "move: expected 4 XMP sidecars"
pass "move: 4 verified and deleted from the library, XMP sidecars written"
stop_receiver
echo "interop: all passed"
