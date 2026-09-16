#!/usr/bin/env bash
# Drives the three acts of docs/demo.md for a recording.
#
#   scripts/demo-record.sh                      # run the acts in this terminal
#   asciinema rec --cols 110 --rows 34 --overwrite \
#     --command scripts/demo-record.sh docs/demo.cast
#
# Binaries are built first, outside the recording, so the acts are not interrupted by
# compilation. Everything is synthetic: the tools, the payments token, and the timestamp
# authority all run locally for this one run.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$(mktemp -d "${TMPDIR:-/tmp}/warden-demo-bin.XXXXXX")
PAUSE=${PAUSE:-2}
cd "$ROOT"

# demo-output/ is left behind by warden-demo, which refuses to overwrite it, so a second
# recording would fail at act 1 unless it goes with the binaries.
cleanup() { rm -rf "$BIN" "$ROOT/demo-output" "$ROOT/demo.out"; }
trap cleanup EXIT

for cmd in warden-demo warden-gate warden-verify; do
  go build -o "$BIN/$cmd" "./cmd/$cmd"
done
rm -rf demo-output

say() { printf '\n\033[1;36m%s\033[0m\n' "$*"; sleep "$PAUSE"; }

# show is what the viewer reads; the command actually run uses the prebuilt binaries in
# $BIN, whose temporary path would otherwise fill the screen.
run() {
  local show=$1 cmd=$2
  printf '\033[1;32m$\033[0m %s\n' "$show"
  sleep 1
  eval "$cmd"
  sleep "$PAUSE"
}
pretty() {
  local shown=${1//$BIN\//go run ./cmd/} # the path a viewer would type
  printf '%s' "${shown#"${shown%%[![:space:]]*}"}"
}

say "Act 1 — one call, decided"
say "An agent proposes; Warden decides. Thirteen steps through the real pipeline."
run "go run ./cmd/warden-demo" "$BIN/warden-demo | tee demo.out"

say "Act 2 — the gate"
say "An agent that obeys every planted instruction. Tool servers count every execution,"
say "so 'denied' means the tool never ran."
run "go run ./cmd/warden-gate | tail -32" "$BIN/warden-gate | tail -32"

say "Act 3 — the evidence"
say "Verify the log with public keys alone. No Warden running, nothing to trust."
verify=$(grep -m1 -- '--log demo-output/receipts.jsonl' demo.out | sed "s|go run ./cmd/warden-verify|$BIN/warden-verify|")
run "$(pretty "$verify")" "$verify"

say "Now one character changed inside a receipt:"
edited=$(grep -m1 -- '--log demo-output/tampered/edited-receipt.jsonl' demo.out | sed "s|go run ./cmd/warden-verify|$BIN/warden-verify|")
run "$(pretty "$edited")" "$edited || true"

say "And the newest receipts deleted — what the anchored checkpoint is for:"
truncated=$(grep -m1 -- '--log demo-output/tampered/truncated.jsonl' demo.out | sed "s|go run ./cmd/warden-verify|$BIN/warden-verify|")
run "$(pretty "$truncated")" "$truncated || true"

say "Every decision above is in the log, signed with ML-DSA-65 + Ed25519."
rm -f demo.out
