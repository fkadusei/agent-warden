#!/usr/bin/env bash
# Runs every scenario in scenarios/ with the Python agent.
#
# Through Warden (default): a temporary `warden serve`, one task credential per scenario,
# every call checked against the scenario (--check), and the exported receipt log
# verified with warden-verify.
#
#   scripts/agent-corpus.sh --adapter script
#   scripts/agent-corpus.sh --adapter openai-compatible --base-url http://127.0.0.1:11434/v1 --model llama3.2:3b
#   scripts/agent-corpus.sh --adapter anthropic --model MODEL_ID      # key from ANTHROPIC_API_KEY
#
# Benchmark baseline (--direct first): the same agent calls the tool servers directly
# and holds the payments token itself; no Warden, no checks, no receipts.
#
#   scripts/agent-corpus.sh --direct --adapter script
#
# Remaining arguments are passed to `warden-agent run`. The tool servers restart with
# each scenario's planted content. Keys and data are synthetic and live in a temporary
# directory removed on exit. Transcripts (and, through Warden, the receipt log, anchor,
# and public keys) are copied to agent-runs/ (ignored by git).
#
# Exit status: 0 when every scenario run succeeds (through Warden: every check passes and
# the log verifies), 1 otherwise. With a real model, --check failures describe the
# model's run, not a Warden failure.
set -euo pipefail

DIRECT=0
if [ "${1:-}" = "--direct" ]; then
  DIRECT=1
  shift
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TOOLS_ADDR=${TOOLS_ADDR:-127.0.0.1:19300}
AGENT_ADDR=${AGENT_ADDR:-127.0.0.1:18643}
APPROVER_ADDR=${APPROVER_ADDR:-127.0.0.1:18644}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/warden-corpus.XXXXXX")
MODE=$([ "$DIRECT" -eq 1 ] && echo direct || echo warden)
RUN_DIR="$ROOT/agent-runs/$(date -u +%Y%m%dT%H%M%SZ)-$MODE"
TOKEN="corpus-$RANDOM$RANDOM$RANDOM"
W="$WORK/warden"
tools_pid=""
serve_pid=""

cleanup() {
  [ -n "$tools_pid" ] && kill "$tools_pid" 2>/dev/null || true
  [ -n "$serve_pid" ] && kill "$serve_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_port() {
  local host=${1%:*} port=${1##*:}
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  echo "nothing listening on $1" >&2
  return 1
}

start_tools() {
  if [ -n "$tools_pid" ]; then
    kill "$tools_pid" 2>/dev/null || true
    wait "$tools_pid" 2>/dev/null || true
  fi
  EXAMPLE_PAYMENTS_TOKEN="$TOKEN" "$WORK/bin/example-tools" --listen "$TOOLS_ADDR" --scenario "$1" >>"$WORK/tools.log" 2>&1 &
  tools_pid=$!
  wait_port "$TOOLS_ADDR"
}

cd "$ROOT"
echo "building ($MODE mode)..."
for cmd in warden example-tools warden-verify; do
  go build -o "$WORK/bin/$cmd" "./cmd/$cmd"
done
uv --directory "$ROOT/agent" sync -q

scenarios=()
for f in "$ROOT"/scenarios/*.json; do
  scenarios+=("$(basename "$f" .json)")
done

if [ "$DIRECT" -eq 0 ]; then
  "$WORK/bin/warden" init --dir "$W" --tools-url "http://$TOOLS_ADDR" --listen "$AGENT_ADDR" \
    --approver-listen "$APPROVER_ADDR" --chain agent-corpus >/dev/null
  start_tools "${scenarios[0]}"
  "$WORK/bin/warden" pin --config "$W/warden.json" --write >/dev/null
  WARDEN_SECRET_PAYMENTS="$TOKEN" "$WORK/bin/warden" serve --config "$W/warden.json" >"$WORK/serve.log" 2>&1 &
  serve_pid=$!
  wait_port "$AGENT_ADDR"
fi

mkdir -p "$RUN_DIR/transcripts"
failed=()
for s in "${scenarios[@]}"; do
  echo
  echo "=== $s"
  start_tools "$s"
  transcript="$RUN_DIR/transcripts/$s.jsonl"
  if [ "$DIRECT" -eq 1 ]; then
    # The agent itself holds the tool credential in the baseline.
    if ! EXAMPLE_PAYMENTS_TOKEN="$TOKEN" uv run --project "$ROOT/agent" -q warden-agent run --scenario "$s" \
        --scenarios-dir "$ROOT/scenarios" --direct --tools-url "http://$TOOLS_ADDR" --transcript "$transcript" "$@"; then
      failed+=("$s")
    fi
    continue
  fi
  principal=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["principal"])' "$ROOT/scenarios/$s.json")
  "$WORK/bin/warden" issue-task --config "$W/warden.json" --agent warden-agent --principal "$principal" \
    --task "corpus-$s" --out "$W/agent-$s" >/dev/null
  if ! uv run --project "$ROOT/agent" -q warden-agent run --scenario "$s" --scenarios-dir "$ROOT/scenarios" \
      --url "https://$AGENT_ADDR" --ca "$W/pki/ca.pem" --cert "$W/agent-$s.pem" --key "$W/agent-$s.key" \
      --transcript "$transcript" --check "$@"; then
    failed+=("$s")
  fi
done

verified=1
if [ "$DIRECT" -eq 0 ]; then
  # Stop Warden cleanly so it writes a final checkpoint, then export and verify the log.
  kill -INT "$serve_pid"
  wait "$serve_pid" || true
  serve_pid=""
  "$WORK/bin/warden" export --config "$W/warden.json" --out "$RUN_DIR/receipts.jsonl" >/dev/null
  cp "$W/keys.json" "$RUN_DIR/keys.json"
  cp "$W/data/anchor.jsonl" "$RUN_DIR/anchor.jsonl"
  echo
  verified=0
  if "$WORK/bin/warden-verify" --log "$RUN_DIR/receipts.jsonl" --chain agent-corpus \
      --keys "$RUN_DIR/keys.json" --anchor "$RUN_DIR/anchor.jsonl"; then
    verified=1
  fi
fi

echo
echo "$MODE mode: ${#scenarios[@]} scenarios, ${#failed[@]} failed${failed:+: ${failed[*]}}"
echo "transcripts: $RUN_DIR"
[ "${#failed[@]}" -eq 0 ] && [ "$verified" -eq 1 ]
