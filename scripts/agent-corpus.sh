#!/usr/bin/env bash
# Runs every scenario in scenarios/ with the Python agent, through Warden and/or
# directly, and reports the benchmark numbers. A thin wrapper around `warden-bench`.
#
#   scripts/agent-corpus.sh --adapter script
#   scripts/agent-corpus.sh --direct --adapter script
#   scripts/agent-corpus.sh --adapter openai-compatible --base-url http://127.0.0.1:11434/v1 --model llama3.2:3b
#   scripts/agent-corpus.sh --adapter anthropic --model MODEL_ID --repeat 3   # key from ANTHROPIC_API_KEY
#
# --direct (first) runs only the baseline: the agent calls the tool servers directly
# and holds the payments token itself, with no Warden. Otherwise both modes run.
# Every other argument is passed to warden-bench (--repeat, --only, --max-steps, ...).
#
# Each run builds the Go binaries, starts the tool servers with each scenario's planted
# content, and (through Warden) a real `warden serve` whose exported log is verified.
# Keys and data are synthetic and removed afterwards; results go to agent-runs/.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MODES="warden,direct"
if [ "${1:-}" = "--direct" ]; then
  MODES="direct"
  shift
fi

uv --directory "$ROOT/agent" sync -q
exec uv run --project "$ROOT/agent" -q warden-bench --modes "$MODES" \
  --scenarios-dir "$ROOT/scenarios" --repo "$ROOT" "$@"
