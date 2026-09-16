# warden-agent

A small, model-agnostic agent that reaches its tools **only through Agent Warden**. It
is untrusted by design: it proposes tool calls and Warden decides them. Its system
prompt contains no security advice, so a run shows what the model does when Warden is
the only thing between it and the tools.

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```sh
cd agent
uv sync
uv run pytest
```

## Run it

Start Warden as in the main README ("Run Warden locally"), serving a scenario's
planted content with `go run ./cmd/example-tools --scenario deputy-ticket-refund`, and
issue a task credential. Then, from the repository root:

```sh
# No model: replay the scenario's calls, exactly like the Go gate's scripted agent
uv run --project agent warden-agent run --scenario deputy-ticket-refund --adapter script

# A local model through Ollama's OpenAI-compatible endpoint
uv run --project agent warden-agent run --scenario deputy-ticket-refund \
  --adapter openai-compatible --base-url http://127.0.0.1:11434/v1 --model llama3.2:3b

# Claude (key read from ANTHROPIC_API_KEY)
uv run --project agent warden-agent run --scenario deputy-ticket-refund \
  --adapter anthropic --model MODEL_ID --transcript run.jsonl
```

Each run prints every call and Warden's answer (`ok`, `denied`, `pending_approval`,
...) and, for a scenario, whether the model attempted each attack call and whether
Warden let any through. `--transcript` writes a JSON Lines record and never overwrites
a file. API keys are read only from environment variables, never from flags.

Model results vary by model and run; they are reported per model and version and are
never a pass/fail gate. The deterministic gate is `go run ./cmd/warden-gate`.

## Benchmark: with and without Warden

`warden-bench` runs the whole corpus in both modes and reports the numbers:

```sh
uv run --project agent warden-bench --adapter script                       # both modes, one pass
uv run --project agent warden-bench --adapter anthropic --model MODEL_ID --repeat 3
uv run --project agent warden-bench --adapter openai-compatible \
  --base-url http://127.0.0.1:11434/v1 --model llama3.2:3b --modes warden
```

It builds the Go binaries, starts the tool servers with each scenario's planted content,
runs a real `warden serve` for the Warden mode (a fresh task credential per scenario),
then stops it, exports the receipt log, and verifies it. Each run writes `results.json`,
`summary.md`, and a transcript per scenario to `agent-runs/bench-<timestamp>/`.

Reported per mode: attack success rate, benign completion rate, how many attack calls
the model attempted at all, call latency (p50/p99), and receipt bytes per call. Model
numbers are measurements, not a gate: a model that rarely calls tools scores a low
attack success rate without Warden doing anything, so the attempted count is printed
beside it. `--repeat` runs each scenario several times, since model runs vary.

## Run the whole corpus

`scripts/agent-corpus.sh` starts a temporary Warden (synthetic keys, removed on exit),
runs every scenario with its own task credential and planted content, stops Warden,
and verifies the exported receipt log with `warden-verify`. Arguments go to
`warden-agent run`:

```sh
scripts/agent-corpus.sh --adapter script
scripts/agent-corpus.sh --adapter openai-compatible --base-url http://127.0.0.1:11434/v1 --model llama3.2:3b
```

For the benchmark baseline, put `--direct` first: the same agent calls the tool servers
directly and holds the payments token itself, with no Warden, checks, or receipts, and
each scenario reports how many attack calls succeeded. This is how agents commonly run
today; it exists only for comparison.

```sh
scripts/agent-corpus.sh --direct --adapter script
```

Every Warden run passes `--check`: the run fails if Warden answered any scenario call the agent
made differently from the scenario's expectation (and, for `script`, if any step was
skipped). Transcripts, the receipt log, the anchor, and the public keys are kept in
`agent-runs/`, which git ignores.
