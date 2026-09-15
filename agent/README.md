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
