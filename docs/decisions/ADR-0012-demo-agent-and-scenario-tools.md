# ADR-0012: Demo agent, scenario tools, and the scripted gate

- **Status:** Accepted (owner, 2026-09-16)
- **Date:** 2026-09-15
- **Related:** threats W1, W3, W4; ADR-0006 (tech stack); design §6, §7, §9;
  Phase 3 plan

## Context

Phase 3 needs an agent that reads attacker-controlled content and proposes tool calls,
tools that serve that content, and a gate proving Warden stops the harmful calls.
ADR-0006 planned a Python demo agent, Python synthetic tools, and a Python benchmark.
Phase 2 has since built the synthetic tools in Go (`internal/exampletools`), and the
Phase 2 gate runs real MCP tool servers in-process under `go test`.

Two facts shape the choice:

- **Models vary.** Attack success depends on the model, and the owner wants results for
  more than one (hosted and local). A weak model can also "resist" an injection simply
  by failing to use tools, which says nothing about Warden.
- **Python can reach Warden.** Checked 2026-09-15: Python 3.14 (OpenSSL 3.6.4) with
  `mcp` 2.2.0 connects to `warden serve` over TLS 1.3 mutual authentication with an
  ML-DSA-65 task credential, lists tools, and calls them.

## Decision

1. **The demo agent is Python and model-agnostic.** It talks to models through an
   adapter interface with two implementations: the Anthropic Messages API, and any
   OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, LM Studio) selected by
   `base_url`. Every transcript and result names the adapter, model, and version.
2. **The gate does not depend on a model.** A scripted agent in Go obeys every
   instruction it finds in tool output: the worst case, deterministic, free, and
   runnable offline in `go test`. The real agent runs the same scenarios as a demo;
   attack-success rates per model are Phase 4.
3. **Scenario tools stay in Go** (`internal/exampletools`), changing ADR-0006 for this
   component. One implementation serves the gate, the demo, and the benchmark, and
   it runs in-process under `go test`.
4. **Scenarios are data.** `scenarios/*.json` describes each scenario (task, planted
   content and where it appears, harmful call, expected outcome, category, threat) in a
   language-neutral form that the Go gate and the Python agent both read.

## Consequences

- Warden's guarantee is tested against an agent that is fully compromised, so passing
  does not depend on any model's judgment.
- Adding a model needs no Warden change: point the OpenAI-compatible adapter at it, or
  add an adapter.
- The Python side stays small (agent now, benchmark harness in Phase 4); the trust path
  and everything the gate needs remain Go.
- Model results remain non-deterministic; they are reported per model and version and
  never used as a pass/fail gate.
