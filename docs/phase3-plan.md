# Phase 3 plan — output inspection and the demo agent

- **Status:** Complete (2026-09-15)
- **Date:** 2026-09-15
- **Goal (design §7):** output inspector, demo agent, and synthetic tools, with the
  `injection`, `exfil`, and `deputy` scenarios running end to end.

## Principle

Detection is never the guarantee. The model only proposes; every call is still
authorized on identity, policy, and approval. Inspection adds **labels** that policy
can use (for example, "no external email while untrusted instructions are in the
task") and **flags** recorded in receipts for auditors. A scenario passes because
policy refused the harmful call, not because a heuristic happened to spot the attack.

## Build order

| Step | Component | Package | Threats | Depends on |
|---|---|---|---|---|
| 3.1 ✅ | **Output inspector** — heuristics over tool results: instruction-like text, hidden text (zero-width and bidirectional control characters, HTML comments, invisible styling), directives naming exposed tools, encoded blobs. Produces flag kinds only, never the matched text. Findings become `flag:<kind>` taint labels, which receipts already record, so the receipt format does not change | `internal/inspect`, `internal/gateway` | W1, W13 | Phase 2 |
| 3.2 ✅ | **Provenance and data labels** — trusted tool servers list who wrote returned content under `_meta` key `io.github.fkadusei.agent-warden/authors`; content by a principal other than the task's adds `foreign_principal`, and malformed provenance fails the call. `tool_taint` in `warden.json` labels a tool's output (e.g. `crm/lookup` → `pii`). The example policy holds refunds and email for approval after planted instructions or foreign content, and blocks email outside the tenant once customer data is in the task | `internal/gateway`, `internal/config` | W3, W4 | 3.1 |
| 3.3 | **Folded into 3.1.** Receipts already carry taint labels, so flags need no new field and existing logs verify unchanged | — | — | — |
| 3.4 ✅ | **Scenario corpus and tools** — language-neutral `scenarios/*.json` (task, planted content and who wrote it, the calls a compromised agent makes, the outcome Warden must produce for each), read by `internal/scenario` and embedded by the root package. 13 scenarios: 4 injection, 3 exfil, 3 deputy, 3 benign. Example tools gain `mail.inbox` and `tickets.get`, serve planted content (`example-tools --scenario ID`), and now own the example policy: any untrusted source (web, email, another principal, planted instructions) sends refunds and email to approval even when the inspector finds nothing, and customer data cannot leave by email or web request | `scenarios/`, `internal/exampletools` | W1, W3, W4 | 3.2 |
| 3.5 ✅ | **Scripted compromised agent + gate** — every scenario runs against a fresh copy of the example deployment (`warden init`'s policy, tools, labels, and inspector, over mutual TLS); the scripted agent makes every call, even after refusals. A scenario passes only if each outcome, read from the signed receipts, matches; named rules match; refused calls never reach a tool while allowed ones reach it exactly once; and the log verifies. `warden-gate` runs it after the Phase 2 attacks. A second test runs the corpus with a permit-everything policy and requires every attack scenario to fail, so the gate is shown to catch a weak policy | `internal/gate` | W1, W3, W4 | 3.3, 3.4 |
| 3.6 ✅ | **Demo agent (Python)** — model-agnostic: an Anthropic adapter, an OpenAI-compatible adapter (OpenAI, Ollama, vLLM, LM Studio via `base_url`), and a `script` adapter that replays a scenario's calls without a model; MCP over mutual TLS with the task credential; step limit; JSON Lines transcript that never overwrites; per-scenario report of which attack calls the model attempted and what Warden answered. No security advice in the system prompt. API keys only from environment variables. Tested with fake models and clients (pytest, ruff, mypy strict); run end to end against `warden serve` with the script adapter and with llama3.2:3b on Ollama | `agent/` | — | 3.4 |
| 3.7 ✅ | **Phase gate** — scripted scenarios pass in `go test`; the real agent runs the same scenarios with any configured model (`scripts/agent-corpus.sh`, `warden-agent run --check`) | tests, docs | W1, W3, W4 | 3.5, 3.6 |

## Gate results (2026-09-15)

| Check | Result |
|---|---|
| `go test ./...` corpus gate (scripted compromised agent, fresh example deployment per scenario) | 13/13 scenarios pass: 10/10 attack calls blocked without reaching a tool, 3/3 benign tasks completed, every log verifies |
| Same corpus with a permit-everything policy | all 10 attack scenarios fail, benign still pass: the gate catches a weak policy |
| `scripts/agent-corpus.sh --adapter script` (Python agent, one real `warden serve`, one task credential per scenario) | 13/13 scenarios with every check passing; exported receipt log VERIFIED by `warden-verify` with the anchor |
| Real model (llama3.2:3b on Ollama) | Reported, not gated: model behavior varies by model and run. Small models often fail to call tools at all, which looks like resistance but is not; meaningful attack-success numbers need capable models and come in Phase 4 |

Deferred to Phase 4: attack-success and benign-completion rates per model with and
without Warden, added latency, and receipt bytes per call.

## Decisions (owner, 2026-09-15)

1. **Model-agnostic agent.** No model is built in. Two adapters cover hosted and
   local models; results always name the model and version (design §6).
2. **Scripted + real.** The gate uses a scripted agent that always follows planted
   instructions: deterministic, free, offline, and the worst case. The real agent
   runs the same corpus as a demo; its attack-success numbers come in Phase 4.
3. **Proposed in ADR-0012:** synthetic tools stay in Go (`internal/exampletools`), not
   Python as ADR-0006 planned, so the gate, the demo, and the benchmark share one
   implementation that runs in-process under `go test`. Python is used for the agent
   and, in Phase 4, the benchmark harness.

## Library facts checked (2026-09-15)

- **Python TLS:** Python 3.14.7 (OpenSSL 3.6.4) and uv's Python 3.13 (OpenSSL 3.5.7)
  load ML-DSA-65 certificates and keys. A probe with `mcp` 2.2.0 connected to a real
  `warden serve` over TLS 1.3 mutual auth with a Warden-issued task credential,
  listed tools, and called `crm.lookup`; a client without a certificate was refused.
- **`mcp` 2.2.0 (Python):** `mcp.client.streamable_http.streamable_http_client(url,
  http_client=httpx2.AsyncClient(...))` yields the transport streams for
  `mcp.client.session.ClientSession`; mutual TLS is an `ssl.SSLContext` passed as
  `verify`.
- **Model SDKs:** `anthropic` 1.5.0, `openai` 3.14.0 (both Python ≥ 3.10).
- **MCP Go SDK v1.8.0:** `CallToolResult` carries `_meta`, which is where trusted tool
  servers state provenance in 3.2.
