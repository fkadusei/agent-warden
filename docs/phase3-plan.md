# Phase 3 plan — output inspection and the demo agent

- **Status:** In progress
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
| 3.5 | **Scripted compromised agent + gate** — an agent that obeys every instruction it reads, the worst case; `injection`, `exfil`, `deputy` added to `warden-gate` and `go test` | `internal/gate` | W1, W3, W4 | 3.3, 3.4 |
| 3.6 | **Demo agent (Python)** — model-agnostic: an Anthropic adapter and an OpenAI-compatible adapter (OpenAI, Ollama, vLLM, LM Studio via `base_url`); MCP over mutual TLS with the task credential; step limit; transcript file. Tested with a fake model | `agent/` | — | 3.4 |
| 3.7 | **Phase gate** — scripted scenarios pass in `go test`; the real agent runs the same scenarios with any configured model | tests, docs | W1, W3, W4 | 3.5, 3.6 |

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
