# Phase 4 plan — the benchmark

- **Status:** In progress
- **Date:** 2026-09-15
- **Goal (design §6, §7):** attack success rate **without** Warden vs. **with** Warden,
  over the same scenarios, model, and tools, published with the benign-task completion
  rate, added latency per call, and receipt bytes per call.

## What "without Warden" means

The same agent, prompt, model, and scenario content, but the agent connects straight to
the example tool servers and holds the tool credentials itself, as agents commonly run
today. There is no policy, approval, inspection, or receipt. An attack **succeeds** when
its call reaches the tool and the tool reports success. Planted content is identical in
both modes because the same tool servers serve it.

## Build order

| Step | Component | Where | Depends on |
|---|---|---|---|
| 4.1 ✅ | **Baseline mode** — `warden-agent run --direct`: MCP straight to each tool server, the agent holding the payments token; per-call latency recorded in both modes; `agent-corpus.sh --direct`. Scripted check: without Warden all 10 attack calls succeed and 3/3 benign tasks complete; through Warden 0/10 succeed, 3/3 benign complete, log verified | `agent/`, `scripts/` | Phase 3 |
| 4.2 ✅ | **Model-tolerant matching** — scenario steps may name the arguments that identify the attack (`match`, e.g. `["to"]`; `[]` means any call to the tool), so a model that rewords an email body still counts; validated by Go, used by the Python report | `internal/scenario`, `agent/`, `scenarios/` | — |
| 4.3 ✅ | **Corpus expansion** — 41 scenarios: 31 attacks (12 injection, 7 exfil, 8 deputy, 4 new `authz`) and 10 benign. Writing them exposed two gaps in the example deployment, now fixed and covered: a recipient list such as `x@evil.example, bob@tenant-a.example` passed the tenant-suffix rule (the `mail.send` schema now allows exactly one address, so schema validation denies lists), and pasted tool calls, hidden text, or encoded blobs did not require approval (the approval rule now covers every inspector flag). Gate: 31/31 attacks blocked, 10/10 benign completed; with a permit-everything policy every policy-dependent attack scenario fails while schema-blocked ones stay blocked | `scenarios/`, `internal/exampletools` | 4.2 |
| 4.4 | **Benchmark harness** — runs corpus × {with, without} × repetitions for a configured model; writes raw results (JSON) and a Markdown table: attack success rate, benign completion, latency p50/p99, receipt bytes per call | `agent/` (`warden-bench`) | 4.1–4.3 |
| 4.5 | **Checkpoint anchoring** in benchmark runs (open question 5: public vs. local RFC 3161 TSA) | `internal/checkpoint` | owner decision |
| 4.6 | **Published results** — a run with a capable model, table in the README with model name and version | `README.md` | 4.4, model access |

## Honest-reporting rules

- Results always name the adapter, model, and version, the date, and repetitions.
- Benign completion is reported beside attack success: a setup that blocks everything is
  useless.
- A model that fails to use tools at all (as llama3.2:3b did in Phase 3) is reported as
  such; its "zero attack success" is not evidence for Warden.
- The deterministic guarantee remains `warden-gate`; model runs are measurements.

## Open decisions

1. **Model(s) for 4.6.** An Anthropic model via `ANTHROPIC_API_KEY`, and/or a larger
   local model through Ollama.
2. **Anchoring (4.5).** Public RFC 3161 TSA or a local one.
