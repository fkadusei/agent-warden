# Phase 5 plan — making it legible

- **Status:** In progress
- **Date:** 2026-09-16
- **Goal (design §7):** README, demo, write-up. Everything works; this phase makes it
  understandable to someone who lands on the repo cold and has five minutes.

## What a first-time reader needs

1. **What is this and what does it stop?** In the first screen, without jargon.
2. **Proof it works.** The benchmark result and the attack gate, with their limits stated.
3. **A way to try it** in one command.
4. **A way to judge the engineering:** the design, the threat model, the decisions.

The repo currently answers 3 well, 2 in scattered places, and 1 last.

## Build order

| Step | Component | Where | Depends on |
|---|---|---|---|
| 5.1 ✅ | **README as the front door** — the benchmark table now sits near the top, a "How a call is decided" section explains the pipeline in one screen, and the walkthroughs moved below. Three stale claims fixed while restructuring: the status said Phase 3, the "not yet" list still named RFC 3161 anchoring and the benchmark (both done), and the gate was described as 25 attacks when it runs 26. Every count and link re-checked against the code | `README.md` | — |
| 5.2 ✅ | **CI and supply chain** (design §9) — `.github/workflows/go.yml`: gofmt, `go vet`, `go test ./...`, `warden-gate`, the race detector on the enforcement path, a demo-and-verify round trip, and `govulncheck`; `agent.yml`: `uv sync --locked`, ruff format and lint, mypy, pytest. Actions pinned by commit SHA | `.github/workflows/` | — |
| 5.3 ✅ | **The write-up** — the argument in one sitting: policy rather than detection (with the paraphrased-refund scenario as the reason), the two ordering rules that carry the weight, what the evidence is built to survive, what the gate guarantees and how it can fail, what the benchmark shows with its caveats beside it, the 1050-refund model error, and what is deliberately not solved. Every scenario, ADR, and count cited was checked against the code | `docs/writeup.md`, `docs/writeup.html` | 5.1 |
| 5.4 ✅ | **Demo recording** — `docs/demo.md` is the storyboard in three acts (a call being decided, the gate, the evidence), quoting real output. `scripts/demo-record.sh` drives it; asciinema 3.2.1 and agg 1.9.0 were installed (owner approved) and the run is committed as `docs/demo.cast` (11 KB, replayable text) and `docs/demo.gif` (1.1 MB, embedded at the top of the README). The cast was re-recorded twice to fix what a viewer sees: the first leaked the temporary build path into the prompts, the second showed a bare `warden-verify` instead of `go run ./cmd/warden-verify` | `docs/demo.md`, `docs/demo.cast`, `docs/demo.gif` | 5.1 |
| 5.5 ✅ | **Local console** — `warden console` (ADR-0015): what Warden decided, what waits for a person, and whether the log verifies, with approve/reject buttons. Loopback only, a one-off startup token on every API call, read-only unless `--key` and `--id` are given, and approvals reuse `approverapi.Sign`/`Submit`, so there is no second signing path. Checked end to end against a live `serve`: it listed a held refund with its arguments verified against the decision receipt, approved it, and the agent then ran the call; an untokened request got 403. The scenario runner was left out of this version | `cmd/warden/console.go`, `console.html` | — |
| 5.6 | **Close-out** — ADR-0012 accepted or rejected; deferred items written down honestly (key rotation and revocation, fuller output inspection, RFC 3161 against a public authority); the agent's `Event loop is closed` teardown noise cleaned up | docs, `agent/` | owner decision |

## Rules for this phase

- **No new claims.** Everything in the README and write-up must point at something that
  runs: a command, a test, a generated page, or a committed result.
- **Limits stay next to the claims,** not in a footnote: what the benchmark measures, what
  the gate guarantees, what the example policy does and does not cover.
- **The reader is not assumed to know MCP, Cedar, or ML-DSA.**

## Open decisions

1. **Web console (5.5)** — build it, or leave it out?
2. **ADR-0012** — accept (scenario tools stay in Go, the agent is model-agnostic) or revisit?
3. **Demo (5.4)** — a terminal recording (asciinema, committable) or a screen video?
